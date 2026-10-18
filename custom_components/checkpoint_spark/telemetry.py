"""Receiver for the gateway's OpenTelemetry/Skyline export (Prometheus remote write v1).

The gateway's OpenTelemetry collector POSTs snappy-compressed protobuf
``prometheus.WriteRequest`` messages. Both formats are decoded here in pure
Python (no extra requirements). Only the newest value per time series is kept,
in memory, with hard limits on request size and number of series.
"""

from __future__ import annotations

from datetime import datetime
import struct
from typing import Any

MAX_BODY = 4 * 1024 * 1024        # compressed request
MAX_UNCOMPRESSED = 32 * 1024 * 1024
MAX_SERIES = 5000
MAX_LABEL_LEN = 256


class TelemetryError(ValueError):
    """Malformed payload."""


# ------------------------------------------------------------------ snappy --
def _varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        if pos >= len(buf):
            raise TelemetryError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise TelemetryError("varint too long")


def snappy_decompress(buf: bytes) -> bytes:
    """Decode the snappy *block* format (as used by Prometheus remote write)."""
    length, pos = _varint(buf, 0)
    if length > MAX_UNCOMPRESSED:
        raise TelemetryError("uncompressed payload too large")
    out = bytearray()
    n = len(buf)
    while pos < n:
        tag = buf[pos]
        pos += 1
        kind = tag & 3
        if kind == 0:  # literal
            ln = tag >> 2
            if ln >= 60:
                extra = ln - 59
                if pos + extra > n:
                    raise TelemetryError("truncated literal length")
                ln = int.from_bytes(buf[pos:pos + extra], "little")
                pos += extra
            ln += 1
            if pos + ln > n:
                raise TelemetryError("truncated literal")
            out += buf[pos:pos + ln]
            pos += ln
        else:
            if kind == 1:
                ln = ((tag >> 2) & 7) + 4
                if pos >= n:
                    raise TelemetryError("truncated copy")
                off = ((tag >> 5) << 8) | buf[pos]
                pos += 1
            elif kind == 2:
                ln = (tag >> 2) + 1
                if pos + 2 > n:
                    raise TelemetryError("truncated copy")
                off = int.from_bytes(buf[pos:pos + 2], "little")
                pos += 2
            else:
                ln = (tag >> 2) + 1
                if pos + 4 > n:
                    raise TelemetryError("truncated copy")
                off = int.from_bytes(buf[pos:pos + 4], "little")
                pos += 4
            if off == 0 or off > len(out):
                raise TelemetryError("invalid copy offset")
            start = len(out) - off
            for i in range(ln):  # may overlap
                out.append(out[start + i])
        if len(out) > length:
            raise TelemetryError("output exceeds declared length")
    if len(out) != length:
        raise TelemetryError("length mismatch")
    return bytes(out)


SNAPPY_STREAM_MAGIC = b"\xff\x06\x00\x00sNaPpY"


def snappy_stream_decompress(buf: bytes) -> bytes:
    """Snappy *framing* format (stream identifier + compressed/uncompressed chunks)."""
    out = bytearray()
    pos, n = 0, len(buf)
    while pos < n:
        if pos + 4 > n:
            raise TelemetryError("truncated chunk header")
        ctype = buf[pos]
        ln = int.from_bytes(buf[pos + 1:pos + 4], "little")
        pos += 4
        if pos + ln > n:
            raise TelemetryError("truncated chunk")
        chunk = buf[pos:pos + ln]
        pos += ln
        if ctype == 0x00:  # compressed: 4-byte CRC + snappy block
            out += snappy_decompress(chunk[4:])
        elif ctype == 0x01:  # uncompressed: 4-byte CRC + data
            out += chunk[4:]
        elif ctype == 0xFF:
            if chunk != b"sNaPpY":
                raise TelemetryError("bad stream identifier")
        elif 0x02 <= ctype <= 0x7F:
            raise TelemetryError(f"reserved unskippable chunk {ctype:#x}")
        # 0x80-0xfe: skippable / padding
        if len(out) > MAX_UNCOMPRESSED:
            raise TelemetryError("uncompressed payload too large")
    return bytes(out)


def decompress(body: bytes, encoding: str = "") -> bytes:
    """Detect the compression by magic bytes (more reliable than the header)."""
    if body.startswith(SNAPPY_STREAM_MAGIC):
        return snappy_stream_decompress(body)
    if body[:2] == b"\x1f\x8b":
        import gzip  # noqa: PLC0415
        import zlib  # noqa: PLC0415

        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(body, MAX_UNCOMPRESSED + 1)
        if len(out) > MAX_UNCOMPRESSED:
            raise TelemetryError("uncompressed payload too large")
        return out
    if "snappy" in encoding.lower() or not encoding:
        return snappy_decompress(body)
    return body


# ---------------------------------------------------------------- protobuf --
def _fields(buf: bytes):
    """Iterate (field_number, wire_type, value) of a protobuf message."""
    pos, n = 0, len(buf)
    while pos < n:
        key, pos = _varint(buf, pos)
        field, wire = key >> 3, key & 7
        if wire == 0:
            val, pos = _varint(buf, pos)
        elif wire == 1:
            if pos + 8 > n:
                raise TelemetryError("truncated fixed64")
            val = buf[pos:pos + 8]
            pos += 8
        elif wire == 2:
            ln, pos = _varint(buf, pos)
            if pos + ln > n:
                raise TelemetryError("truncated bytes")
            val = buf[pos:pos + ln]
            pos += ln
        elif wire == 5:
            if pos + 4 > n:
                raise TelemetryError("truncated fixed32")
            val = buf[pos:pos + 4]
            pos += 4
        else:
            raise TelemetryError(f"unsupported wire type {wire}")
        yield field, wire, val


def parse_write_request(buf: bytes) -> list[dict[str, Any]]:
    """prometheus.WriteRequest -> [{"labels": {...}, "samples": [(ts_ms, value)]}]."""
    series = []
    for field, wire, val in _fields(buf):
        if field != 1 or wire != 2:  # 1 = timeseries; 3 = metadata (ignored)
            continue
        labels: dict[str, str] = {}
        samples: list[tuple[int, float]] = []
        for f2, w2, v2 in _fields(val):
            if f2 == 1 and w2 == 2:  # Label
                name = value = ""
                for f3, w3, v3 in _fields(v2):
                    if w3 == 2 and f3 in (1, 2):
                        text = v3.decode("utf-8", "replace")[:MAX_LABEL_LEN]
                        if f3 == 1:
                            name = text
                        else:
                            value = text
                if name:
                    labels[name] = value
            elif f2 == 2 and w2 == 2:  # Sample
                value, ts = float("nan"), 0
                for f3, w3, v3 in _fields(v2):
                    if f3 == 1 and w3 == 1:
                        value = struct.unpack("<d", v3)[0]
                    elif f3 == 2 and w3 == 0:
                        ts = v3 - (1 << 64) if v3 >= 1 << 63 else v3
                samples.append((ts, value))
        series.append({"labels": labels, "samples": samples})
    return series


# ------------------------------------------------------------------- store --
def series_key(labels: dict[str, str]) -> str:
    name = labels.get("__name__", "")
    rest = ",".join(f'{k}="{v}"' for k, v in sorted(labels.items()) if k != "__name__")
    return f"{name}{{{rest}}}" if rest else name


class TelemetryStore:
    """Newest sample per series (bounded)."""

    def __init__(self) -> None:
        self.series: dict[str, dict[str, Any]] = {}
        self.requests = 0
        self.rejected = 0
        self.dropped_series = 0
        self.last_received: datetime | None = None
        self.listeners: list[Any] = []
        self.last_error: str | None = None

    def add(self, series: list[dict[str, Any]], now: datetime) -> int:
        stored = 0
        for s in series:
            if not s["samples"]:
                continue
            key = series_key(s["labels"])
            if key not in self.series and len(self.series) >= MAX_SERIES:
                self.dropped_series += 1
                continue
            ts, value = max(s["samples"], key=lambda x: x[0])
            self.series[key] = {"labels": s["labels"], "value": value, "ts": ts}
            stored += 1
        self.requests += 1
        self.last_received = now
        return stored

    def metric_names(self) -> dict[str, int]:
        """Metric name -> number of series."""
        out: dict[str, int] = {}
        for item in self.series.values():
            name = item["labels"].get("__name__", "")
            out[name] = out.get(name, 0) + 1
        return dict(sorted(out.items()))

    def query(self, prefix: str = "", limit: int = 200) -> list[dict[str, Any]]:
        rows = [
            {"metric": k, "value": v["value"], "ts": v["ts"]}
            for k, v in sorted(self.series.items())
            if k.startswith(prefix)
        ]
        return rows[:limit]
