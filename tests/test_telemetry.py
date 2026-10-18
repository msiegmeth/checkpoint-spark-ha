"""Prometheus remote write decoding (snappy block + protobuf), built from scratch."""

import struct

import pytest

from custom_components.checkpoint_spark.telemetry import (
    TelemetryError,
    TelemetryStore,
    parse_write_request,
    series_key,
    snappy_decompress,
)


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _ld(field: int, payload: bytes) -> bytes:
    return _varint(field << 3 | 2) + _varint(len(payload)) + payload


def _label(name: str, value: str) -> bytes:
    return _ld(1, _ld(1, name.encode()) + _ld(2, value.encode()))


def _sample(value: float, ts: int) -> bytes:
    return _ld(2, _varint(1 << 3 | 1) + struct.pack("<d", value) + _varint(2 << 3 | 0) + _varint(ts))


def _series(labels: dict, samples: list) -> bytes:
    body = b"".join(_label(k, v) for k, v in labels.items()) + b"".join(_sample(v, t) for t, v in samples)
    return _ld(1, body)


def _snappy_literal(data: bytes) -> bytes:
    """Valid snappy block using only literals (max 60 bytes each)."""
    out = bytearray(_varint(len(data)))
    for i in range(0, len(data), 60):
        chunk = data[i:i + 60]
        out.append((len(chunk) - 1) << 2)
        out += chunk
    return bytes(out)


def test_roundtrip() -> None:
    req = _series({"__name__": "cpu_usage", "core": "0"}, [(1000, 12.5), (2000, 17.0)]) + \
        _series({"__name__": "mem_used"}, [(2000, 1464.0)])
    series = parse_write_request(snappy_decompress(_snappy_literal(req)))
    assert series[0]["labels"] == {"__name__": "cpu_usage", "core": "0"}
    assert series[0]["samples"] == [(1000, 12.5), (2000, 17.0)]
    store = TelemetryStore()
    store.add(series, None)
    assert store.series['cpu_usage{core="0"}']["value"] == 17.0
    assert store.metric_names() == {"cpu_usage": 1, "mem_used": 1}
    assert series_key({"__name__": "x"}) == "x"


def test_snappy_copy() -> None:
    # "abcd" literal + copy (offset 4, length 4) -> "abcdabcd"
    block = _varint(8) + bytes([3 << 2]) + b"abcd" + bytes([(0 << 2) | 1, 4])
    assert snappy_decompress(block) == b"abcdabcd"


@pytest.mark.parametrize("bad", [b"", _varint(10) + b"\x00a", _varint(4) + bytes([1, 9])])
def test_snappy_rejects_garbage(bad: bytes) -> None:
    with pytest.raises(TelemetryError):
        snappy_decompress(bad)


def test_size_limit() -> None:
    with pytest.raises(TelemetryError):
        snappy_decompress(_varint(10**9))


def test_snappy_stream_and_gzip() -> None:
    import gzip

    from custom_components.checkpoint_spark.telemetry import SNAPPY_STREAM_MAGIC, decompress

    req = _series({"__name__": "up"}, [(1, 1.0)])
    block = _snappy_literal(req)
    framed = SNAPPY_STREAM_MAGIC + bytes([0x00]) + (len(block) + 4).to_bytes(3, "little") + b"\0\0\0\0" + block
    assert parse_write_request(decompress(framed, "snappy"))[0]["labels"] == {"__name__": "up"}
    assert parse_write_request(decompress(gzip.compress(req), "gzip"))[0]["samples"] == [(1, 1.0)]
    assert decompress(block, "snappy") == req
