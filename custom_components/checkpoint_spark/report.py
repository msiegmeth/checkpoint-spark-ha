"""Parsing helpers for decoded Spark reports (shared by coordinator and platforms)."""

from __future__ import annotations

from typing import Any

from homeassistant.util import dt as dt_util

_PREFIXES = ("MALWARE_SEVERITY.", "APPI_RANK_LEVEL.")
_INT_FIELDS = {
    "sessions": "sessions",
    "bytes": "bytes",
    "downBytes": "down_bytes",
    "upBytes": "up_bytes",
    "incidents": "incidents",
    "blocked": "blocked",
}
_TEXT_FIELDS = {"severity": "severity", "risk": "risk", "category": "category", "cve": "cve"}


def _int(value: Any) -> int | None:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _summary(report: dict[str, Any], header: str) -> int | None:
    for item in report.get("summary") or []:
        if isinstance(item, dict) and str(item.get("header", "")).endswith(f".{header}"):
            return _int(item.get("value"))
    return None


def _has_summary(report: dict[str, Any], header: str) -> bool:
    return any(
        isinstance(i, dict) and str(i.get("header", "")).endswith(f".{header}")
        for i in report.get("summary") or []
    )


def _compact(item: dict[str, Any]) -> dict[str, Any]:
    """Reduce a chart entry to readable, typed fields."""
    out: dict[str, Any] = {"name": item.get("name") or item.get("label")}
    for src, dst in _INT_FIELDS.items():
        if (val := _int(item.get(src))) is not None:
            out[dst] = val
    for src, dst in _TEXT_FIELDS.items():
        val = item.get(src)
        if val not in (None, ""):
            val = str(val)
            for prefix in _PREFIXES:
                val = val.removeprefix(prefix)
            if dst == "risk":
                val = val.lower().removesuffix("risk") or None
            elif dst == "severity":
                val = val.lower()
            out[dst] = val
    if len(out) == 1 and (val := _int(item.get("value"))) is not None:
        out["count"] = val
    return out


def _chart(report: dict[str, Any], key: str) -> list[dict[str, Any]]:
    chart = report.get(key)
    data = chart.get("chartData") if isinstance(chart, dict) else None
    if not isinstance(data, list):
        return []
    return [_compact(i) for i in data if isinstance(i, dict)]


def _history(report: dict[str, Any]) -> list[dict[str, Any]]:
    chart = report.get("bandwidthUsageChart")
    data = chart.get("chartData") if isinstance(chart, dict) else None
    out = []
    for item in data if isinstance(data, list) else []:
        if not isinstance(item, dict) or (ts := _int(item.get("label"))) is None:
            continue
        out.append(
            {
                "time": dt_util.utc_from_timestamp(ts).isoformat(),
                "down_bytes": _int(item.get("downBytes")),
                "up_bytes": _int(item.get("upBytes")),
            }
        )
    return out


def blades_of(report: dict[str, Any]) -> dict[str, bool]:
    """Software blade name -> enabled, e.g. {"ips": True, "threat_emulation": False}."""
    blades = report.get("bladesStatus")
    out: dict[str, bool] = {}
    for blade in blades if isinstance(blades, list) else []:
        if isinstance(blade, dict) and blade.get("bladeCode"):
            name = str(blade["bladeCode"]).removeprefix("BLADE.").lower()
            out[name] = bool(_int(blade.get("enabled")))
    return out
