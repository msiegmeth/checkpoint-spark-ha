"""Evaluation of parsed syslog messages (no Home Assistant imports, unit-testable).

Recognised (observed on R81.10.17, Check Point log export key="value" format):
- IPS:            ProductName "SmartDefense" with an "attack" field
- Malware:        anti-virus / anti-bot / threat emulation messages that name a
                  malware or protection (best effort, field names vary)
- Anti-Malware:   periodic status "Anti Malware" with scan_hosts_* / unique_detected_*
- Firewall drop:  "VPN-1 & FireWall-1" with Action "drop"
"""

from __future__ import annotations

from collections import Counter, deque
from datetime import datetime, timedelta
from typing import Any

WINDOW = timedelta(hours=24)
RECENT = 20
EVENT_DEDUP = timedelta(hours=1)

_MALWARE_PRODUCTS = ("anti virus", "anti-virus", "anti bot", "anti-bot", "threat emulation", "threat extraction")
_MALWARE_NAME_KEYS = ("malware_name", "malware_family", "protection_name", "virus_name", "Name", "attack")
_SEVERITY = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _clean(value: Any) -> str | None:
    text = str(value).strip() if value is not None else ""
    return text or None


class LogAnalyzer:
    """Keeps rolling 24 h counters and recent detections; returns events for new threats."""

    def __init__(self, ignore_sources: set[str] | None = None) -> None:
        self.ignore_sources = set(ignore_sources or ())
        self.ips: deque[dict[str, Any]] = deque()
        self.drops: deque[tuple[datetime, str | None, str | None]] = deque()
        self.recent_ips: deque[dict[str, Any]] = deque(maxlen=RECENT)
        self.recent_malware: deque[dict[str, Any]] = deque(maxlen=RECENT)
        self.anti_malware: dict[str, int] = {}
        self.ignored = 0
        self._last_event: dict[tuple[str, str, str], datetime] = {}

    # ------------------------------------------------------------- input --
    def add(self, msg: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
        fields: dict[str, str] = msg.get("fields") or {}
        product = (fields.get("ProductName") or "").strip()
        lower = product.lower()
        self._prune(now)

        if lower == "anti malware" and "scan_hosts_day" in fields:
            for key in (
                "scan_hosts_hour", "scan_hosts_day", "scan_hosts_week",
                "unique_detected_hour", "unique_detected_day", "unique_detected_week",
            ):
                if (val := _int(fields.get(key))) is not None:
                    self.anti_malware[key] = val
            return []

        if "firewall" in lower and (fields.get("Action") or "").strip().lower() == "drop":
            self.drops.append((now, fields.get("src"), fields.get("service_id") or fields.get("svc")))
            return []

        if lower == "smartdefense" and fields.get("attack"):
            return self._detection("ips_attack", fields, now, self.recent_ips, self.ips)

        if any(p in lower for p in _MALWARE_PRODUCTS):
            if any(_clean(fields.get(k)) for k in _MALWARE_NAME_KEYS):
                return self._detection("malware_detected", fields, now, self.recent_malware, None)
        return []

    def _detection(
        self,
        kind: str,
        fields: dict[str, str],
        now: datetime,
        recent: deque[dict[str, Any]],
        window: deque[dict[str, Any]] | None,
    ) -> list[dict[str, Any]]:
        src = _clean(fields.get("src"))
        name = next(
            (_clean(fields.get(k)) for k in ("Name", "malware_name", "protection_name", "attack") if _clean(fields.get(k))),
            None,
        )
        item = {
            "time": now.isoformat(),
            "name": name,
            "attack": _clean(fields.get("attack")),
            "severity": _SEVERITY.get(str(fields.get("Severity") or fields.get("severity") or "").strip()),
            "action": _clean(fields.get("Action")) or None,
            "src": src,
            "dst": _clean(fields.get("dst")),
            "cve": _clean(fields.get("Reference")),
            "resource": (_clean(fields.get("resource")) or "")[:200] or None,
            "product": _clean(fields.get("ProductName")),
        }
        item = {k: v for k, v in item.items() if v is not None}
        if src in self.ignore_sources:
            self.ignored += 1
            return []
        recent.append(item)
        if window is not None:
            window.append(item | {"_t": now})
        key = (kind, name or "", src or "")
        last = self._last_event.get(key)
        if last and now - last < EVENT_DEDUP:
            return []
        self._last_event[key] = now
        return [{"kind": kind, "source": "syslog", "value": 1, **item}]

    def _prune(self, now: datetime) -> None:
        cutoff = now - WINDOW
        while self.ips and self.ips[0]["_t"] < cutoff:
            self.ips.popleft()
        while self.drops and self.drops[0][0] < cutoff:
            self.drops.popleft()
        stale = now - EVENT_DEDUP
        if len(self._last_event) > 1000:
            self._last_event = {k: t for k, t in self._last_event.items() if t >= stale}

    # ------------------------------------------------------------ output --
    def ips_count(self, now: datetime, hours: int = 1) -> int:
        cutoff = now - timedelta(hours=hours)
        return sum(1 for i in self.ips if i["_t"] >= cutoff)

    def drop_count(self, now: datetime, hours: int = 1) -> int:
        cutoff = now - timedelta(hours=hours)
        return sum(1 for t, _s, _v in self.drops if t >= cutoff)

    def drop_top(self, index: int, limit: int = 5) -> list[dict[str, Any]]:
        counts = Counter(d[index] for d in self.drops if d[index])
        return [{"name": k, "count": v} for k, v in counts.most_common(limit)]
