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
import ipaddress
from typing import Any

WINDOW = timedelta(hours=24)
RECENT = 20
EVENT_DEDUP = timedelta(hours=1)
MAX_EVENTS_PER_HOUR = 30      # global cap so a flood cannot spam notifications
MAX_HISTORY = 2000            # persisted detections
MAX_WINDOW_IPS = 20_000       # rolling 24 h buffers are bounded as well
MAX_WINDOW_DROPS = 200_000

_MALWARE_PRODUCTS = ("anti virus", "anti-virus", "anti bot", "anti-bot", "threat emulation", "threat extraction")
_MALWARE_NAME_KEYS = ("malware_name", "malware_family", "protection_name", "virus_name", "Name", "attack")
_HISTORY_KEYS = {"time", "kind", "name", "attack", "severity", "action", "src", "dst", "cve", "resource", "product", "direction"}
DIRECTIONS = ("inbound", "internal", "outbound")


def _is_internal(ip: str | None) -> bool | None:
    """Private/LAN address (RFC 1918, link-local, loopback, CGNAT); None if not an IP."""
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr in ipaddress.ip_network("100.64.0.0/10")


def direction(src: str | None, dst: str | None) -> str | None:
    """inbound = from the internet, internal = LAN to LAN, outbound = LAN to the internet."""
    s_int, d_int = _is_internal(src), _is_internal(dst)
    if s_int is None:
        return None
    if not s_int:
        return "inbound"
    if d_int is False:
        return "outbound"
    return "internal"
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

    def __init__(self, ignore_sources: set[str] | None = None, retention_days: int = 90) -> None:
        self.ignore_sources = set(ignore_sources or ())
        self.retention = timedelta(days=max(1, retention_days))
        self.ips: deque[dict[str, Any]] = deque(maxlen=MAX_WINDOW_IPS)
        self.drops: deque[tuple[datetime, str | None, str | None]] = deque(maxlen=MAX_WINDOW_DROPS)
        self.recent_ips: deque[dict[str, Any]] = deque(maxlen=RECENT)
        self.recent_malware: deque[dict[str, Any]] = deque(maxlen=RECENT)
        # persisted detections (IPS + malware), newest last
        self.history: deque[dict[str, Any]] = deque(maxlen=MAX_HISTORY)
        self.anti_malware: dict[str, int] = {}
        self.ignored = 0
        self.events_suppressed = 0
        self.dirty = False
        self._last_event: dict[tuple[str, str, str], datetime] = {}
        self._event_times: deque[datetime] = deque(maxlen=MAX_EVENTS_PER_HOUR)

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
            "direction": direction(src, _clean(fields.get("dst"))),
        }
        item = {k: v for k, v in item.items() if v is not None}
        if src in self.ignore_sources:
            self.ignored += 1
            return []
        recent.append(item)
        self.history.append(item | {"kind": kind})
        self.dirty = True
        if window is not None:
            window.append(item | {"_t": now})
        key = (kind, name or "", src or "")
        last = self._last_event.get(key)
        if last and now - last < EVENT_DEDUP:
            return []
        if len(self._event_times) == MAX_EVENTS_PER_HOUR and now - self._event_times[0] < timedelta(hours=1):
            self.events_suppressed += 1
            return []
        self._last_event[key] = now
        self._event_times.append(now)
        return [{"kind": kind, "source": "syslog", "value": 1, **item}]

    def _prune(self, now: datetime) -> None:
        old = now - self.retention
        while self.history and self.history[0]["time"] < old.isoformat():
            self.history.popleft()
            self.dirty = True
        cutoff = now - WINDOW
        while self.ips and self.ips[0]["_t"] < cutoff:
            self.ips.popleft()
        while self.drops and self.drops[0][0] < cutoff:
            self.drops.popleft()
        stale = now - EVENT_DEDUP
        if len(self._last_event) > 1000:
            self._last_event = {k: t for k, t in self._last_event.items() if t >= stale}

    # ------------------------------------------------------- persistence --
    def dump(self) -> dict[str, Any]:
        return {"history": list(self.history)}

    def load(self, data: dict[str, Any], now: datetime) -> None:
        """Restore persisted detections (validated, bounded)."""
        for item in (data or {}).get("history", [])[-MAX_HISTORY:]:
            if not isinstance(item, dict) or not isinstance(item.get("time"), str):
                continue
            clean = {
                k: (v[:500] if isinstance(v, str) else v)
                for k, v in item.items()
                if k in _HISTORY_KEYS and isinstance(v, (str, int, float))
            }
            if "direction" not in clean and (d := direction(clean.get("src"), clean.get("dst"))):
                clean["direction"] = d  # entries stored before 0.6.0
            self.history.append(clean)
            (self.recent_malware if clean.get("kind") == "malware_detected" else self.recent_ips).append(
                {k: v for k, v in clean.items() if k != "kind"}
            )
        self._prune(now)
        self.dirty = False

    def history_since(self, now: datetime, days: int, kind: str | None = None) -> list[dict[str, Any]]:
        cutoff = (now - timedelta(days=days)).isoformat()
        return [i for i in self.history if i["time"] >= cutoff and (kind is None or i.get("kind") == kind)]

    def daily_counts(self, now: datetime, days: int = 30) -> dict[str, dict[str, int]]:
        """{'2026-10-18': {'ips_attack': 3, 'malware_detected': 1}, …} for the last days."""
        out: dict[str, dict[str, int]] = {}
        for item in self.history_since(now, days):
            day = item["time"][:10]
            out.setdefault(day, {}).setdefault(item.get("kind", "?"), 0)
            out[day][item.get("kind", "?")] += 1
        return out

    # ------------------------------------------------------------ output --
    def ips_count(self, now: datetime, hours: int = 1, direction: str | None = None) -> int:
        cutoff = now - timedelta(hours=hours)
        return sum(1 for i in self.ips if i["_t"] >= cutoff and (direction is None or i.get("direction") == direction))

    def direction_counts(self, now: datetime, days: int, kind: str = "ips_attack") -> dict[str, int]:
        """Stored detections of one kind per direction over the last days."""
        out = dict.fromkeys(DIRECTIONS, 0)
        for item in self.history_since(now, days, kind):
            if item.get("direction") in out:
                out[item["direction"]] += 1
        return out

    def drop_count(self, now: datetime, hours: int = 1) -> int:
        cutoff = now - timedelta(hours=hours)
        return sum(1 for t, _s, _v in self.drops if t >= cutoff)

    def drop_top(self, index: int, limit: int = 5) -> list[dict[str, Any]]:
        counts = Counter(d[index] for d in self.drops if d[index])
        return [{"name": k, "count": v} for k, v in counts.most_common(limit)]
