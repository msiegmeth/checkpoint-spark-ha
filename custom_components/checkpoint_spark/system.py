"""Parsers for read-only clish "show" outputs.

Only explicitly listed fields are kept. The raw outputs contain secrets
(PPPoE password and hash, setup Wi-Fi password, ...) and are never stored.
"""

from __future__ import annotations

from datetime import date, datetime
import re
from typing import Any

# command -> parser; all of them must start with "show"
SHOW_DIAG = "show diag"
SHOW_MEMORY = "show memory-usage"
SHOW_INTERNET = "show internet-connections"
SHOW_VPN = "show vpn tunnels"
SHOW_LICENSE = "show license"
SHOW_VERSION = "show software-version"
SHOW_FW_UPGRADE = "show cloud-services-firmware-upgrade"

_NUM = re.compile(r"-?\d+(?:\.\d+)?")


def _float(text: str | None) -> float | None:
    m = _NUM.search(text or "")
    return float(m.group()) if m else None


def parse_diag(out: str) -> dict[str, Any]:
    """Firmware, serial, temperatures, eMMC wear and overall hardware health."""
    fields: dict[str, str] = {}
    for line in out.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            fields[key.strip()] = val.strip()

    def temp(key: str) -> float | None:
        return _float(fields.get(key, "").split(" - ")[0])

    emmc = [
        int(n)
        for key, val in fields.items()
        if key.startswith("EMMC") and "lifetime used" in key
        for n in re.findall(r"\d+", val.split(" - ")[0])[-1:]
    ]
    checks = {
        key: val.rsplit(" - ", 1)[-1].split(" ")[0]
        for key, val in fields.items()
        if key.startswith(("Voltage", "CPU Temperature", "DDR Temperature", "EMMC")) and " - " in val
    }
    return {
        "firmware": fields.get("Current image name"),
        "serial_number": fields.get("Serial number"),
        "hw_version": fields.get("HW version"),
        "cpu_temperature": temp("CPU Temperature"),
        "cpu_temperature_internal": temp("CPU Temperature(internal)"),
        "ddr_temperature": temp("DDR Temperature"),
        # "0-10%" / "20-30%" -> upper bound of the worst chip
        "emmc_wear": max(emmc) if emmc else None,
        "hardware_ok": all(v == "OK" for v in checks.values()) if checks else None,
        "hardware_problems": sorted(k for k, v in checks.items() if v != "OK"),
    }


def parse_memory(out: str) -> dict[str, Any]:
    return {"memory_used_mb": _float(out)}


_INTERNET_KEYS = {
    "name": "name",
    "type": "type",
    "interface": "interface",
    "is-active": "active",
    "is-primary": "primary",
    "link-status": "link_status",
    "conn-duration": "connected_seconds",
    "ipv4-address": "ipv4_address",
}


def parse_internet(out: str) -> dict[str, Any]:
    """All internet connections (whitelisted fields only); primary connection first."""
    conns: list[dict[str, Any]] = []
    for block in re.split(r"\n\s*\n", out):
        raw: dict[str, str] = {}
        for line in block.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                raw[key.strip()] = val.strip()
        if "name" not in raw:
            continue
        conn: dict[str, Any] = {}
        for src, dst in _INTERNET_KEYS.items():
            val = raw.get(src)
            if val in (None, ""):
                continue
            if dst in ("active", "primary"):
                conn[dst] = val.lower() == "true"
            elif dst == "connected_seconds":
                conn[dst] = int(_float(val) or 0)
            else:
                conn[dst] = val
        conns.append(conn)
    conns.sort(key=lambda c: not c.get("primary"))
    return {"internet": conns}


def parse_vpn(out: str) -> dict[str, Any]:
    """'show vpn tunnels' table: header line + one line per tunnel."""
    lines = [line for line in out.splitlines() if line.strip()]
    if not lines:
        return {"vpn_tunnels": []}
    header = lines[0].split()
    tunnels = []
    for line in lines[1:]:
        cols = line.split()
        if len(cols) < 2 or set(line.strip()) <= {"-", "=", " "}:
            continue
        row = dict(zip(header, cols, strict=False))
        tunnels.append(
            {
                "name": row.get("tunnel") or cols[0],
                "type": row.get("type"),
                # last column is the state ("up"/"down"/…) in observed firmware
                "state": cols[-1].lower(),
            }
        )
    return {"vpn_tunnels": tunnels}


def _parse_date(text: str) -> date | None:
    try:
        return datetime.strptime(text, "%d%b%Y").date()
    except ValueError:
        return None


def parse_license(out: str, today: date) -> dict[str, Any]:
    """Contract coverage table: SKU + expiration (contract IDs are not kept)."""
    contracts = []
    for m in re.finditer(r"^\s*\d+\s*\|\s*\S+\s*\|\s*(\d{1,2}[A-Za-z]{3}\d{4})\s*\|\s*(\S+)", out, re.M):
        expires = _parse_date(m.group(1))
        if expires:
            contracts.append(
                {"sku": m.group(2), "expires": expires.isoformat(), "expired": expires < today}
            )
    future = sorted(date.fromisoformat(c["expires"]) for c in contracts if not c["expired"])
    return {
        "contracts": contracts,
        "next_contract_expiry": future[0].isoformat() if future else None,
        "expired_contracts": sorted(c["sku"] for c in contracts if c["expired"]),
    }


def parse_version(out: str) -> dict[str, Any]:
    """"This is Check Point's 1570 Appliance R81.10.17 - Build 968"."""
    m = re.search(r"(\S+) Appliance (R[\d.]+)\s*-\s*Build (\d+)", out)
    if not m:
        return {}
    return {"model": m.group(1), "firmware_version": m.group(2), "firmware_build": m.group(3)}


def parse_fw_upgrade(out: str) -> dict[str, Any]:
    """Automatic firmware upgrade settings (cloud service); no "update available" flag exists."""
    raw: dict[str, str] = {}
    for line in out.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            raw[key.strip()] = val.strip()
    if "activate" not in raw:
        return {}
    return {
        "firmware_auto_upgrade": {
            "enabled": raw.get("activate", "").lower() == "true",
            "frequency": raw.get("frequency"),
            "time": raw.get("time"),
            "day_of_week": raw.get("day-of-week"),
            "day_of_month": raw.get("day-of-month"),
        }
    }
