"""Parsers for clish show outputs (anonymised sample outputs)."""

from datetime import date

from custom_components.checkpoint_spark import system

DIAG = """
Current system info
-----------------------------------
Current image name: R81_996004968_10_17
Serial number: XX00000000
HW version: 071
Setup WiFi password: secret123
Voltage 3V3:\t\t3.3572V - OK (valid: 3.1500V ~ 3.4500V)
CPU Temperature:\t\t48.0000C - OK (valid: 0.0000C ~ 86.0000C)
CPU Temperature(internal):\t\t57.9780C - OK (valid: 0.0000C ~ 105.0000C)
DDR Temperature:\t\t47.0000C - OK (valid: 0.0000C ~ 86.0000C)
EMMC % of device lifetime used:\t\t0-10% - OK (valid: 0 ~ 99%)
EMMC(Type B) % of device lifetime used:\t\t20-30% - OK (valid: 0 ~ 99%)
EMMC EOL status:\t\tNormal - OK
"""

INTERNET = """name:                         Internet1
password:                     topsecret
password-hash:                abcdef
type:                         pppoe
interface:                    WAN
is-active:                    true
is-primary:                   true
link-status:                  1/full
conn-duration:                1037401
ipv4-address:                 198.51.100.7
"""

LICENSE = """Contract Coverage:

 #   ID          Expiration   SKU
===+===========+============+====================
1  | AAAAAAA   | 31Mar2029  | CPSB-EBP-IPS
   +-----------+------------+--------------------
2  | BBBBBBB   | 12Apr2024  | CPSB-TE-S-2Y
"""


def test_diag() -> None:
    d = system.parse_diag(DIAG)
    assert d["firmware"] == "R81_996004968_10_17"
    assert d["cpu_temperature"] == 48.0
    assert d["ddr_temperature"] == 47.0
    assert d["emmc_wear"] == 30
    assert d["hardware_ok"] is True
    assert "secret123" not in str(d)


def test_diag_problem() -> None:
    d = system.parse_diag(DIAG.replace("47.0000C - OK", "90.0000C - HIGH"))
    assert d["hardware_ok"] is False
    assert d["hardware_problems"] == ["DDR Temperature"]


def test_internet_whitelist() -> None:
    conns = system.parse_internet(INTERNET)["internet"]
    assert conns == [
        {
            "name": "Internet1",
            "type": "pppoe",
            "interface": "WAN",
            "active": True,
            "primary": True,
            "link_status": "1/full",
            "connected_seconds": 1037401,
            "ipv4_address": "198.51.100.7",
        }
    ]
    assert "topsecret" not in str(conns) and "abcdef" not in str(conns)


def test_vpn() -> None:
    out = "tunnel type local remote peer internet-connection state\nt1 s a b p I1 up\nt2 s a b p I1 down\n"
    tunnels = system.parse_vpn(out)["vpn_tunnels"]
    assert [t["state"] for t in tunnels] == ["up", "down"]
    assert system.parse_vpn("tunnel type state\n")["vpn_tunnels"] == []


def test_license() -> None:
    lic = system.parse_license(LICENSE, date(2026, 10, 18))
    assert lic["next_contract_expiry"] == "2029-03-31"
    assert lic["expired_contracts"] == ["CPSB-TE-S-2Y"]
    assert "AAAAAAA" not in str(lic)


def test_memory() -> None:
    assert system.parse_memory("Memory usage is: 1464 MB\n") == {"memory_used_mb": 1464.0}
