"""Syslog evaluation (anonymised sample fields)."""

from datetime import UTC, datetime, timedelta

from custom_components.checkpoint_spark.log_analysis import LogAnalyzer
from custom_components.checkpoint_spark.syslog import parse_message

NOW = datetime(2026, 10, 18, 8, 0, tzinfo=UTC)
IPS = (
    '<14>Oct 18 03:18:55 GW Action="reject" Name="Directory Traversal" Severity="4" '
    'Reference="CVE-2002-0946" attack="Directory Traversal" src="192.0.2.2" dst="192.0.2.1" '
    'ProductName="SmartDefense"'
)
STATUS = (
    '<14>Oct 18 01:02:12 GW Action=" " scan_hosts_hour="46" scan_hosts_day="58" scan_hosts_week="182" '
    'unique_detected_hour="3" unique_detected_day="5" unique_detected_week="10" ProductName="Anti Malware"'
)
DROP = '<85>Oct 18 00:57:29 GW Action="drop" service_id="tcp-high-ports" src="203.0.113.9" ProductName="VPN-1 & FireWall-1"'


def test_ips_event_and_dedup() -> None:
    a = LogAnalyzer()
    events = a.add(parse_message(IPS), NOW)
    assert len(events) == 1
    ev = events[0]
    assert ev["kind"] == "ips_attack" and ev["source"] == "syslog"
    assert ev["name"] == "Directory Traversal" and ev["severity"] == "critical"
    assert ev["cve"] == "CVE-2002-0946" and ev["src"] == "192.0.2.2"
    # same attack + source within the hour: counted, but no new event
    assert a.add(parse_message(IPS), NOW + timedelta(minutes=5)) == []
    assert a.ips_count(NOW + timedelta(minutes=5)) == 2
    assert len(a.add(parse_message(IPS), NOW + timedelta(minutes=70))) == 1


def test_ignore_sources() -> None:
    a = LogAnalyzer({"192.0.2.2"})
    assert a.add(parse_message(IPS), NOW) == []
    assert a.ignored == 1 and a.ips_count(NOW) == 0


def test_anti_malware_status() -> None:
    a = LogAnalyzer()
    a.add(parse_message(STATUS), NOW)
    assert a.anti_malware["scan_hosts_day"] == 58
    assert a.anti_malware["unique_detected_week"] == 10


def test_firewall_drops_window() -> None:
    a = LogAnalyzer()
    a.add(parse_message(DROP), NOW - timedelta(hours=2))
    a.add(parse_message(DROP), NOW)
    assert a.drop_count(NOW) == 1 and a.drop_count(NOW, 24) == 2
    assert a.drop_top(1) == [{"name": "203.0.113.9", "count": 2}]


def test_truncated_value() -> None:
    msg = parse_message('<14>Oct 18 03:08:08 GW Action="accept" ProductName="Application Control(+)URL Filte')
    assert msg["fields"]["ProductName"] == "Application Control(+)URL Filte"
