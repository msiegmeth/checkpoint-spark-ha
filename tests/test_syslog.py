"""Syslog line parsing (preparation stage)."""

from custom_components.checkpoint_spark.syslog import parse_message


def test_rfc5424_structured() -> None:
    msg = parse_message(
        '<134>1 2026-10-18T01:00:00Z GW CP-GW - Log [Fields@1.3.6.1.4.1.2620 '
        'action="Prevent" src="192.0.2.5" malware_name="Generic.TC.x"]'
    )
    assert msg["facility"] == 16 and msg["severity"] == 6
    assert msg["fields"] == {"action": "Prevent", "src": "192.0.2.5", "malware_name": "Generic.TC.x"}


def test_bsd_key_value() -> None:
    msg = parse_message('<13>Oct 18 01:00:00 GW action=Accept; src=198.51.100.4; product:"Anti Bot"')
    assert msg["fields"] == {"action": "Accept", "src": "198.51.100.4", "product": "Anti Bot"}
    assert msg["header"] == "Oct 18 01:00:00 GW"


def test_plain_text() -> None:
    msg = parse_message("hello world")
    assert "fields" not in msg and msg["header"] == "hello world"
