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


def test_control_chars_and_length() -> None:
    from custom_components.checkpoint_spark.syslog import MAX_FIELD_LEN

    msg = parse_message('<13>x a="' + "A" * 5000 + '" b="x\x1b[31my"')
    assert len(msg["fields"]["a"]) == MAX_FIELD_LEN
    assert "\x1b" not in msg["fields"]["b"]


def test_parse_target_and_hosts() -> None:
    from custom_components.checkpoint_spark.syslog import parse_target, split_hosts

    assert parse_target("192.0.2.2:514") == ("192.0.2.2", 514)
    assert parse_target("nas.local") == ("nas.local", 514)
    assert parse_target("nas:99999") is None and parse_target("") is None
    assert split_hosts("a, b;c ,") == {"a", "b", "c"}
