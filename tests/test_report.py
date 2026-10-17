"""Report parsing against the anonymised sample in docs/."""

import json
from pathlib import Path

from custom_components.checkpoint_spark.report import (
    _chart,
    _compact,
    _has_summary,
    _summary,
    blades_of,
)

SAMPLE = json.loads((Path(__file__).parents[1] / "docs" / "report-sample.json").read_text())


def test_summary() -> None:
    assert _summary(SAMPLE, "TOTAL_PROTECTIONS") == 1531
    assert _has_summary(SAMPLE, "TOTAL_HIGH_RISK_APPS")
    assert _summary(SAMPLE, "DOES_NOT_EXIST") is None
    assert _summary({}, "TOTAL_BYTES") is None


def test_chart() -> None:
    apps = _chart(SAMPLE, "topAppsByBandwidthChart")
    assert apps and isinstance(apps[0]["bytes"], int)
    assert _chart(SAMPLE, "topUsersByBandwidthChart") == []  # no chartData
    assert _chart({}, "anything") == []


def test_compact() -> None:
    assert _compact({"name": "x", "value": "3"}) == {"name": "x", "count": 3}
    item = _compact({"name": "a", "risk": "APPI_RANK_LEVEL.HIGHRISK", "severity": "MALWARE_SEVERITY.MEDIUM"})
    assert item["risk"] == "high" and item["severity"] == "medium"


def test_blades() -> None:
    blades = blades_of(SAMPLE)
    assert blades["ips"] is True
    assert blades["threat_emulation"] is False
