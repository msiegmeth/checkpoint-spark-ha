"""Constants for the Check Point Quantum Spark integration."""

from __future__ import annotations

from typing import Final

DOMAIN: Final = "checkpoint_spark"

DEFAULT_PORT: Final = 4434
DEFAULT_VERIFY_SSL: Final = False

CONF_REPORT_TYPES: Final = "report_types"
CONF_SCAN_INTERVAL_MIN: Final = "scan_interval"

REPORT_TYPES: Final = ["hourly", "daily", "weekly", "monthly"]
DEFAULT_REPORT_TYPES: Final = ["daily"]

DEFAULT_SCAN_INTERVAL_MIN: Final = 15
# Polling interval per report type (minutes); option key f"{CONF_SCAN_INTERVAL_MIN}_{type}"
DEFAULT_INTERVALS: Final = {"hourly": 15, "daily": 30, "weekly": 180, "monthly": 360}
MIN_SCAN_INTERVAL_MIN: Final = 5
MAX_SCAN_INTERVAL_MIN: Final = 1440

CONF_MONITORED_BLADES: Final = "monitored_blades"
CONF_REDACT_DIAGNOSTICS: Final = "redact_diagnostics"
CONF_SYSLOG_ENABLED: Final = "syslog_enabled"
CONF_SYSLOG_PORT: Final = "syslog_port"
DEFAULT_SYSLOG_PORT: Final = 5140
CONF_SYSLOG_IGNORE: Final = "syslog_ignore_sources"
CONF_SYSLOG_SENDERS: Final = "syslog_senders"
CONF_SYSLOG_FORWARD: Final = "syslog_forward"
CONF_SYSLOG_RETENTION: Final = "syslog_retention_days"
DEFAULT_SYSLOG_RETENTION: Final = 90

EVENT_THREAT: Final = f"{DOMAIN}_threat"
# Same threat is reported at most once per this many hours
EVENT_DEDUP_HOURS: Final = 24
# Report types used for threat events, most current first
EVENT_REPORT_ORDER: Final = ["hourly", "daily", "weekly", "monthly"]

REQUEST_TIMEOUT: Final = 60
