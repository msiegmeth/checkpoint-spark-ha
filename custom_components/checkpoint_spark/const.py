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
MIN_SCAN_INTERVAL_MIN: Final = 5
MAX_SCAN_INTERVAL_MIN: Final = 1440

REQUEST_TIMEOUT: Final = 60
