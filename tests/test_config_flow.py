"""Config flow."""

from unittest.mock import patch

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.checkpoint_spark.api import SparkAuthError, SparkConnectionError
from custom_components.checkpoint_spark.const import DOMAIN

INPUT = {
    "host": "192.0.2.1",
    "port": 4434,
    "username": "ha-api",
    "password": "pw",
    "verify_ssl": False,
}
LOGIN = "custom_components.checkpoint_spark.config_flow.SparkApi.login"


async def _start(hass: HomeAssistant):
    return await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )


async def test_success(hass: HomeAssistant) -> None:
    result = await _start(hass)
    assert result["type"] is FlowResultType.FORM
    with (
        patch(LOGIN, return_value={"role": "ROLE.RO"}),
        patch("custom_components.checkpoint_spark.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], INPUT)
    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["result"].unique_id == "192.0.2.1:4434"
    assert result["data"]["username"] == "ha-api"


async def test_invalid_auth(hass: HomeAssistant) -> None:
    result = await _start(hass)
    with patch(LOGIN, side_effect=SparkAuthError("nope")):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], INPUT)
    assert result["errors"] == {"base": "invalid_auth"}


async def test_cannot_connect(hass: HomeAssistant) -> None:
    result = await _start(hass)
    with patch(LOGIN, side_effect=SparkConnectionError("down")):
        result = await hass.config_entries.flow.async_configure(result["flow_id"], INPUT)
    assert result["errors"] == {"base": "cannot_connect"}


async def test_already_configured(hass: HomeAssistant) -> None:
    MockConfigEntry(domain=DOMAIN, unique_id="192.0.2.1:4434", data=INPUT).add_to_hass(hass)
    result = await _start(hass)
    result = await hass.config_entries.flow.async_configure(result["flow_id"], INPUT)
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "already_configured"
