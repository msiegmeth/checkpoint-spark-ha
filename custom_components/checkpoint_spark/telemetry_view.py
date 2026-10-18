"""HTTP endpoint for the gateway's OpenTelemetry export (Prometheus remote write)."""

from __future__ import annotations

import base64
import binascii
import hmac
import logging

from aiohttp import web

from homeassistant.components.http import HomeAssistantView
from homeassistant.helpers.http import KEY_HASS
from homeassistant.util import dt as dt_util

from .const import CONF_TELEMETRY_PASSWORD, CONF_TELEMETRY_USERNAME, DOMAIN
from .telemetry import MAX_BODY, TelemetryError, parse_write_request, snappy_decompress

_LOGGER = logging.getLogger(__name__)
TELEMETRY_URL = f"/api/{DOMAIN}/telemetry"


def _decode(body: bytes, encoding: str) -> list:
    raw = snappy_decompress(body) if "snappy" in encoding else body
    return parse_write_request(raw)


class TelemetryView(HomeAssistantView):
    """Accepts remote-write POSTs from a configured gateway (basic auth + source IP)."""

    url = TELEMETRY_URL
    name = f"api:{DOMAIN}:telemetry"
    requires_auth = False  # the gateway can only do basic auth; checked below
    cors_allowed = False

    async def post(self, request: web.Request) -> web.Response:
        hass = request.app[KEY_HASS]
        remote = request.remote or ""
        coordinator = next(
            (
                e.runtime_data
                for e in hass.config_entries.async_loaded_entries(DOMAIN)
                if getattr(e.runtime_data, "telemetry", None) is not None
                and remote in e.runtime_data.telemetry_allowed
            ),
            None,
        )
        if coordinator is None:
            _LOGGER.debug("Telemetry POST from %s rejected (not an allowed gateway)", remote)
            return web.Response(status=403)
        store = coordinator.telemetry
        opts = coordinator.config_entry.options
        if not self._authorized(request, opts.get(CONF_TELEMETRY_USERNAME, ""), opts.get(CONF_TELEMETRY_PASSWORD, "")):
            store.rejected += 1
            return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="checkpoint_spark"'})
        if (request.content_length or 0) > MAX_BODY:
            store.rejected += 1
            return web.Response(status=413)
        body = await request.content.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            store.rejected += 1
            return web.Response(status=413)
        if "write.v2" in (request.headers.get("Content-Type") or ""):
            store.rejected += 1
            _LOGGER.warning("Telemetry: remote write v2 is not supported yet")
            return web.Response(status=415)
        try:
            series = await hass.async_add_executor_job(_decode, body, request.headers.get("Content-Encoding", "snappy"))
        except (TelemetryError, ValueError, IndexError) as err:
            store.rejected += 1
            _LOGGER.debug("Telemetry payload rejected: %s", err)
            return web.Response(status=400)
        store.add(series, dt_util.utcnow())
        for listener in list(store.listeners):
            listener()
        return web.Response(status=204)

    @staticmethod
    def _authorized(request: web.Request, user: str, password: str) -> bool:
        if not password:
            return False
        header = request.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            got_user, _, got_pw = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        except (binascii.Error, UnicodeDecodeError):
            return False
        return hmac.compare_digest(got_user, user) & hmac.compare_digest(got_pw, password)
