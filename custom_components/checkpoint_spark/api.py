"""Minimal client for the Gaia Embedded (Quantum Spark) local REST API.

Only read-only calls are used: login, logout, generate-report and clish
commands that start with "show".
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
from typing import Any

import aiohttp

from .const import REQUEST_TIMEOUT

_LOGGER = logging.getLogger(__name__)


class SparkError(Exception):
    """Base error."""


class SparkConnectionError(SparkError):
    """Gateway not reachable or unexpected answer."""


class SparkAuthError(SparkError):
    """Login rejected."""


def _first(obj: Any) -> Any:
    """Responses may be an object or a list with one object."""
    if isinstance(obj, list):
        return obj[0] if obj else {}
    return obj


def _b64decode(value: str) -> str:
    try:
        return base64.b64decode(value).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError) as err:
        raise SparkConnectionError(f"Invalid base64 payload: {err}") from err


class SparkApi:
    """Stateless helper; open a session with login() and close it with logout()."""

    def __init__(
        self, session: aiohttp.ClientSession, host: str, port: int, verify_ssl: bool
    ) -> None:
        self._session = session
        self._base = f"https://{host}:{port}/web-api"
        self._ssl = None if verify_ssl else False
        self._sid: str | None = None
        self.login_info: dict[str, Any] = {}

    async def _post(self, command: str, body: dict[str, Any] | None) -> Any:
        headers = {"Content-Type": "application/json"}
        if self._sid:
            headers["x-chkp-sid"] = self._sid
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT):
                resp = await self._session.post(
                    f"{self._base}/{command}",
                    data=json.dumps(body) if body is not None else None,
                    headers=headers,
                    ssl=self._ssl,
                )
                text = await resp.text()
        except (TimeoutError, aiohttp.ClientError) as err:
            raise SparkConnectionError(f"{command}: {err}") from err

        # Wrong credentials come back as 400/401, on some firmware as
        # 500 {"errorCode": "system_error", "errors": ["Web server error"]}.
        if command == "login" and (
            resp.status in (400, 401, 403)
            or (resp.status == 500 and "system_error" in text)
        ):
            _LOGGER.debug("login rejected: HTTP %s %s", resp.status, text[:200])
            raise SparkAuthError(f"login rejected (HTTP {resp.status})")
        if resp.status in (401, 403):
            raise SparkAuthError(f"{command}: HTTP {resp.status}")
        if resp.status != 200:
            raise SparkConnectionError(f"{command}: HTTP {resp.status}: {text[:200]}")
        if not text:
            return {}
        try:
            return json.loads(text)
        except ValueError as err:
            raise SparkConnectionError(f"{command}: invalid JSON") from err

    async def login(self, user: str, password: str) -> dict[str, Any]:
        data = _first(await self._post("login", {"user": user, "password": password}))
        sid = data.get("sid") if isinstance(data, dict) else None
        if not sid:
            raise SparkAuthError("login returned no sid")
        self._sid = sid
        self.login_info = {k: v for k, v in data.items() if k != "sid"}
        return self.login_info

    async def logout(self) -> None:
        if not self._sid:
            return
        try:
            await self._post("logout", None)
        except SparkError as err:
            _LOGGER.debug("logout failed: %s", err)
        finally:
            self._sid = None

    async def generate_report(self, report_type: str) -> Any:
        """Return the decoded reportData (parsed JSON)."""
        data = _first(await self._post("generate-report", {"type": report_type}))
        raw = data.get("reportData") if isinstance(data, dict) else None
        if not raw:
            raise SparkConnectionError(f"generate-report {report_type}: no reportData")
        try:
            return json.loads(_b64decode(raw))
        except ValueError as err:
            raise SparkConnectionError(
                f"generate-report {report_type}: reportData is not JSON"
            ) from err

    async def run_show_command(self, command: str) -> str:
        """Run a read-only clish command. Only "show ..." is allowed."""
        if not command.strip().lower().startswith("show "):
            raise ValueError("only clish 'show' commands are allowed")
        script = base64.b64encode(command.encode()).decode()
        data = _first(await self._post("run-clish-command", {"script": script}))
        out = data.get("output", "") if isinstance(data, dict) else ""
        return _b64decode(out) if out else ""
