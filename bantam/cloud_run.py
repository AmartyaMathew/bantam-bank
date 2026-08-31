"""Lifecycle coordination for finite Cloud Run Jobs with local sidecars."""

from __future__ import annotations

import http.client
import logging
import os
from collections.abc import Callable
from typing import TypeVar


LOGGER = logging.getLogger(__name__)
SHUTDOWN_ENV = "BANTAM_CLOUD_SQL_PROXY_SHUTDOWN"
_ADMIN_HOST = "127.0.0.1"
_ADMIN_PORT = 9091
_SHUTDOWN_PATH = "/quitquitquit"
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})
_Result = TypeVar("_Result")


def _shutdown_enabled() -> bool:
    value = os.getenv(SHUTDOWN_ENV, "").strip().lower()
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False
    raise ValueError(f"{SHUTDOWN_ENV} must be true or false")


def shutdown_cloud_sql_proxy(*, timeout_seconds: float = 5.0) -> bool:
    """Ask the loopback-only Cloud SQL Auth Proxy admin server to exit."""

    if not _shutdown_enabled():
        return False

    connection = http.client.HTTPConnection(
        _ADMIN_HOST,
        _ADMIN_PORT,
        timeout=timeout_seconds,
    )
    try:
        connection.request("POST", _SHUTDOWN_PATH)
        response = connection.getresponse()
        response.read()
        if not 200 <= response.status < 300:
            raise RuntimeError(
                f"Cloud SQL Auth Proxy shutdown returned HTTP {response.status}"
            )
    finally:
        connection.close()

    LOGGER.info("Cloud SQL Auth Proxy shutdown requested")
    return True


def run_cloud_job(operation: Callable[[], _Result]) -> _Result:
    """Run finite work, then stop the proxy without masking work failures."""

    try:
        result = operation()
    except BaseException:
        try:
            shutdown_cloud_sql_proxy()
        except Exception:
            LOGGER.exception("Cloud SQL Auth Proxy shutdown failed after job failure")
        raise

    shutdown_cloud_sql_proxy()
    return result
