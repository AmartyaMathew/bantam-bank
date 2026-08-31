"""Cloud Run sidecar lifecycle regressions."""

from __future__ import annotations

import pytest

import bantam.cloud_run as cloud_run


class FakeResponse:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.read_called = False

    def read(self) -> bytes:
        self.read_called = True
        return b""


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.request_call: tuple[str, str] | None = None
        self.closed = False

    def request(self, method: str, path: str) -> None:
        self.request_call = (method, path)

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def test_cloud_job_does_not_contact_proxy_by_default(monkeypatch) -> None:
    monkeypatch.delenv(cloud_run.SHUTDOWN_ENV, raising=False)
    monkeypatch.setattr(
        cloud_run.http.client,
        "HTTPConnection",
        lambda *args, **kwargs: pytest.fail("proxy must not be contacted"),
    )

    assert cloud_run.run_cloud_job(lambda: "complete") == "complete"


def test_cloud_job_stops_proxy_after_success(monkeypatch) -> None:
    response = FakeResponse()
    connection = FakeConnection(response)
    monkeypatch.setenv(cloud_run.SHUTDOWN_ENV, "true")
    monkeypatch.setattr(
        cloud_run.http.client,
        "HTTPConnection",
        lambda host, port, timeout: connection,
    )

    assert cloud_run.run_cloud_job(lambda: 7) == 7
    assert connection.request_call == ("POST", "/quitquitquit")
    assert response.read_called is True
    assert connection.closed is True


def test_successful_work_fails_when_proxy_cannot_stop(monkeypatch) -> None:
    monkeypatch.setenv(cloud_run.SHUTDOWN_ENV, "true")

    class BrokenConnection(FakeConnection):
        def request(self, method: str, path: str) -> None:
            raise OSError("proxy unavailable")

    connection = BrokenConnection(FakeResponse())
    monkeypatch.setattr(
        cloud_run.http.client,
        "HTTPConnection",
        lambda host, port, timeout: connection,
    )

    with pytest.raises(OSError, match="proxy unavailable"):
        cloud_run.run_cloud_job(lambda: None)

    assert connection.closed is True


def test_work_failure_is_not_masked_by_shutdown_failure(monkeypatch) -> None:
    monkeypatch.setenv(cloud_run.SHUTDOWN_ENV, "true")

    class BrokenConnection(FakeConnection):
        def request(self, method: str, path: str) -> None:
            raise OSError("proxy unavailable")

    monkeypatch.setattr(
        cloud_run.http.client,
        "HTTPConnection",
        lambda host, port, timeout: BrokenConnection(FakeResponse()),
    )

    def fail_work() -> None:
        raise RuntimeError("migration failed")

    with pytest.raises(RuntimeError, match="migration failed"):
        cloud_run.run_cloud_job(fail_work)


def test_shutdown_flag_is_strict(monkeypatch) -> None:
    monkeypatch.setenv(cloud_run.SHUTDOWN_ENV, "sometimes")

    with pytest.raises(ValueError, match=cloud_run.SHUTDOWN_ENV):
        cloud_run.shutdown_cloud_sql_proxy()
