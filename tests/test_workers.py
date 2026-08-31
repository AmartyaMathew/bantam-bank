"""Projection-worker regressions for idempotent event handling."""

from __future__ import annotations

import asyncio
import json
from contextlib import nullcontext
from types import SimpleNamespace
from uuid import uuid4

from bantam.workers import NotificationWorker, PullWorker


class Result:
    def __init__(self, rows=None) -> None:
        self.rows = rows or []

    def fetchall(self):
        return self.rows


def test_pull_worker_treats_asyncio_timeout_as_empty_poll() -> None:
    class Worker(PullWorker):
        durable = "test-worker"

    async def run_worker_once() -> int:
        stop = asyncio.Event()

        class Subscription:
            calls = 0

            async def fetch(self, *, batch, timeout):
                assert batch == 10
                assert timeout == 1
                self.calls += 1
                stop.set()
                raise asyncio.TimeoutError

        subscription = Subscription()

        class JetStream:
            async def pull_subscribe(self, subject, *, durable, stream):
                assert subject == "payment.transfer_posted.v1"
                assert durable == "test-worker"
                assert stream == "BANTAM_EVENTS"
                return subscription

        await Worker(None, JetStream()).run(stop)
        return subscription.calls

    assert asyncio.run(run_worker_once()) == 1


def test_self_transfer_keeps_sent_and_received_notifications_distinct() -> None:
    customer_id = uuid4()
    source_id = uuid4()
    destination_id = uuid4()
    inserts: list[tuple[object, ...]] = []

    class Connection:
        def execute(self, query, parameters):
            if "SELECT account_id, customer_id" in query:
                return Result(
                    [
                        {"account_id": source_id, "customer_id": customer_id},
                        {"account_id": destination_id, "customer_id": customer_id},
                    ]
                )
            assert "account_id, direction" in query
            inserts.append(parameters)
            return Result()

    class Pool:
        def connection(self):
            return nullcontext(Connection())

    event_id = uuid4()
    message = SimpleNamespace(
        data=json.dumps(
            {
                "event_id": str(event_id),
                "payload": {
                    "source_account_id": str(source_id),
                    "destination_account_id": str(destination_id),
                    "amount_minor": 2500,
                    "currency": "GBP",
                },
            }
        ).encode()
    )

    NotificationWorker(Pool(), None).handle(message)

    assert len(inserts) == 2
    assert {(row[3], row[4]) for row in inserts} == {
        (source_id, "SENT"),
        (destination_id, "RECEIVED"),
    }
