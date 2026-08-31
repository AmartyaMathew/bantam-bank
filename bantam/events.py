"""Transactional-outbox publisher and event-bus bootstrap logic."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import UUID

import nats
from nats.aio.client import Client as NATS
from nats.js import JetStreamContext
from nats.js.api import RetentionPolicy, StorageType, StreamConfig
from nats.js.errors import APIError, NotFoundError
from psycopg_pool import ConnectionPool

from bantam.pubsub import PubSubClient


LOGGER = logging.getLogger(__name__)
STREAM_NAME = "BANTAM_EVENTS"
SUBJECTS = ["customer.>", "account.>", "payment.>", "ledger.>", "risk.>", "audit.>"]


@dataclass(frozen=True, slots=True)
class OutboxEvent:
    event_id: UUID
    aggregate_id: UUID
    event_type: str
    event_version: int
    payload: dict[str, object]
    created_at: datetime


class EventPublisher(Protocol):
    async def publish(
        self, event: OutboxEvent, envelope: dict[str, object]
    ) -> dict[str, object]:
        """Publish one outbox event and return backend-specific log metadata."""


async def connect(url: str, name: str) -> tuple[NATS, JetStreamContext]:
    connection = await nats.connect(
        url,
        name=name,
        max_reconnect_attempts=-1,
        reconnect_time_wait=1,
    )
    jetstream = connection.jetstream()
    try:
        await jetstream.stream_info(STREAM_NAME)
    except NotFoundError:
        try:
            await jetstream.add_stream(
                config=StreamConfig(
                    name=STREAM_NAME,
                    subjects=SUBJECTS,
                    storage=StorageType.FILE,
                    retention=RetentionPolicy.LIMITS,
                    max_age=timedelta(days=7).total_seconds(),
                )
            )
        except APIError:
            # Several services start together; another may have won stream creation.
            await jetstream.stream_info(STREAM_NAME)
    return connection, jetstream


class NatsEventPublisher:
    def __init__(self, jetstream: JetStreamContext) -> None:
        self.jetstream = jetstream

    async def publish(
        self, event: OutboxEvent, envelope: dict[str, object]
    ) -> dict[str, object]:
        acknowledgement = await self.jetstream.publish(
            event.event_type,
            json.dumps(envelope, separators=(",", ":")).encode(),
            headers={"Nats-Msg-Id": str(event.event_id)},
        )
        return {"stream_sequence": acknowledgement.seq}


class PubSubEventPublisher:
    def __init__(self, client: PubSubClient, topic: str) -> None:
        self.client = client
        self.topic = topic

    async def publish(
        self, event: OutboxEvent, envelope: dict[str, object]
    ) -> dict[str, object]:
        message_id = await asyncio.to_thread(
            self.client.publish,
            self.topic,
            json.dumps(envelope, separators=(",", ":")).encode(),
            {
                "event_id": str(event.event_id),
                "event_type": event.event_type,
                "event_version": str(event.event_version),
            },
        )
        return {"pubsub_message_id": message_id}


class OutboxPublisher:
    def __init__(
        self,
        pool: ConnectionPool,
        publisher: EventPublisher,
        interval: timedelta,
    ) -> None:
        self.pool = pool
        self.publisher = publisher
        self.interval = interval.total_seconds()

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                await self.publish_batch()
            except Exception:
                LOGGER.exception("outbox publish batch failed")
            try:
                await asyncio.wait_for(stop.wait(), timeout=self.interval)
            except TimeoutError:
                pass

    async def publish_batch(self) -> int:
        await asyncio.to_thread(self._recover_expired_claims)
        published = 0
        for _ in range(50):
            event = await asyncio.to_thread(self._claim)
            if event is None:
                return published
            envelope = {
                "event_id": str(event.event_id),
                "event_type": event.event_type,
                "event_version": event.event_version,
                "occurred_at": event.created_at.astimezone(UTC).isoformat(),
                "producer": "bantam-ledger",
                "correlation_id": str(event.aggregate_id),
                "causation_id": "",
                "payload": event.payload,
            }
            try:
                metadata = await self.publisher.publish(event, envelope)
            except Exception as error:
                await asyncio.to_thread(self._release, event.event_id, str(error))
                raise
            await asyncio.to_thread(self._mark_published, event.event_id)
            published += 1
            LOGGER.info(
                "outbox event published",
                extra={
                    "event_id": str(event.event_id),
                    "subject": event.event_type,
                    **metadata,
                },
            )
        return published

    def _recover_expired_claims(self) -> None:
        with self.pool.connection() as connection:
            connection.execute(
                """
                UPDATE outbox_events
                SET status = 'PENDING', claimed_at = NULL,
                    last_error = 'publisher claim expired before acknowledgement'
                WHERE status = 'PUBLISHING'
                  AND claimed_at < now() - interval '1 minute'
                """
            )

    def _claim(self) -> OutboxEvent | None:
        # SKIP LOCKED lets several publishers cooperate without publishing the
        # same row, while the expiry path recovers a crashed claimant.
        with self.pool.connection() as connection:
            with connection.transaction():
                row = connection.execute(
                    """
                    SELECT outbox_event_id, aggregate_id, event_type,
                           event_version, payload, created_at
                    FROM outbox_events
                    WHERE status = 'PENDING'
                    ORDER BY created_at
                    FOR UPDATE SKIP LOCKED
                    LIMIT 1
                    """
                ).fetchone()
                if not row:
                    return None
                connection.execute(
                    """
                    UPDATE outbox_events
                    SET status = 'PUBLISHING',
                        publish_attempts = publish_attempts + 1,
                        claimed_at = now()
                    WHERE outbox_event_id = %s
                    """,
                    (row["outbox_event_id"],),
                )
        return OutboxEvent(
            event_id=row["outbox_event_id"],
            aggregate_id=row["aggregate_id"],
            event_type=row["event_type"],
            event_version=row["event_version"],
            payload=row["payload"],
            created_at=row["created_at"],
        )

    def _release(self, event_id: UUID, error: str) -> None:
        with self.pool.connection() as connection:
            connection.execute(
                """
                UPDATE outbox_events
                SET status = 'PENDING', claimed_at = NULL, last_error = %s
                WHERE outbox_event_id = %s
                """,
                (error[:2000], event_id),
            )

    def _mark_published(self, event_id: UUID) -> None:
        with self.pool.connection() as connection:
            connection.execute(
                """
                UPDATE outbox_events
                SET status = 'PUBLISHED', published_at = now(),
                    claimed_at = NULL, last_error = NULL
                WHERE outbox_event_id = %s
                """,
                (event_id,),
            )
