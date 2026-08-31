"""Durable event consumers for risk and customer notification projections."""

from __future__ import annotations

import asyncio
import json
import logging
from uuid import UUID, uuid4

from nats.aio.msg import Msg
from nats.errors import TimeoutError as NATSTimeoutError
from nats.js import JetStreamContext
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from bantam import audit
from bantam.events import STREAM_NAME
from bantam.money import format_minor
from bantam.pubsub import PubSubClient, PubSubMessage


LOGGER = logging.getLogger(__name__)
TRANSFER_SUBJECT = "payment.transfer_posted.v1"


def decode_transfer_data(data: bytes) -> tuple[UUID, dict[str, object]]:
    envelope = json.loads(data)
    return UUID(envelope["event_id"]), envelope["payload"]


def decode_transfer(message: Msg) -> tuple[UUID, dict[str, object]]:
    return decode_transfer_data(message.data)


def create_risk_alert(
    pool: ConnectionPool, threshold: int, payload: dict[str, object]
) -> None:
    amount_minor = int(payload["amount_minor"])
    if amount_minor <= threshold:
        return
    transaction_id = UUID(str(payload["transaction_id"]))
    source_account_id = UUID(str(payload["source_account_id"]))
    destination_account_id = UUID(str(payload["destination_account_id"]))

    with pool.connection() as connection:
        customer = connection.execute(
            """
            SELECT COALESCE(source.customer_id, destination.customer_id)
                AS customer_id
            FROM bank_accounts source
            JOIN bank_accounts destination
              ON destination.account_id = %s
            WHERE source.account_id = %s
            """,
            (destination_account_id, source_account_id),
        ).fetchone()
        with connection.transaction():
            alert_id = uuid4()
            created = connection.execute(
                """
                INSERT INTO risk_alerts (
                    risk_alert_id, transaction_id, customer_id, rule_id,
                    severity, explanation
                ) VALUES (%s,%s,%s,'HIGH_VALUE_TRANSFER','HIGH',%s)
                ON CONFLICT (transaction_id, rule_id) DO NOTHING
                RETURNING risk_alert_id
                """,
                (
                    alert_id,
                    transaction_id,
                    customer["customer_id"] if customer else None,
                    (
                        f"Transfer amount {amount_minor} {payload['currency']} "
                        f"minor units exceeded threshold {threshold}"
                    ),
                ),
            ).fetchone()
            if not created:
                return
            connection.execute(
                """
                INSERT INTO outbox_events (
                    outbox_event_id, aggregate_type, aggregate_id,
                    event_type, event_version, payload
                ) VALUES (%s,'risk_alert',%s,'risk.transaction_flagged.v1',1,%s)
                """,
                (
                    uuid4(),
                    alert_id,
                    Jsonb(
                        {
                            "risk_alert_id": str(alert_id),
                            "transaction_id": str(transaction_id),
                            "rule_id": "HIGH_VALUE_TRANSFER",
                            "severity": "HIGH",
                        }
                    ),
                ),
            )
            audit.record(
                connection,
                actor_type="SERVICE",
                actor_id="risk-worker",
                action="RISK_ALERT_CREATED",
                resource_type="risk_alert",
                resource_id=str(alert_id),
                request_id=uuid4(),
                correlation_id=transaction_id,
                metadata={
                    "rule_id": "HIGH_VALUE_TRANSFER",
                    "amount_minor": amount_minor,
                },
            )


def create_notifications(
    pool: ConnectionPool, event_id: UUID, payload: dict[str, object]
) -> None:
    source_account_id = UUID(str(payload["source_account_id"]))
    destination_account_id = UUID(str(payload["destination_account_id"]))
    amount_minor = int(payload["amount_minor"])
    currency = str(payload["currency"])

    with pool.connection() as connection:
        recipients = connection.execute(
            """
            SELECT account_id, customer_id FROM bank_accounts
            WHERE (account_id = %s OR account_id = %s)
              AND customer_id IS NOT NULL
            """,
            (source_account_id, destination_account_id),
        ).fetchall()
        for recipient in recipients:
            sent = recipient["account_id"] == source_account_id
            direction = "SENT" if sent else "RECEIVED"
            subject = "Transfer sent" if sent else "Transfer received"
            verb = "sent" if sent else "received"
            body = (
                f"You {verb} {format_minor(amount_minor, currency)} "
                "in a fake-money Bantam transfer."
            )
            connection.execute(
                """
                INSERT INTO notifications (
                    notification_id, customer_id, event_id, account_id,
                    direction, notification_type, subject, body
                ) VALUES (%s,%s,%s,%s,%s,'TRANSFER_POSTED',%s,%s)
                ON CONFLICT (customer_id, event_id, account_id, direction)
                DO NOTHING
                """,
                (
                    uuid4(),
                    recipient["customer_id"],
                    event_id,
                    recipient["account_id"],
                    direction,
                    subject,
                    body,
                ),
            )


class PullWorker:
    durable: str

    def __init__(self, pool: ConnectionPool, jetstream: JetStreamContext) -> None:
        self.pool = pool
        self.jetstream = jetstream

    async def run(self, stop: asyncio.Event) -> None:
        subscription = await self.jetstream.pull_subscribe(
            TRANSFER_SUBJECT,
            durable=self.durable,
            stream=STREAM_NAME,
        )
        while not stop.is_set():
            try:
                messages = await subscription.fetch(batch=10, timeout=1)
            except (NATSTimeoutError, asyncio.TimeoutError):
                # Empty JetStream pull polls are normal. nats-py can raise its
                # own timeout type or the stdlib asyncio timeout depending on
                # the fetch path, so both must keep the worker alive.
                continue
            for message in messages:
                try:
                    await asyncio.to_thread(self.handle, message)
                except Exception:
                    LOGGER.exception(
                        "worker event failed", extra={"worker": self.durable}
                    )
                    await message.nak()
                else:
                    await message.ack()

    def handle(self, message: Msg) -> None:
        raise NotImplementedError


class PubSubPullWorker:
    durable: str

    def __init__(
        self,
        pool: ConnectionPool,
        client: PubSubClient,
        subscription: str,
    ) -> None:
        self.pool = pool
        self.client = client
        self.subscription = subscription

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            try:
                processed = await self.process_batch()
            except Exception:
                LOGGER.exception(
                    "pubsub worker batch failed", extra={"worker": self.durable}
                )
                processed = 0
            if processed == 0:
                try:
                    await asyncio.wait_for(stop.wait(), timeout=1)
                except TimeoutError:
                    pass

    async def process_batch(self) -> int:
        messages = await asyncio.to_thread(self.client.pull, self.subscription, 10)
        for message in messages:
            try:
                await asyncio.to_thread(self.handle_message, message)
            except Exception:
                LOGGER.exception(
                    "pubsub worker event failed",
                    extra={
                        "worker": self.durable,
                        "pubsub_message_id": message.message_id,
                    },
                )
            else:
                await asyncio.to_thread(
                    self.client.acknowledge, self.subscription, [message.ack_id]
                )
        return len(messages)

    def handle_message(self, message: PubSubMessage) -> None:
        raise NotImplementedError


class RiskWorker(PullWorker):
    durable = "bantam-risk-worker"

    def __init__(
        self,
        pool: ConnectionPool,
        jetstream: JetStreamContext,
        threshold: int,
    ) -> None:
        super().__init__(pool, jetstream)
        self.threshold = threshold

    def handle(self, message: Msg) -> None:
        _, payload = decode_transfer(message)
        create_risk_alert(self.pool, self.threshold, payload)


class PubSubRiskWorker(PubSubPullWorker):
    durable = "bantam-risk-worker"

    def __init__(
        self,
        pool: ConnectionPool,
        client: PubSubClient,
        subscription: str,
        threshold: int,
    ) -> None:
        super().__init__(pool, client, subscription)
        self.threshold = threshold

    def handle_message(self, message: PubSubMessage) -> None:
        _, payload = decode_transfer_data(message.data)
        create_risk_alert(self.pool, self.threshold, payload)


class NotificationWorker(PullWorker):
    durable = "bantam-notification-worker"

    def handle(self, message: Msg) -> None:
        event_id, payload = decode_transfer(message)
        create_notifications(self.pool, event_id, payload)


class PubSubNotificationWorker(PubSubPullWorker):
    durable = "bantam-notification-worker"

    def handle_message(self, message: PubSubMessage) -> None:
        event_id, payload = decode_transfer_data(message.data)
        create_notifications(self.pool, event_id, payload)
