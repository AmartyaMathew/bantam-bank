"""Command-line entry point for the API, workers, and deterministic demo seed."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal

import uvicorn

from bantam.api import create_app
from bantam.cloud_run import run_cloud_job
from bantam.config import Settings
from bantam.database import Database
from bantam.events import (
    NatsEventPublisher,
    OutboxPublisher,
    PubSubEventPublisher,
    connect,
)
from bantam.ledger import LedgerService
from bantam.pubsub import PubSubClient
from bantam.sca import SCAService
from bantam.seed import bootstrap_aspis_admin, bootstrap_bank_admin, seed
from bantam.workers import (
    NotificationWorker,
    PubSubNotificationWorker,
    PubSubRiskWorker,
    RiskWorker,
)


def configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def services(
    settings: Settings, *, migrate: bool | None = None
) -> tuple[Database, LedgerService]:
    database = Database(
        settings.database_url,
        min_size=settings.database_pool_min_size,
        max_size=settings.database_pool_max_size,
    )
    database.open(
        migrate=settings.run_migrations_on_startup if migrate is None else migrate
    )
    sca = SCAService(
        settings.sca_secret,
        settings.sca_ttl,
        settings.sca_threshold_minor,
        settings.demo_mode,
    )
    return database, LedgerService(database.pool, sca)


def run_migrations(settings: Settings) -> None:
    database = Database(
        settings.database_url,
        min_size=settings.database_pool_min_size,
        max_size=settings.database_pool_max_size,
    )
    database.open(migrate=False)
    try:
        database.apply_migrations(runtime_grantee=settings.migration_runtime_grantee)
    finally:
        database.close()


def install_signal_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(signum, stop.set)
        except NotImplementedError:
            pass


def pubsub_client(settings: Settings) -> PubSubClient:
    return PubSubClient(settings.pubsub_project_id or "")


async def run_event_service(kind: str, settings: Settings) -> None:
    database, _ = services(settings)
    connection = None
    stop = asyncio.Event()
    install_signal_handlers(stop)
    try:
        if settings.event_bus == "pubsub":
            client = pubsub_client(settings)
            if kind == "outbox-publisher":
                service = OutboxPublisher(
                    database.pool,
                    PubSubEventPublisher(client, settings.pubsub_topic or ""),
                    settings.outbox_poll_interval,
                )
            elif kind == "risk-worker":
                service = PubSubRiskWorker(
                    database.pool,
                    client,
                    settings.pubsub_risk_subscription or "",
                    settings.risk_threshold_minor,
                )
            else:
                service = PubSubNotificationWorker(
                    database.pool,
                    client,
                    settings.pubsub_notification_subscription or "",
                )
            await service.run(stop)
            return

        connection, jetstream = await connect(settings.nats_url, f"bantam-{kind}")
        if kind == "outbox-publisher":
            service = OutboxPublisher(
                database.pool,
                NatsEventPublisher(jetstream),
                settings.outbox_poll_interval,
            )
        elif kind == "risk-worker":
            service = RiskWorker(
                database.pool, jetstream, settings.risk_threshold_minor
            )
        else:
            service = NotificationWorker(database.pool, jetstream)
        await service.run(stop)
    finally:
        if connection is not None:
            await connection.drain()
        database.close()


async def run_event_batch(kind: str, settings: Settings) -> None:
    if settings.event_bus != "pubsub":
        raise SystemExit("one-shot event jobs require EVENT_BUS=pubsub")
    database, _ = services(settings)
    try:
        client = pubsub_client(settings)
        if kind == "outbox-publisher-once":
            service = OutboxPublisher(
                database.pool,
                PubSubEventPublisher(client, settings.pubsub_topic or ""),
                settings.outbox_poll_interval,
            )
            published = await service.publish_batch()
            logging.info(
                "outbox one-shot batch complete", extra={"published": published}
            )
            return
        if kind == "risk-worker-once":
            service = PubSubRiskWorker(
                database.pool,
                client,
                settings.pubsub_risk_subscription or "",
                settings.risk_threshold_minor,
            )
        else:
            service = PubSubNotificationWorker(
                database.pool,
                client,
                settings.pubsub_notification_subscription or "",
            )
        processed = await service.process_batch()
        logging.info("worker one-shot batch complete", extra={"processed": processed})
    finally:
        database.close()


SERVICES = (
    "api",
    "outbox-publisher",
    "risk-worker",
    "notification-worker",
    "outbox-publisher-once",
    "risk-worker-once",
    "notification-worker-once",
    "migrate",
    "seed",
    "bootstrap-bank-admin",
    "bootstrap-aspis-admin",
)

CLOUD_RUN_JOB_SERVICES = frozenset(
    {
        "migrate",
        "bootstrap-bank-admin",
        "bootstrap-aspis-admin",
        "outbox-publisher-once",
        "risk-worker-once",
        "notification-worker-once",
    }
)


def run_admin_bootstrap(service: str, settings: Settings) -> None:
    if service == "bootstrap-bank-admin":
        email_name = "BANK_ADMIN_BOOTSTRAP_EMAIL"
        credential_name = "BANK_ADMIN_BOOTSTRAP_PASSWORD"
        bootstrap = bootstrap_bank_admin
    else:
        email_name = "ASPIS_ADMIN_BOOTSTRAP_EMAIL"
        credential_name = "ASPIS_ADMIN_BOOTSTRAP_PASSWORD"
        bootstrap = bootstrap_aspis_admin

    email = os.getenv(email_name, "").strip()
    password = os.getenv(credential_name, "")
    if not email or not password:
        raise SystemExit(f"{email_name} and {credential_name} are required")

    database, _ = services(settings)
    try:
        bootstrap(database.pool, email=email, password=password)
    finally:
        database.close()


def run_service(service: str) -> None:
    settings = Settings.from_env()

    if service == "migrate":
        run_migrations(settings)
        return

    if service in {"bootstrap-bank-admin", "bootstrap-aspis-admin"}:
        run_admin_bootstrap(service, settings)
        return

    if service == "api":
        host, port = settings.uvicorn_address()
        # Proxy headers remain disabled in Uvicorn.  The application resolves
        # forwarding metadata itself and only from explicitly trusted networks.
        uvicorn.run(
            create_app(settings=settings),
            host=host,
            port=port,
            log_level="info",
            proxy_headers=False,
            server_header=False,
        )
        return
    if service == "seed":
        if not settings.allow_demo_seed:
            raise SystemExit(
                "Refusing to run the public demo seed outside local development. "
                "Set APP_ENV=development and ALLOW_DEMO_SEED=true for "
                "Codespaces/Compose seed data."
            )
        database, ledger = services(settings)
        try:
            seed(database.pool, ledger)
        finally:
            database.close()
        return
    if service.endswith("-once"):
        asyncio.run(run_event_batch(service, settings))
        return
    asyncio.run(run_event_service(service, settings))


def main() -> None:
    parser = argparse.ArgumentParser(prog="bantam")
    parser.add_argument("service", choices=SERVICES)
    arguments = parser.parse_args()
    configure_logging()

    if arguments.service in CLOUD_RUN_JOB_SERVICES:
        run_cloud_job(lambda: run_service(arguments.service))
        return
    run_service(arguments.service)


if __name__ == "__main__":
    main()
