"""Append-only structured audit-event writer used inside caller transactions."""

from __future__ import annotations

from collections.abc import Mapping
from uuid import UUID, uuid4

from psycopg import Connection
from psycopg.types.json import Jsonb


def record(
    connection: Connection,
    *,
    actor_type: str,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str,
    request_id: UUID | None = None,
    correlation_id: UUID | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    metadata: Mapping[str, object] | None = None,
) -> None:
    """Append evidence using the caller's transaction and correlation context."""

    request_id = request_id or uuid4()
    correlation_id = correlation_id or request_id
    connection.execute(
        """
        INSERT INTO audit_events (
            audit_event_id, actor_type, actor_id, action, resource_type,
            resource_id, request_id, correlation_id, ip_address,
            user_agent, metadata
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """,
        (
            uuid4(),
            actor_type,
            actor_id,
            action,
            resource_type,
            resource_id,
            request_id,
            correlation_id,
            ip_address,
            user_agent,
            Jsonb(dict(metadata or {})),
        ),
    )
