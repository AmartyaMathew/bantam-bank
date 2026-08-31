"""PostgreSQL pool lifecycle and serialized, transactional SQL migrations."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool


LOGGER = logging.getLogger(__name__)
MIGRATIONS = Path(os.getenv("MIGRATIONS_DIR", Path.cwd() / "migrations")).resolve()


class Database:
    def __init__(
        self,
        database_url: str,
        *,
        min_size: int = 1,
        max_size: int = 8,
    ) -> None:
        if not 0 <= min_size <= max_size or max_size == 0:
            raise ValueError("database pool sizes must satisfy 0 <= min <= max")
        self.pool = ConnectionPool(
            conninfo=database_url,
            min_size=min_size,
            max_size=max_size,
            timeout=10,
            kwargs={"autocommit": True, "row_factory": dict_row},
            open=False,
        )

    def open(self, *, migrate: bool = False) -> None:
        self.pool.open(wait=True)
        if migrate:
            self.apply_migrations()
        from bantam.auth import set_revocation_pool

        set_revocation_pool(self.pool)

    def close(self) -> None:
        from bantam.auth import set_revocation_pool

        set_revocation_pool(None)
        self.pool.close()

    def ping(self) -> None:
        with self.pool.connection() as connection:
            connection.execute("SELECT 1")

    def apply_migrations(self, *, runtime_grantee: str | None = None) -> None:
        # The session-level advisory lock prevents two starting replicas from
        # applying the same migration concurrently.
        migration_files = sorted(MIGRATIONS.glob("*.sql"))
        if not migration_files:
            raise RuntimeError(f"no migration files found in {MIGRATIONS}")
        with self.pool.connection() as connection:
            connection.execute(
                "SELECT pg_advisory_lock(hashtext('bantam_schema_migrations'))"
            )
            try:
                connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS schema_migrations (
                        version TEXT PRIMARY KEY,
                        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    )
                    """
                )
                for path in migration_files:
                    applied = connection.execute(
                        "SELECT 1 FROM schema_migrations WHERE version = %s",
                        (path.name,),
                    ).fetchone()
                    if applied:
                        continue
                    with connection.transaction():
                        with psycopg.ClientCursor(connection) as cursor:
                            cursor.execute(path.read_text(encoding="utf-8"))
                        connection.execute(
                            "INSERT INTO schema_migrations (version) VALUES (%s)",
                            (path.name,),
                        )
                    LOGGER.info(
                        "database migration applied", extra={"version": path.name}
                    )
                if runtime_grantee is not None:
                    self.grant_runtime_privileges(connection, runtime_grantee)
            finally:
                connection.execute(
                    "SELECT pg_advisory_unlock(hashtext('bantam_schema_migrations'))"
                )

    def grant_runtime_privileges(
        self, connection: psycopg.Connection, runtime_grantee: str
    ) -> None:
        """Grant normal app DML privileges after a privileged migration run.

        GCP production runs migrations under a short-lived Cloud Run Job identity
        while the API and workers use a separate long-lived runtime identity.
        Objects created by the migration identity are not automatically usable
        by the runtime identity, so the migration command can grant the runtime
        role the narrow privileges needed for normal application traffic.
        """

        grantee = runtime_grantee.strip()
        if not grantee or "\x00" in grantee:
            raise ValueError("runtime migration grantee must be a non-empty role")

        quoted_grantee = sql.Identifier(grantee)
        statements = (
            sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(quoted_grantee),
            sql.SQL(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES "
                "IN SCHEMA public TO {}"
            ).format(quoted_grantee),
            sql.SQL(
                "GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO {}"
            ).format(quoted_grantee),
            sql.SQL("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {}").format(
                quoted_grantee
            ),
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}"
            ).format(quoted_grantee),
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                "GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO {}"
            ).format(quoted_grantee),
            sql.SQL(
                "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
                "GRANT EXECUTE ON FUNCTIONS TO {}"
            ).format(quoted_grantee),
        )
        for statement in statements:
            connection.execute(statement)
        LOGGER.info(
            "database runtime privileges granted",
            extra={"runtime_grantee": grantee},
        )
