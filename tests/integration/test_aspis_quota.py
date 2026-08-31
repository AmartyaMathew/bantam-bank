"""Transactional Aspis generation quota regressions."""

from __future__ import annotations

import os
from uuid import UUID, uuid4

import pytest
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from bantam.asvs_ai import ACCOUNT_DAILY_GENERATION_LIMIT, AsvsAiService
from bantam.errors import BantamError
from bantam.seed import ADMIN_USER_ID


DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL",
    "postgres://bantam:bantam@localhost:5433/bantam?sslmode=disable",
)
pytestmark = pytest.mark.integration


def test_account_daily_quota_survives_new_sessions() -> None:
    generation_ids: list[UUID] = []
    with ConnectionPool(
        conninfo=DATABASE_URL,
        min_size=1,
        max_size=1,
        kwargs={"autocommit": True, "row_factory": dict_row},
    ) as pool:
        service = AsvsAiService(
            pool,
            feature_enabled=False,
            api_key=None,
            target_commit="quota-regression",
            application_source_root="/not-mounted/application",
            terraform_source_root="/not-mounted/terraform",
        )
        try:
            for index in range(ACCOUNT_DAILY_GENERATION_LIMIT):
                generation_id = uuid4()
                generation_ids.append(generation_id)
                service._reserve(
                    generation_id=generation_id,
                    initiated_by=ADMIN_USER_ID,
                    session_jti=uuid4(),
                    prompt_sha256=f"{index:064x}",
                    provenance={"schema_version": "quota-test"},
                )

            with pytest.raises(BantamError) as caught:
                service._reserve(
                    generation_id=uuid4(),
                    initiated_by=ADMIN_USER_ID,
                    session_jti=uuid4(),
                    prompt_sha256="f" * 64,
                    provenance={"schema_version": "quota-test"},
                )

            assert caught.value.code == "ASVS_AI_ACCOUNT_DAILY_LIMIT"
            assert caught.value.status_code == 429
        finally:
            with pool.connection() as connection:
                connection.execute(
                    "DELETE FROM asvs_ai_generations WHERE generation_id = ANY(%s)",
                    (generation_ids,),
                )
