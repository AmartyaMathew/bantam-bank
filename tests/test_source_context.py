"""Tests for the bounded source and OpenAPI snapshot boundary."""

from __future__ import annotations

from pathlib import Path

import pytest

from bantam.source_context import (
    MAX_CONTEXT_BYTES,
    SourceContextError,
    build_openapi_snapshot,
    build_source_context,
    describe_source_roots,
)


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def test_snapshot_uses_real_files_and_redacts_likely_secrets(tmp_path: Path) -> None:
    application = tmp_path / "application"
    terraform = tmp_path / "terraform"
    _write(
        application / "bantam" / "api.py",
        'PASSWORD = "never-send-this"\n'
        "def require_roles(*roles: str):\n"
        "    return roles\n",
    )
    _write(application / ".env", "TOKEN=also-never-send-this\n")
    _write(
        terraform / "runtime.tf",
        'resource "google_cloud_run_v2_service" "bank" {\n'
        '  ingress = "INGRESS_TRAFFIC_ALL"\n'
        "}\n",
    )
    _write(terraform / "terraform.tfvars", 'api_token = "not-source-code"\n')

    snapshot = build_source_context(str(application), str(terraform))

    assert snapshot.sha256
    assert snapshot.document["included_bytes"] <= MAX_CONTEXT_BYTES
    files = snapshot.document["files"]
    assert {(item["repository"], item["path"]) for item in files} == {
        ("application", "bantam/api.py"),
        ("terraform", "runtime.tf"),
    }
    rendered = str(files)
    assert "never-send-this" not in rendered
    assert "also-never-send-this" not in rendered
    assert "[REDACTED]" in rendered
    assert "google_cloud_run_v2_service" in rendered


def test_snapshot_requires_both_repository_kinds(tmp_path: Path) -> None:
    application = tmp_path / "application"
    terraform = tmp_path / "terraform"
    _write(application / "bantam" / "api.py", "def health():\n    return True\n")
    terraform.mkdir()

    with pytest.raises(SourceContextError, match="both application source"):
        build_source_context(str(application), str(terraform))

    status = describe_source_roots(str(application), str(terraform))
    assert status["application"]["ready"] is True
    assert status["terraform"]["ready"] is False
    assert status["ready"] is False


def test_openapi_snapshot_keeps_only_relevant_operations_and_schemas() -> None:
    document = {
        "openapi": "3.1.0",
        "info": {"title": "Bantam API", "version": "0.2.0", "description": "drop"},
        "paths": {
            "/v1/auth/login": {
                "post": {
                    "operationId": "login",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/LoginRequest"}
                            }
                        }
                    },
                    "responses": {"200": {"description": "Successful response"}},
                }
            },
            "/v1/admin/asvs/test-plans": {
                "post": {
                    "operationId": "generate",
                    "responses": {"201": {"description": "Created"}},
                }
            },
        },
        "components": {
            "schemas": {
                "LoginRequest": {
                    "type": "object",
                    "properties": {
                        "email": {"type": "string"},
                        "password": {"type": "string"},
                    },
                },
                "Unrelated": {"type": "object"},
            }
        },
    }

    snapshot = build_openapi_snapshot(document)

    assert set(snapshot.document["paths"]) == {"/v1/auth/login"}
    assert set(snapshot.document["components"]["schemas"]) == {"LoginRequest"}
    assert snapshot.document["info"] == {
        "title": "Bantam API",
        "version": "0.2.0",
    }
