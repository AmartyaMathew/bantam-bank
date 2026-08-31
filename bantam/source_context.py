"""Bounded, secret-minimised source context for the ASVS model boundary.

The model receives excerpts from the code that is actually mounted in the
running platform.  File discovery is deterministic, symlinks and common secret
locations are ignored, likely credential literals are redacted, and strict
per-repository and aggregate byte limits keep the request inside the provider
prototype quota.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_CONTEXT_FILES = 12
MAX_CONTEXT_BYTES = 16_000
MAX_APPLICATION_BYTES = 10_000
MAX_TERRAFORM_BYTES = 6_000
MAX_FILE_EXCERPT_BYTES = 2_600
MAX_SOURCE_FILE_BYTES = 1_048_576
MAX_OPENAPI_BYTES = 12_000

_APPLICATION_FILE_LIMIT = 7
_TERRAFORM_FILE_LIMIT = 5
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete"})
_OPENAPI_PATHS = frozenset(
    {
        "/v1/auth/login",
        "/v1/auth/logout",
        "/v1/me",
        "/v1/admin/customers",
        "/v1/accounts/{account_id}/transactions",
        "/v1/transfers",
    }
)
_EXCLUDED_COMPONENTS = frozenset(
    {
        ".git",
        ".terraform",
        ".venv",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "htmlcov",
        "node_modules",
        "vendor",
    }
)
_EXCLUDED_NAMES = frozenset(
    {
        ".env",
        ".env.local",
        "credentials.json",
        "service-account.json",
        "terraform.tfstate",
        "terraform.tfstate.backup",
    }
)
_APPLICATION_ROOT_FILES = frozenset({"Dockerfile", "pyproject.toml", "README.md"})
_APPLICATION_SUFFIXES = frozenset(
    {".json", ".md", ".py", ".sql", ".toml", ".ts", ".tsx", ".yaml", ".yml"}
)
_SOURCE_KEYWORDS = (
    "authenticated",
    "authorization",
    "csrf",
    "require_roles",
    "@app.",
    "session",
    "admin",
    "account",
    "transfer",
    "asvs",
)
_TERRAFORM_KEYWORDS = (
    "google_cloud_run",
    "service_account",
    "secret_manager",
    "ingress",
    "iam",
    "vpc",
    "firewall",
    "cloud_sql",
    "database",
    "ssl",
)
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?P<prefix>\b(?:password|passwd|secret|token|api[_-]?key|"
    r"client[_-]?secret|private[_-]?key)\b[^:=\n]{0,48}(?:=|:)\s*)"
    r"(?P<value>.+)$"
)
_CREDENTIAL_URL = re.compile(r"(?i)(://)[^/@\s:]+:[^/@\s]+@")
_BEARER_TOKEN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")
_KNOWN_TOKEN = re.compile(
    r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})\b"
)
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_PEM = re.compile(
    r"-----BEGIN [^-]+-----.*?-----END [^-]+-----",
    flags=re.DOTALL,
)


class SourceContextError(ValueError):
    """Raised when a safe, complete source snapshot cannot be constructed."""


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    document: dict[str, Any]
    sha256: str


def canonical_sha(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalise_root(raw: str, label: str) -> Path:
    try:
        root = Path(raw).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise SourceContextError(f"{label} source root is unavailable") from error
    if not root.is_dir():
        raise SourceContextError(f"{label} source root is not a directory")
    return root


def _excluded(relative: Path) -> bool:
    lowered = {part.casefold() for part in relative.parts}
    return bool(lowered & _EXCLUDED_COMPONENTS) or relative.name.casefold() in {
        name.casefold() for name in _EXCLUDED_NAMES
    }


def _allowed(relative: Path, repository: str) -> bool:
    if _excluded(relative):
        return False
    if repository == "terraform":
        return relative.name.endswith(".tf") or relative.name.endswith(".tf.json")
    if len(relative.parts) == 1 and relative.name in _APPLICATION_ROOT_FILES:
        return True
    if not relative.parts or relative.parts[0] not in {
        "bantam",
        "migrations",
        "security",
        "web",
    }:
        return False
    return relative.suffix.casefold() in _APPLICATION_SUFFIXES


def _candidate_paths(root: Path, repository: str) -> list[Path]:
    candidates: list[Path] = []
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(
            directory
            for directory in directories
            if directory.casefold() not in _EXCLUDED_COMPONENTS
            and not (current_path / directory).is_symlink()
        )
        for filename in sorted(filenames):
            path = current_path / filename
            if path.is_symlink() or not path.is_file():
                continue
            try:
                relative = path.relative_to(root)
            except ValueError:
                continue
            if _allowed(relative, repository):
                candidates.append(path)
    return sorted(
        candidates,
        key=lambda path: (
            _priority(path.relative_to(root), repository),
            path.as_posix(),
        ),
    )


def _priority(relative: Path, repository: str) -> int:
    path = relative.as_posix()
    if repository == "terraform":
        ordered = {
            "runtime.tf": 0,
            "iam.tf": 1,
            "secrets.tf": 2,
            "network.tf": 3,
            "database.tf": 4,
            "migrations.tf": 5,
            "variables.tf": 6,
            "locals.tf": 7,
        }
        return ordered.get(relative.name, 20)
    ordered = {
        "bantam/api.py": 0,
        "bantam/auth.py": 1,
        "bantam/security.py": 2,
        "bantam/schemas.py": 3,
        "bantam/asvs.py": 4,
        "bantam/config.py": 5,
        "bantam/domain.py": 6,
    }
    if path in ordered:
        return ordered[path]
    if path.startswith("security/aspis/asvs/"):
        return 7
    if path.startswith("migrations/"):
        return 8
    if path.startswith("bantam/"):
        return 10
    return 30


def _redact(text: str) -> str:
    text = _PEM.sub("[REDACTED PEM MATERIAL]", text)
    redacted: list[str] = []
    for line in text.splitlines():
        line = _CREDENTIAL_URL.sub(r"\1[REDACTED]@", line)
        line = _BEARER_TOKEN.sub("Bearer [REDACTED]", line)
        line = _KNOWN_TOKEN.sub("[REDACTED TOKEN]", line)
        line = _JWT.sub("[REDACTED JWT]", line)
        match = _SENSITIVE_ASSIGNMENT.search(line)
        if match:
            line = line[: match.start("value")] + "[REDACTED]"
        redacted.append(line)
    return "\n".join(redacted)


def redact_sensitive_text(text: str) -> str:
    """Return the shared deterministic secret-minimised representation.

    Repository knowledge graphs use the same model-boundary redaction as the
    ASVS source-context feature.  Keeping this public seam here prevents two
    subtly different credential filters from evolving in parallel.
    """

    return _redact(text)


def _bounded_text(value: str, limit: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    marker = "\n...[excerpt truncated]"
    available = max(0, limit - len(marker.encode("utf-8")))
    return encoded[:available].decode("utf-8", errors="ignore") + marker


def _excerpt(text: str, repository: str, limit: int) -> tuple[str, bool]:
    lines = text.splitlines()
    numbered = "\n".join(f"{index + 1:04d}: {line}" for index, line in enumerate(lines))
    if len(numbered.encode("utf-8")) <= limit:
        return numbered, False

    keywords = _TERRAFORM_KEYWORDS if repository == "terraform" else _SOURCE_KEYWORDS
    hits = [
        index
        for index, line in enumerate(lines)
        if any(keyword in line.casefold() for keyword in keywords)
    ]
    if not hits:
        hits = [0]

    selected: set[int] = set()
    for hit in hits:
        selected.update(range(max(0, hit - 3), min(len(lines), hit + 5)))
        candidate = "\n".join(
            f"{index + 1:04d}: {lines[index]}" for index in sorted(selected)
        )
        if len(candidate.encode("utf-8")) >= limit:
            break
    rendered = "\n".join(
        f"{index + 1:04d}: {lines[index]}" for index in sorted(selected)
    )
    return _bounded_text(rendered, limit), True


def _read_source_file(
    root: Path,
    path: Path,
    repository: str,
    limit: int,
) -> dict[str, Any] | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if len(raw) > MAX_SOURCE_FILE_BYTES or b"\x00" in raw:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    excerpt, truncated = _excerpt(_redact(text), repository, limit)
    return {
        "repository": repository,
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "source_bytes": len(raw),
        "included_bytes": len(excerpt.encode("utf-8")),
        "truncated": truncated,
        "excerpt": excerpt,
    }


def _collect(
    root: Path,
    repository: str,
    *,
    file_limit: int,
    byte_limit: int,
) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    remaining = byte_limit
    for path in _candidate_paths(root, repository):
        if len(selected) >= file_limit or remaining < 256:
            break
        document = _read_source_file(
            root,
            path,
            repository,
            min(MAX_FILE_EXCERPT_BYTES, remaining),
        )
        if document is None or document["included_bytes"] == 0:
            continue
        selected.append(document)
        remaining -= int(document["included_bytes"])
    return selected


def describe_source_roots(
    application_root: str,
    terraform_root: str,
) -> dict[str, Any]:
    status: dict[str, Any] = {}
    for repository, raw in (
        ("application", application_root),
        ("terraform", terraform_root),
    ):
        try:
            root = _normalise_root(raw, repository)
            count = len(_candidate_paths(root, repository))
            status[repository] = {"ready": count > 0, "eligible_files": count}
        except SourceContextError:
            status[repository] = {"ready": False, "eligible_files": 0}
    status["ready"] = bool(
        status["application"]["ready"] and status["terraform"]["ready"]
    )
    return status


def build_source_context(
    application_root: str,
    terraform_root: str,
) -> SourceSnapshot:
    application = _normalise_root(application_root, "application")
    terraform = _normalise_root(terraform_root, "terraform")
    files = [
        *_collect(
            application,
            "application",
            file_limit=_APPLICATION_FILE_LIMIT,
            byte_limit=MAX_APPLICATION_BYTES,
        ),
        *_collect(
            terraform,
            "terraform",
            file_limit=_TERRAFORM_FILE_LIMIT,
            byte_limit=MAX_TERRAFORM_BYTES,
        ),
    ]
    repositories = {item["repository"] for item in files}
    if repositories != {"application", "terraform"}:
        raise SourceContextError(
            "both application source and Terraform source are required"
        )
    included_bytes = sum(int(item["included_bytes"]) for item in files)
    if len(files) > MAX_CONTEXT_FILES or included_bytes > MAX_CONTEXT_BYTES:
        raise SourceContextError("source context exceeded its safe aggregate limit")
    document = {
        "schema_version": "1.0",
        "limits": {
            "max_files": MAX_CONTEXT_FILES,
            "max_bytes": MAX_CONTEXT_BYTES,
            "max_file_excerpt_bytes": MAX_FILE_EXCERPT_BYTES,
        },
        "included_files": len(files),
        "included_bytes": included_bytes,
        "files": files,
    }
    return SourceSnapshot(document=document, sha256=canonical_sha(document))


def _schema_references(value: object) -> set[str]:
    references: set[str] = set()
    if isinstance(value, dict):
        reference = value.get("$ref")
        prefix = "#/components/schemas/"
        if isinstance(reference, str) and reference.startswith(prefix):
            references.add(reference.removeprefix(prefix))
        for nested in value.values():
            references.update(_schema_references(nested))
    elif isinstance(value, list):
        for nested in value:
            references.update(_schema_references(nested))
    return references


def build_openapi_snapshot(document: dict[str, Any]) -> SourceSnapshot:
    paths: dict[str, Any] = {}
    source_paths = document.get("paths")
    source_paths = source_paths if isinstance(source_paths, dict) else {}
    for path in sorted(_OPENAPI_PATHS):
        path_item = source_paths.get(path)
        if not isinstance(path_item, dict):
            continue
        operations = {
            method: {
                key: value
                for key, value in operation.items()
                if key
                in {
                    "operationId",
                    "parameters",
                    "requestBody",
                    "responses",
                    "security",
                    "summary",
                }
            }
            for method, operation in path_item.items()
            if method in _HTTP_METHODS and isinstance(operation, dict)
        }
        if operations:
            paths[path] = operations

    source_components = document.get("components")
    source_components = source_components if isinstance(source_components, dict) else {}
    source_schemas = source_components.get("schemas")
    source_schemas = source_schemas if isinstance(source_schemas, dict) else {}
    required = _schema_references(paths)
    schemas: dict[str, Any] = {}
    pending = sorted(required)
    while pending:
        name = pending.pop(0)
        if name in schemas:
            continue
        schema = source_schemas.get(name)
        if not isinstance(schema, dict):
            continue
        schemas[name] = schema
        pending.extend(sorted(_schema_references(schema) - schemas.keys()))

    info = document.get("info")
    info = info if isinstance(info, dict) else {}
    snapshot = {
        "openapi": document.get("openapi"),
        "info": {
            key: info[key]
            for key in ("title", "version")
            if key in info and isinstance(info[key], str)
        },
        "paths": paths,
        "components": {"schemas": schemas},
    }
    if not paths:
        raise SourceContextError("the running OpenAPI contract has no ASVS operations")
    encoded = json.dumps(
        snapshot,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    if len(encoded) > MAX_OPENAPI_BYTES:
        raise SourceContextError("the OpenAPI snapshot exceeded its safe size limit")
    return SourceSnapshot(document=snapshot, sha256=canonical_sha(snapshot))
