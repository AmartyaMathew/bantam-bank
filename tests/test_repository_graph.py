"""Repository graph determinism, language coverage, and model boundaries."""

from __future__ import annotations

import base64
import json

import pytest

from bantam.errors import BantamError
from bantam.repository_graph import (
    ModelOutput,
    GitHubRepositoryClient,
    RepositoryFile,
    RepositorySnapshot,
    RepositorySource,
    RepositoryWorkflowValidator,
    build_repository_catalog,
    build_repository_model_request,
    generate_repository_narrative,
)


class _JsonResponse:
    def __init__(self, document: dict[str, object]) -> None:
        self.raw = json.dumps(document).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def read(self, limit: int) -> bytes:
        return self.raw[:limit]


class _GitHubOpener:
    def __init__(self, source: bytes) -> None:
        self.source = source
        self.authorization: list[str | None] = []

    def open(self, request, timeout: int):
        assert timeout == 30
        self.authorization.append(request.get_header("Authorization"))
        url = request.full_url
        if "/commits/main" in url:
            return _JsonResponse(
                {"sha": "a" * 40, "commit": {"tree": {"sha": "b" * 40}}}
            )
        if "/git/trees/" in url:
            return _JsonResponse(
                {
                    "truncated": False,
                    "tree": [
                        {
                            "path": "app.py",
                            "type": "blob",
                            "sha": "c" * 40,
                            "size": len(self.source),
                        }
                    ],
                }
            )
        encoded = base64.b64encode(self.source).decode()
        wrapped = "\n".join(
            encoded[index : index + 12] for index in range(0, len(encoded), 12)
        )
        return _JsonResponse(
            {"sha": "c" * 40, "encoding": "base64", "content": wrapped}
        )


def _snapshot(*files: tuple[str, str], language: str = "auto") -> RepositorySnapshot:
    source = RepositorySource(
        repository="example/project",
        ref="main",
        root_path="",
        language=language,
    )
    repository_files = tuple(
        RepositoryFile(path=path, sha=f"{index:040x}", content=content)
        for index, (path, content) in enumerate(files, start=1)
    )
    python = any(path.endswith(".py") for path, _ in files)
    terraform = any(path.endswith((".tf", ".tf.json")) for path, _ in files)
    detected = "mixed" if python and terraform else "python" if python else "terraform"
    return RepositorySnapshot(
        source=source,
        resolved_commit="a" * 40,
        files=repository_files,
        detected_language=detected,
        source_sha256="b" * 64,
    )


def test_github_reader_pins_commit_and_decodes_wrapped_blob_content() -> None:
    source = b"def main() -> None:\n    return None\n"
    opener = _GitHubOpener(source)
    client = GitHubRepositoryClient("private-read-token")
    client.opener = opener

    snapshot = client.fetch(
        RepositorySource(
            repository="example/project",
            ref="main",
            root_path="",
            language="python",
        )
    )

    assert snapshot.resolved_commit == "a" * 40
    assert snapshot.files[0].content.encode() == source
    assert snapshot.detected_language == "python"
    assert opener.authorization == ["Bearer private-read-token"] * 3


def test_python_repository_graph_extracts_routes_signatures_checks_and_sql() -> None:
    snapshot = _snapshot(
        (
            "app.py",
            """from fastapi import FastAPI

app = FastAPI()

def persist_user(connection, email: str) -> None:
    connection.execute("INSERT INTO users (email) VALUES (%s)", (email,))

@app.post("/users")
def register_user(email: str, connection):
    if not email:
        raise ValueError("email required")
    persist_user(connection, email)
    return {"email": email}
""",
        ),
        (
            "docs/users.md",
            "# User registration\n\n`POST /users` is handled by `register_user`.\n",
        ),
        language="python",
    )

    first = build_repository_catalog(snapshot)
    second = build_repository_catalog(snapshot)

    assert first == second
    flow = next(flow for flow in first["default_flows"] if flow["route"])
    selected = {
        node["id"]: node for node in first["nodes"] if node["id"] in flow["node_ids"]
    }
    assert flow["route"] == {"method": "POST", "path": "/users"}
    assert any(
        node.get("signature", "").startswith("def register_user(")
        for node in selected.values()
    )
    assert any(node["kind"] == "check" for node in selected.values())
    assert any(
        node["kind"] == "effect" and node.get("tables") == ["users"]
        for node in selected.values()
    )
    assert any(node["kind"] == "documentation" for node in first["nodes"])


def test_terraform_repository_graph_extracts_blocks_dependencies_and_checks() -> None:
    snapshot = _snapshot(
        (
            "variables.tf",
            """variable "project_id" {
  type = string
  validation {
    condition = length(var.project_id) > 4
    error_message = "project_id is too short"
  }
}
""",
        ),
        (
            "main.tf",
            """resource "google_service_account" "runtime" {
  account_id = "runtime"
}

resource "google_cloud_run_v2_service" "app" {
  name = "${var.project_id}-app"
  template {
    service_account = google_service_account.runtime.email
  }
}
""",
        ),
        language="terraform",
    )

    catalog = build_repository_catalog(snapshot)
    nodes = {node["id"]: node for node in catalog["nodes"]}
    app_id = "terraform:resource:google_cloud_run_v2_service.app"
    runtime_id = "terraform:resource:google_service_account.runtime"
    variable_id = "terraform:variable:var.project_id"

    assert nodes[app_id]["signature"] == (
        'resource "google_cloud_run_v2_service" "app"'
    )
    assert any(
        edge["source"] == app_id
        and edge["target"] == runtime_id
        and edge["type"] == "depends_on"
        for edge in catalog["edges"]
    )
    assert any(
        edge["source"] == app_id
        and edge["target"] == variable_id
        and edge["type"] == "depends_on"
        for edge in catalog["edges"]
    )
    assert any(
        node["kind"] == "check" and node.get("function_symbol") == "var.project_id"
        for node in catalog["nodes"]
    )
    flow = next(
        flow
        for flow in catalog["default_flows"]
        if flow["name"] == "Provision google_cloud_run_v2_service.app"
    )
    assert flow["node_ids"][0] == app_id
    validation = RepositoryWorkflowValidator(catalog).validate(
        {
            "name": "Cloud Run dependency path",
            "description": "A custom infrastructure view.",
            "actor_role": "SYSTEM",
            "node_ids": flow["node_ids"],
        }
    )
    assert validation["valid"] is True


def test_repository_custom_workflow_rejects_unknown_and_disconnected_nodes() -> None:
    snapshot = _snapshot(
        (
            "app.py",
            """def first() -> None:
    return None

def second() -> None:
    return None
""",
        ),
        language="python",
    )
    catalog = build_repository_catalog(snapshot)
    validator = RepositoryWorkflowValidator(catalog)

    result = validator.validate(
        {
            "name": "Invented code path",
            "description": "Must not pass merely because both functions exist.",
            "actor_role": "SYSTEM",
            "node_ids": [
                "function:app.first",
                "function:app.second",
                "function:app.missing",
            ],
        }
    )

    assert result["valid"] is False
    assert {error["code"] for error in result["errors"]} == {
        "DISCONNECTED_EDGE",
        "UNKNOWN_NODE",
    }


def test_terraform_json_blocks_use_the_same_stable_addresses() -> None:
    snapshot = _snapshot(
        (
            "main.tf.json",
            json.dumps(
                {
                    "variable": {"region": {"default": "europe-west2"}},
                    "resource": {
                        "google_storage_bucket": {
                            "evidence": {"location": "${var.region}"}
                        }
                    },
                }
            ),
        ),
        language="terraform",
    )

    catalog = build_repository_catalog(snapshot)

    assert any(
        node["id"] == "terraform:resource:google_storage_bucket.evidence"
        and node["signature"] == 'resource "google_storage_bucket" "evidence"'
        for node in catalog["nodes"]
    )


class _ModelClient:
    def __init__(self) -> None:
        self.request: dict[str, object] | None = None

    def generate(self, request_body: dict[str, object]) -> ModelOutput:
        self.request = request_body
        return ModelOutput(
            content=json.dumps(
                {
                    "schema_version": "1.0",
                    "summary": "The application exposes a deterministic user registration path.",
                    "architecture": [
                        {
                            "name": "HTTP edge",
                            "explanation": "The route delegates to an extracted Python handler.",
                            "node_ids": ["route:POST:/users"],
                        }
                    ],
                    "important_flows": [
                        {
                            "flow_id": "default:post:/users",
                            "explanation": "This flow validates input and persists a user.",
                        }
                    ],
                    "reading_order": ["Start with the POST /users flow."],
                    "limitations": [],
                    "attack_tree": {
                        "title": "Abuse the user registration boundary",
                        "root_attack_node_id": "attack:registration-abuse",
                        "nodes": [
                            {
                                "attack_node_id": "attack:registration-abuse",
                                "title": "Abuse user registration",
                                "description": (
                                    "Reach an unintended outcome through the supplied "
                                    "registration boundary."
                                ),
                                "kind": "GOAL",
                                "operator": "OR",
                                "graph_node_ids": ["route:POST:/users"],
                                "flow_ids": ["default:post:/users"],
                            },
                            {
                                "attack_node_id": "attack:submit-hostile-input",
                                "title": "Submit hostile registration input",
                                "description": (
                                    "Exercise the exposed route with input designed to "
                                    "cross an expected validation boundary."
                                ),
                                "kind": "ACTION",
                                "operator": "LEAF",
                                "graph_node_ids": ["route:POST:/users"],
                                "flow_ids": ["default:post:/users"],
                            },
                            {
                                "attack_node_id": "attack:repeat-registration",
                                "title": "Repeat registration requests",
                                "description": (
                                    "Exercise the same public route repeatedly and observe "
                                    "whether controls constrain the requests."
                                ),
                                "kind": "ACTION",
                                "operator": "LEAF",
                                "graph_node_ids": ["route:POST:/users"],
                                "flow_ids": ["default:post:/users"],
                            },
                        ],
                        "edges": [
                            {
                                "parent_attack_node_id": "attack:registration-abuse",
                                "child_attack_node_id": "attack:submit-hostile-input",
                            },
                            {
                                "parent_attack_node_id": "attack:registration-abuse",
                                "child_attack_node_id": "attack:repeat-registration",
                            },
                        ],
                        "assumptions": [
                            "The projection does not prove either action succeeds."
                        ],
                        "limitations": [],
                    },
                }
            ),
            request_id="request-1",
            input_tokens=200,
            output_tokens=100,
        )


class _InventedReferenceModel(_ModelClient):
    def generate(self, request_body: dict[str, object]) -> ModelOutput:
        output = super().generate(request_body)
        document = json.loads(output.content)
        document["attack_tree"]["nodes"][1]["graph_node_ids"] = [
            "function:invented.backdoor"
        ]
        return ModelOutput(
            content=json.dumps(document),
            request_id=output.request_id,
            input_tokens=output.input_tokens,
            output_tokens=output.output_tokens,
        )


class _MalformedAttackTreeModel(_ModelClient):
    def generate(self, request_body: dict[str, object]) -> ModelOutput:
        output = super().generate(request_body)
        document = json.loads(output.content)
        document["attack_tree"]["edges"].append(
            {
                "parent_attack_node_id": "attack:submit-hostile-input",
                "child_attack_node_id": "attack:registration-abuse",
            }
        )
        return ModelOutput(
            content=json.dumps(document),
            request_id=output.request_id,
            input_tokens=output.input_tokens,
            output_tokens=output.output_tokens,
        )


def test_mistral_receives_only_a_bounded_redacted_graph_projection() -> None:
    snapshot = _snapshot(
        (
            "app.py",
            """from fastapi import FastAPI
app = FastAPI()
@app.post("/users")
def register_user(email: str):
    return email
""",
        ),
        (
            "docs/configuration.md",
            "# Configuration\nPOST /users uses this configuration.\napi_key = super-secret-model-value\n",
        ),
        language="python",
    )
    catalog = build_repository_catalog(snapshot)
    client = _ModelClient()

    result = generate_repository_narrative(catalog, client, requested=True)
    request, projection = build_repository_model_request(catalog)

    assert result["status"] == "READY"
    assert result["explanation"]["schema_version"] == "1.0"
    assert (
        result["explanation"]["attack_tree"]["root_attack_node_id"]
        == "attack:registration-abuse"
    )
    assert client.request is not None
    rendered = json.dumps(client.request)
    assert "super-secret-model-value" not in rendered
    assert "[REDACTED]" in rendered
    assert len(json.dumps(projection).encode("utf-8")) <= 72_000
    assert request["model"] == "mistral-small-2603"
    assert request["max_tokens"] == 4_000
    assert (
        request["response_format"]["json_schema"]["name"]
        == "repository_graph_security_analysis"
    )
    assert "defensive attack tree" in request["messages"][1]["content"]


def test_mistral_cannot_invent_graph_references() -> None:
    catalog = build_repository_catalog(
        _snapshot(
            (
                "app.py",
                """from fastapi import FastAPI
app = FastAPI()
@app.post("/users")
def register_user(email: str):
    return email
""",
            ),
            language="python",
        )
    )

    result = generate_repository_narrative(
        catalog, _InventedReferenceModel(), requested=True
    )

    assert result["status"] == "FAILED"
    assert result["error_code"] == "REPOSITORY_MODEL_REFERENCE_INVALID"


def test_mistral_attack_tree_must_be_a_connected_acyclic_tree() -> None:
    catalog = build_repository_catalog(
        _snapshot(
            (
                "app.py",
                """from fastapi import FastAPI
app = FastAPI()
@app.post("/users")
def register_user(email: str):
    return email
""",
            ),
            language="python",
        )
    )

    result = generate_repository_narrative(
        catalog, _MalformedAttackTreeModel(), requested=True
    )

    assert result["status"] == "FAILED"
    assert result["error_code"] == "REPOSITORY_MODEL_ATTACK_TREE_INVALID"


@pytest.mark.parametrize(
    "value",
    [
        "http://github.com/example/project",
        "https://evil.example/example/project",
        "https://user:pass@github.com/example/project",
        "example/project/extra",
    ],
)
def test_repository_source_rejects_non_github_or_ambiguous_values(value: str) -> None:
    with pytest.raises(BantamError):
        RepositorySource.from_mapping(
            {"repository": value, "ref": "main", "root_path": "", "language": "auto"}
        )
