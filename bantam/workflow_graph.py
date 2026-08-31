"""Deterministic source-to-workflow graph generation and validation.

The workflow graph is intentionally built without an LLM.  Python's AST,
SQL text, route decorators, and version-controlled Markdown are the only
inputs.  The generated JSON is committed with the application and loaded at
runtime, so the production API does not need access to the repository.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable
from uuid import UUID, uuid4

from bantam.errors import BantamError

if TYPE_CHECKING:
    from psycopg_pool import ConnectionPool


CATALOG_VERSION = 1
DEFAULT_CATALOG_PATH = Path(__file__).with_name("workflow_catalog.json")
ROLE_BY_ANNOTATION: dict[str, tuple[str, ...]] = {
    "CustomerPrincipal": ("CUSTOMER",),
    "AdminPrincipal": ("BANK_ADMIN",),
    "AspisAdminPrincipal": ("BANK_ADMIN", "ASPIS_ADMIN"),
    "AspisPrincipal": ("BANK_ADMIN", "ASPIS_ADMIN", "ASPIS_AUDITOR"),
    "MfaPrincipal": ("BANK_ADMIN", "ASPIS_ADMIN", "ASPIS_AUDITOR"),
    "OperatorPrincipal": ("BANK_ADMIN", "RISK_ANALYST"),
    "AuditPrincipal": ("BANK_ADMIN", "RISK_ANALYST", "COMPLIANCE_AUDITOR"),
    "ReconcilePrincipal": ("BANK_ADMIN", "COMPLIANCE_AUDITOR"),
    "AnyPrincipal": (
        "CUSTOMER",
        "BANK_ADMIN",
        "RISK_ANALYST",
        "COMPLIANCE_AUDITOR",
        "ASPIS_AUDITOR",
        "ASPIS_ADMIN",
    ),
}

DOC_BY_HANDLER = {
    "register": "registration.md",
    "login": "login.md",
    "logout": "logout.md",
    "me": "view-profile.md",
    "submit_kyc": "kyc-submit.md",
    "list_accounts": "list-accounts.md",
    "open_account": "open-account.md",
    "list_account_transactions": "account-transactions.md",
    "list_notifications": "notifications.md",
    "account_status_claim": "account-status-claim.md",
    "create_sca_challenge": "sca-challenge.md",
    "create_transfer": "transfer.md",
    "get_transfer": "get-transfer.md",
    "admin_list_customers": "admin-list-customers.md",
    "admin_decide_kyc": "kyc-decision.md",
    "operator_set_account_status": "freeze-unfreeze-account.md",
    "admin_demo_deposit": "demo-deposit.md",
    "admin_reverse_transaction": "reverse-transaction.md",
    "operator_list_transactions": "admin-list-transactions.md",
    "list_risk_alerts": "risk-alerts.md",
    "create_manual_risk_alert": "risk-alerts.md",
    "review_risk_alert": "risk-alerts.md",
    "list_audit_events": "audit-events.md",
    "run_reconciliation": "reconciliation.md",
}

FLOW_LABELS = {
    "register": "Register a customer",
    "register_aspis_auditor": "Register an Aspis auditor",
    "login": "Sign in",
    "logout": "Sign out",
    "me": "View profile",
    "mfa_state": "View MFA state",
    "begin_mfa_enrollment": "Begin MFA enrollment",
    "remove_passkey": "Remove a passkey",
    "remove_totp": "Remove TOTP",
    "submit_kyc": "Submit KYC",
    "list_accounts": "List accounts",
    "open_account": "Open an account",
    "get_account": "View an account",
    "list_account_transactions": "View account activity",
    "list_notifications": "View notifications",
    "account_status_claim": "Issue an account-status claim",
    "create_sca_challenge": "Create an SCA challenge",
    "create_transfer": "Send money",
    "get_transfer": "View a transfer",
    "list_aspis_auditor_requests": "List Aspis auditor requests",
    "decide_aspis_auditor_request": "Decide an Aspis auditor request",
    "admin_asvs_overview": "View ASVS assurance",
    "admin_run_asvs": "Run ASVS verification",
    "admin_generate_asvs_test_plan": "Generate an ASVS test plan",
    "admin_execute_asvs_test_plan": "Execute an ASVS test plan",
    "admin_list_users": "List admin users",
    "admin_create_user": "Create an admin user",
    "admin_list_customers": "List customers",
    "admin_decide_kyc": "Decide customer KYC",
    "operator_set_account_status": "Freeze or unfreeze an account",
    "admin_demo_deposit": "Create a synthetic deposit",
    "admin_reverse_transaction": "Reverse a transaction",
    "operator_list_transactions": "List transactions",
    "list_risk_alerts": "List risk alerts",
    "create_manual_risk_alert": "Create a risk alert",
    "review_risk_alert": "Review a risk alert",
    "list_audit_events": "View audit events",
    "run_reconciliation": "Run reconciliation",
    "health": "Check service health",
}

SYSTEM_FLOWS = (
    (
        "async-outbox-publish",
        "Publish transactional outbox",
        "bantam.events.OutboxPublisher.publish_batch",
        "async-outbox-publish.md",
    ),
    (
        "async-risk-worker",
        "Generate a risk alert from an event",
        "bantam.workers.create_risk_alert",
        "async-risk-worker.md",
    ),
    (
        "async-notification-worker",
        "Generate transfer notifications",
        "bantam.workers.create_notifications",
        "async-notification-worker.md",
    ),
)

STATE_SERVICE_CLASSES = {
    "auth": "bantam.auth.AuthService",
    "claims": "bantam.auth.SignedClaimService",
    "database": "bantam.database.Database",
    "ledger": "bantam.ledger.LedgerService",
    "mfa": "bantam.mfa.MfaService",
    "sca": "bantam.sca.SCAService",
    "asvs": "bantam.asvs.AsvsService",
    "asvs_ai": "bantam.asvs_ai.AsvsAiService",
    "workflow_graph": "bantam.workflow_graph.WorkflowGraphService",
    "repository_graph": "bantam.repository_graph.RepositoryGraphService",
}

SELF_SERVICE_CLASSES = {
    "sca": "bantam.sca.SCAService",
    "publisher": "bantam.events.EventPublisher",
    "pool": "psycopg_pool.ConnectionPool",
}

IGNORED_CALL_SUFFIXES = {
    "append",
    "astype",
    "connection",
    "date",
    "decode",
    "encode",
    "execute",
    "extend",
    "fetchall",
    "fetchone",
    "format",
    "get",
    "hexdigest",
    "isoformat",
    "items",
    "join",
    "lower",
    "pop",
    "removeprefix",
    "replace",
    "set_cookie",
    "split",
    "strip",
    "transaction",
    "upper",
    "values",
}

IGNORED_CALLS = {
    "bool",
    "bytes",
    "date",
    "dict",
    "enumerate",
    "int",
    "isinstance",
    "len",
    "list",
    "max",
    "min",
    "next",
    "range",
    "set",
    "str",
    "sum",
    "tuple",
    "uuid4",
}


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _humanize(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").strip().capitalize()


def _bounded(value: str, limit: int = 180) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else f"{value[: limit - 1]}…"


def _expression_text(source: str, node: ast.AST) -> str:
    segment = ast.get_source_segment(source, node)
    if segment is None:
        raise ValueError("could not recover an expression from its source")
    return " ".join(segment.split())


def _function_signature(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    source: str,
) -> str:
    positional = list(node.args.posonlyargs) + list(node.args.args)
    defaults: list[ast.expr | None] = [None] * (
        len(positional) - len(node.args.defaults)
    ) + list(node.args.defaults)
    parts: list[str] = []
    positional_only = len(node.args.posonlyargs)
    for index, (argument, default) in enumerate(zip(positional, defaults)):
        rendered = argument.arg
        if argument.annotation is not None:
            rendered += f": {_expression_text(source, argument.annotation)}"
        if default is not None:
            rendered += f" = {_expression_text(source, default)}"
        parts.append(rendered)
        if positional_only and index + 1 == positional_only:
            parts.append("/")
    if node.args.vararg is not None:
        rendered = f"*{node.args.vararg.arg}"
        if node.args.vararg.annotation is not None:
            rendered += f": {_expression_text(source, node.args.vararg.annotation)}"
        parts.append(rendered)
    elif node.args.kwonlyargs:
        parts.append("*")
    for argument, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        rendered = argument.arg
        if argument.annotation is not None:
            rendered += f": {_expression_text(source, argument.annotation)}"
        if default is not None:
            rendered += f" = {_expression_text(source, default)}"
        parts.append(rendered)
    if node.args.kwarg is not None:
        rendered = f"**{node.args.kwarg.arg}"
        if node.args.kwarg.annotation is not None:
            rendered += f": {_expression_text(source, node.args.kwarg.annotation)}"
        parts.append(rendered)
    prefix = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
    result = f"{prefix} {node.name}({', '.join(parts)})"
    if node.returns is not None:
        result += f" -> {_expression_text(source, node.returns)}"
    return result


def _route_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, str] | None:
    for decorator in node.decorator_list:
        if not isinstance(decorator, ast.Call):
            continue
        function = decorator.func
        if not isinstance(function, ast.Attribute):
            continue
        if (
            function.attr in {"get", "post", "put", "patch", "delete"}
            and decorator.args
            and isinstance(decorator.args[0], ast.Constant)
        ):
            return function.attr.upper(), str(decorator.args[0].value)
        if (
            function.attr == "route"
            and decorator.args
            and isinstance(decorator.args[0], ast.Constant)
        ):
            methods = ["GET"]
            for keyword in decorator.keywords:
                if keyword.arg != "methods" or not isinstance(
                    keyword.value, (ast.List, ast.Tuple)
                ):
                    continue
                discovered = [
                    str(item.value).upper()
                    for item in keyword.value.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                ]
                if discovered:
                    methods = discovered
            return sorted(methods)[0], str(decorator.args[0].value)
    return None


def _roles(node: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    discovered: list[str] = []
    for argument in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]:
        if argument.annotation is None:
            continue
        annotation_names = {
            child.id
            for child in ast.walk(argument.annotation)
            if isinstance(child, ast.Name)
        }
        for name, roles in ROLE_BY_ANNOTATION.items():
            if name in annotation_names:
                for role in roles:
                    if role not in discovered:
                        discovered.append(role)
    return tuple(discovered or ("PUBLIC",))


def _imports(tree: ast.Module) -> dict[str, str]:
    aliases: dict[str, str] = {}
    for statement in tree.body:
        if isinstance(statement, ast.Import):
            for item in statement.names:
                aliases[item.asname or item.name] = item.name
        elif isinstance(statement, ast.ImportFrom) and statement.module:
            for item in statement.names:
                aliases[item.asname or item.name] = f"{statement.module}.{item.name}"
    return aliases


@dataclass
class FunctionFact:
    symbol: str
    module: str
    class_name: str | None
    node: ast.FunctionDef | ast.AsyncFunctionDef
    file: str
    signature: str
    source: str
    imports: dict[str, str]
    route: tuple[str, str] | None = None
    events: list[dict[str, Any]] = field(default_factory=list)

    @property
    def node_id(self) -> str:
        return f"function:{self.symbol}"


class _EventVisitor(ast.NodeVisitor):
    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.root = root
        self.calls: list[ast.Call] = []
        self.checks: list[ast.If] = []
        self.transactions: list[ast.With | ast.AsyncWith] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is self.root:
            for statement in node.body:
                self.visit(statement)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is self.root:
            for statement in node.body:
                self.visit(statement)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(node)
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        self.checks.append(node)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        if any(_is_transaction(item.context_expr) for item in node.items):
            self.transactions.append(node)
        self.generic_visit(node)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        if any(_is_transaction(item.context_expr) for item in node.items):
            self.transactions.append(node)
        self.generic_visit(node)


def _is_transaction(expression: ast.expr) -> bool:
    return (
        isinstance(expression, ast.Call)
        and isinstance(expression.func, ast.Attribute)
        and expression.func.attr == "transaction"
    )


def _sql_text(expression: ast.expr) -> str | None:
    if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
        candidate = " ".join(expression.value.split())
        if re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", candidate, re.I):
            return candidate
        return None
    if isinstance(expression, ast.Call):
        if (
            isinstance(expression.func, ast.Attribute)
            and expression.func.attr == "format"
        ):
            return _sql_text(expression.func.value)
        if expression.args:
            return _sql_text(expression.args[0])
    return None


def _sql_operation(statement: str) -> str:
    match = re.search(r"\b(SELECT|INSERT|UPDATE|DELETE)\b", statement, re.I)
    return match.group(1).upper() if match else "SQL"


def _sql_tables(statement: str) -> list[str]:
    patterns = (
        r"\bFROM\s+([a-z_][a-z0-9_]*)",
        r"\bJOIN\s+([a-z_][a-z0-9_]*)",
        r"\bINTO\s+([a-z_][a-z0-9_]*)",
        r"\bUPDATE\s+([a-z_][a-z0-9_]*)",
    )
    tables: list[str] = []
    for pattern in patterns:
        for name in re.findall(pattern, statement, re.I):
            lowered = name.lower()
            if lowered not in tables:
                tables.append(lowered)
    return tables


def _failure_outcomes(node: ast.If, source: str) -> list[str]:
    outcomes: list[str] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Raise) or child.exc is None:
            continue
        rendered = _bounded(_expression_text(source, child.exc), 120)
        if rendered not in outcomes:
            outcomes.append(rendered)
    return outcomes


def _dotted_name(node: ast.expr) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        owner = _dotted_name(node.value)
        return f"{owner}.{node.attr}" if owner else node.attr
    return ""


def _call_text(call: ast.Call) -> str:
    return _dotted_name(call.func)


class CatalogBuilder:
    """Build the same catalogue for the same repository bytes."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.functions: dict[str, FunctionFact] = {}
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._short_symbols: dict[str, list[str]] = defaultdict(list)

    def build(self) -> dict[str, Any]:
        self._index_python()
        self._extract_events()
        flows = self._route_flows()
        flows.extend(self._system_flows())
        self._index_database_constraints()
        for flow in flows:
            sequence = flow["node_ids"]
            for source, target in zip(sequence, sequence[1:]):
                self._edge(source, target, "next", flow_id=flow["flow_id"])
        catalog: dict[str, Any] = {
            "version": CATALOG_VERSION,
            "generator": "bantam.workflow_graph.CatalogBuilder",
            "nodes": sorted(self.nodes.values(), key=lambda item: item["id"]),
            "edges": sorted(
                self.edges.values(),
                key=lambda item: (item["source"], item["target"], item["type"]),
            ),
            "default_flows": sorted(flows, key=lambda item: item["flow_id"]),
        }
        catalog["graph_digest"] = _digest(catalog)
        return catalog

    def _index_python(self) -> None:
        for path in sorted((self.root / "bantam").glob("*.py")):
            relative = path.relative_to(self.root).as_posix()
            module = relative.removesuffix(".py").replace("/", ".")
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=relative)
            imports = _imports(tree)
            self._collect_definitions(
                tree.body,
                module=module,
                relative=relative,
                source=source,
                imports=imports,
                class_name=None,
                function_parents=(),
            )
        for symbol in self.functions:
            self._short_symbols[symbol.rsplit(".", 1)[-1]].append(symbol)
        for fact in self.functions.values():
            self.nodes[fact.node_id] = {
                "id": fact.node_id,
                "kind": "function",
                "label": _humanize(fact.node.name),
                "symbol": fact.symbol,
                "signature": fact.signature,
                "file": fact.file,
                "line": fact.node.lineno,
            }

    def _collect_definitions(
        self,
        statements: Iterable[ast.stmt],
        *,
        module: str,
        relative: str,
        source: str,
        imports: dict[str, str],
        class_name: str | None,
        function_parents: tuple[str, ...],
    ) -> None:
        for statement in statements:
            if isinstance(statement, ast.ClassDef):
                self._collect_definitions(
                    statement.body,
                    module=module,
                    relative=relative,
                    source=source,
                    imports=imports,
                    class_name=statement.name,
                    function_parents=(),
                )
                continue
            if not isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            route = _route_decorator(statement)
            if class_name:
                symbol = f"{module}.{class_name}.{statement.name}"
            elif route:
                symbol = f"{module}.{statement.name}"
            elif function_parents:
                symbol = f"{module}.{'.'.join(function_parents)}.{statement.name}"
            else:
                symbol = f"{module}.{statement.name}"
            fact = FunctionFact(
                symbol=symbol,
                module=module,
                class_name=class_name,
                node=statement,
                file=relative,
                signature=_function_signature(statement, source),
                source=source,
                imports=imports,
                route=route,
            )
            self.functions[symbol] = fact
            self._collect_definitions(
                statement.body,
                module=module,
                relative=relative,
                source=source,
                imports=imports,
                class_name=class_name,
                function_parents=(*function_parents, statement.name),
            )

    def _resolve_call(self, fact: FunctionFact, call: ast.Call) -> str | None:
        rendered = _call_text(call)
        if not rendered:
            return None
        suffix = rendered.rsplit(".", 1)[-1]
        if rendered in IGNORED_CALLS or suffix in IGNORED_CALL_SUFFIXES:
            return None
        if isinstance(call.func, ast.Name):
            imported = fact.imports.get(call.func.id)
            if imported in self.functions:
                return imported
            local = f"{fact.module}.{call.func.id}"
            if local in self.functions:
                return local
            matches = self._short_symbols.get(call.func.id, [])
            return matches[0] if len(matches) == 1 else None
        if not isinstance(call.func, ast.Attribute):
            return None
        if isinstance(call.func.value, ast.Name):
            owner = call.func.value.id
            if owner == "self" and fact.class_name:
                candidate = f"{fact.module}.{fact.class_name}.{call.func.attr}"
                if candidate in self.functions:
                    return candidate
            imported = fact.imports.get(owner)
            candidate = f"{imported}.{call.func.attr}" if imported else ""
            if candidate in self.functions:
                return candidate
        parts = rendered.split(".")
        if "state" in parts:
            index = parts.index("state")
            if index + 2 < len(parts):
                service = parts[index + 1]
                method = parts[index + 2]
                owner = STATE_SERVICE_CLASSES.get(service)
                candidate = f"{owner}.{method}" if owner else ""
                if candidate in self.functions:
                    return candidate
        if len(parts) >= 2 and parts[0] == "self":
            owner = SELF_SERVICE_CLASSES.get(parts[1])
            candidate = f"{owner}.{parts[-1]}" if owner else ""
            if candidate in self.functions:
                return candidate
        return None

    def _extract_events(self) -> None:
        for fact in self.functions.values():
            visitor = _EventVisitor(fact.node)
            visitor.visit(fact.node)
            candidates: list[tuple[int, int, int, dict[str, Any]]] = []
            occurrence: dict[str, int] = defaultdict(int)
            for node in visitor.checks:
                condition = _bounded(_expression_text(fact.source, node.test), 240)
                key = hashlib.sha256(condition.encode("utf-8")).hexdigest()[:12]
                occurrence[f"check:{key}"] += 1
                node_id = f"check:{fact.symbol}:{key}:{occurrence[f'check:{key}']}"
                graph_node = {
                    "id": node_id,
                    "kind": "check",
                    "label": f"Check {_bounded(condition, 72)}",
                    "condition": condition,
                    "function_symbol": fact.symbol,
                    "signature": fact.signature,
                    "file": fact.file,
                    "line": node.lineno,
                    "failure_outcomes": _failure_outcomes(node, fact.source),
                }
                self.nodes[node_id] = graph_node
                self._edge(fact.node_id, node_id, "checks")
                candidates.append(
                    (node.lineno, node.col_offset, 2, {"node_id": node_id})
                )
            for node in visitor.transactions:
                node_id = f"transaction:{fact.symbol}:{node.lineno}"
                self.nodes[node_id] = {
                    "id": node_id,
                    "kind": "transaction",
                    "label": "PostgreSQL transaction",
                    "function_symbol": fact.symbol,
                    "file": fact.file,
                    "line": node.lineno,
                    "durability": "all operations commit or roll back together",
                }
                self._edge(fact.node_id, node_id, "contains")
                candidates.append(
                    (node.lineno, node.col_offset, 0, {"node_id": node_id})
                )
            sql_occurrence: dict[str, int] = defaultdict(int)
            for call in visitor.calls:
                rendered = _call_text(call)
                if rendered.endswith(".execute") and call.args:
                    statement = _sql_text(call.args[0])
                    if statement:
                        operation = _sql_operation(statement)
                        tables = _sql_tables(statement)
                        fingerprint = hashlib.sha256(
                            statement.encode("utf-8")
                        ).hexdigest()[:12]
                        sql_occurrence[fingerprint] += 1
                        node_id = (
                            f"sql:{fact.symbol}:{fingerprint}:"
                            f"{sql_occurrence[fingerprint]}"
                        )
                        kind = (
                            "lock"
                            if operation == "SELECT"
                            and "FOR UPDATE" in statement.upper()
                            else "effect"
                            if operation in {"INSERT", "UPDATE", "DELETE"}
                            else "query"
                        )
                        label_target = ", ".join(tables[:2]) or "database"
                        self.nodes[node_id] = {
                            "id": node_id,
                            "kind": kind,
                            "label": f"{operation.title()} {label_target}",
                            "operation": operation,
                            "tables": tables,
                            "sql": statement,
                            "durable": operation in {"INSERT", "UPDATE", "DELETE"},
                            "function_symbol": fact.symbol,
                            "file": fact.file,
                            "line": call.lineno,
                        }
                        self._edge(
                            fact.node_id,
                            node_id,
                            "reads" if operation == "SELECT" else "writes",
                        )
                        candidates.append(
                            (call.lineno, call.col_offset, 3, {"node_id": node_id})
                        )
                        continue
                target = self._resolve_call(fact, call)
                if target and target != fact.symbol:
                    target_id = f"function:{target}"
                    self._edge(fact.node_id, target_id, "calls")
                    candidates.append(
                        (
                            call.lineno,
                            call.col_offset,
                            1,
                            {"node_id": target_id, "call": target},
                        )
                    )
            candidates.sort(key=lambda item: item[:3])
            fact.events = [item[3] for item in candidates]

    def _route_flows(self) -> list[dict[str, Any]]:
        flows: list[dict[str, Any]] = []
        for fact in sorted(self.functions.values(), key=lambda item: item.symbol):
            if fact.route is None:
                continue
            method, path = fact.route
            route_id = f"route:{method}:{path}"
            roles = list(_roles(fact.node))
            self.nodes[route_id] = {
                "id": route_id,
                "kind": "route",
                "label": f"{method} {path}",
                "method": method,
                "path": path,
                "roles": roles,
                "signature": fact.signature,
                "function_symbol": fact.symbol,
                "file": fact.file,
                "line": fact.node.lineno,
            }
            self._edge(route_id, fact.node_id, "handled_by")
            sequence = [route_id, fact.node_id]
            self._expand(fact.symbol, sequence, depth=0, stack=set())
            sequence = _dedupe_consecutive(sequence[:160])
            doc_name = DOC_BY_HANDLER.get(fact.node.name)
            title = FLOW_LABELS.get(fact.node.name, _humanize(fact.node.name))
            documentation = self._documentation(doc_name)
            if documentation["documentation"] is None:
                documentation = self._generated_documentation(
                    title=title,
                    roles=roles,
                    method=method,
                    path=path,
                    fact=fact,
                    sequence=sequence,
                )
            flows.append(
                {
                    "flow_id": f"default:{method.lower()}:{path}",
                    "name": title,
                    "description": f"Deterministically extracted from {fact.symbol}.",
                    "actor_roles": roles,
                    "source": "generated",
                    "route": {"method": method, "path": path},
                    "node_ids": sequence,
                    **documentation,
                }
            )
        return flows

    def _system_flows(self) -> list[dict[str, Any]]:
        flows: list[dict[str, Any]] = []
        for flow_id, name, symbol, doc_name in SYSTEM_FLOWS:
            if symbol not in self.functions:
                continue
            sequence = [f"function:{symbol}"]
            self._expand(symbol, sequence, depth=0, stack=set())
            sequence = _dedupe_consecutive(sequence[:160])
            documentation = self._documentation(doc_name)
            if documentation["documentation"] is None:
                documentation = self._generated_system_documentation(
                    title=name,
                    fact=self.functions[symbol],
                    sequence=sequence,
                )
            flows.append(
                {
                    "flow_id": f"default:system:{flow_id}",
                    "name": name,
                    "description": f"Deterministically extracted from {symbol}.",
                    "actor_roles": ["SYSTEM"],
                    "source": "generated",
                    "route": None,
                    "node_ids": sequence,
                    **documentation,
                }
            )
        return flows

    def _expand(
        self,
        symbol: str,
        sequence: list[str],
        *,
        depth: int,
        stack: set[str],
    ) -> None:
        if depth > 2 or symbol in stack:
            return
        fact = self.functions.get(symbol)
        if fact is None:
            return
        stack = {*stack, symbol}
        for event in fact.events:
            node_id = event["node_id"]
            sequence.append(node_id)
            target = event.get("call")
            if isinstance(target, str):
                self._expand(target, sequence, depth=depth + 1, stack=stack)

    def _documentation(self, doc_name: str | None) -> dict[str, Any]:
        if not doc_name:
            return {"documentation_path": None, "documentation": None}
        path = self.root / "docs" / "reference" / "flows" / doc_name
        if not path.is_file():
            return {"documentation_path": None, "documentation": None}
        return {
            "documentation_path": path.relative_to(self.root).as_posix(),
            "documentation": path.read_text(encoding="utf-8"),
        }

    def _generated_documentation(
        self,
        *,
        title: str,
        roles: list[str],
        method: str,
        path: str,
        fact: FunctionFact,
        sequence: list[str],
    ) -> dict[str, Any]:
        lines = [
            f"# Flow: {title}",
            "",
            "This reference is generated deterministically from the current Python AST ",
            "because no authored Markdown page is mapped to this route.",
            "",
            f"- **Entry:** `{method} {path}`",
            f"- **Actor:** `{'`, `'.join(roles)}`",
            f"- **Handler:** `{fact.symbol}`",
            f"- **Signature:** `{fact.signature}`",
            "",
            "## Extracted code path",
            "",
        ]
        documented_sequence = sequence[:16]
        for index, node_id in enumerate(documented_sequence, start=1):
            node = self.nodes[node_id]
            evidence = (
                node.get("signature")
                or node.get("condition")
                or (
                    f"{node.get('operation')} {', '.join(node.get('tables', []))}"
                    if node.get("operation")
                    else None
                )
                or node.get("symbol")
                or node.get("function_symbol")
                or node["id"]
            )
            rendered = str(evidence).replace("`", "'")
            lines.append(
                f"{index}. **{node['kind']} — {node['label']}** — `{rendered}`"
            )
        if len(sequence) > len(documented_sequence):
            lines.extend(
                [
                    "",
                    (
                        f"The explorer contains {len(sequence) - len(documented_sequence)} "
                        "additional extracted nodes. Select them in the code lane for "
                        "their exact evidence."
                    ),
                ]
            )
        return {
            "documentation_path": None,
            "documentation": "\n".join(lines) + "\n",
        }

    def _generated_system_documentation(
        self,
        *,
        title: str,
        fact: FunctionFact,
        sequence: list[str],
    ) -> dict[str, Any]:
        lines = [
            f"# Flow: {title}",
            "",
            "This reference is generated deterministically from the current Python AST.",
            "",
            "- **Actor:** `SYSTEM`",
            f"- **Entry function:** `{fact.symbol}`",
            f"- **Signature:** `{fact.signature}`",
            "",
            "## Extracted code path",
            "",
        ]
        documented_sequence = sequence[:16]
        for index, node_id in enumerate(documented_sequence, start=1):
            node = self.nodes[node_id]
            evidence = (
                node.get("signature")
                or node.get("condition")
                or (
                    f"{node.get('operation')} {', '.join(node.get('tables', []))}"
                    if node.get("operation")
                    else None
                )
                or node.get("symbol")
                or node.get("function_symbol")
                or node["id"]
            )
            rendered = str(evidence).replace("`", "'")
            lines.append(
                f"{index}. **{node['kind']} — {node['label']}** — `{rendered}`"
            )
        if len(sequence) > len(documented_sequence):
            lines.extend(
                [
                    "",
                    (
                        f"The explorer contains {len(sequence) - len(documented_sequence)} "
                        "additional extracted nodes. Select them in the code lane for "
                        "their exact evidence."
                    ),
                ]
            )
        return {
            "documentation_path": None,
            "documentation": "\n".join(lines) + "\n",
        }

    def _index_database_constraints(self) -> None:
        trigger_pattern = re.compile(
            r"CREATE\s+(?:CONSTRAINT\s+)?TRIGGER\s+([a-z_][a-z0-9_]*)"
            r"[\s\S]*?\sON\s+([a-z_][a-z0-9_]*)"
            r"[\s\S]*?EXECUTE\s+FUNCTION\s+([a-z_][a-z0-9_]*)\s*\(\s*\)",
            re.I,
        )
        constraints_by_table: dict[str, list[str]] = defaultdict(list)
        for path in sorted((self.root / "migrations").glob("*.sql")):
            text = path.read_text(encoding="utf-8")
            relative = path.relative_to(self.root).as_posix()
            for match in trigger_pattern.finditer(text):
                name, table, function = (value.lower() for value in match.groups())
                node_id = f"constraint:postgres:{name}"
                self.nodes[node_id] = {
                    "id": node_id,
                    "kind": "constraint",
                    "label": _humanize(name),
                    "constraint": name,
                    "database_function": function,
                    "tables": [table],
                    "file": relative,
                    "line": text[: match.start()].count("\n") + 1,
                }
                constraints_by_table[table].append(node_id)
        for node in tuple(self.nodes.values()):
            if node.get("kind") != "effect":
                continue
            for table in node.get("tables", []):
                for constraint_id in constraints_by_table.get(table, []):
                    self._edge(node["id"], constraint_id, "enforced_by")
                    constraint = self.nodes[constraint_id]
                    node.setdefault("constraints", []).append(
                        {
                            "node_id": constraint_id,
                            "name": constraint["constraint"],
                            "database_function": constraint["database_function"],
                        }
                    )
            if node.get("constraints"):
                node["constraints"].sort(key=lambda item: item["name"])

    def _edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        *,
        flow_id: str | None = None,
    ) -> None:
        key = (source, target, edge_type)
        existing = self.edges.get(key)
        if existing is None:
            existing = {"source": source, "target": target, "type": edge_type}
            self.edges[key] = existing
        if flow_id:
            flow_ids = existing.setdefault("flow_ids", [])
            if flow_id not in flow_ids:
                flow_ids.append(flow_id)
                flow_ids.sort()


def _dedupe_consecutive(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        if not result or result[-1] != value:
            result.append(value)
    return result


def build_catalog(root: Path) -> dict[str, Any]:
    return CatalogBuilder(root).build()


def load_catalog(path: Path = DEFAULT_CATALOG_PATH) -> dict[str, Any]:
    try:
        catalog = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"workflow catalogue is unavailable: {path}") from error
    expected = catalog.get("graph_digest")
    unsigned = {key: value for key, value in catalog.items() if key != "graph_digest"}
    if expected != _digest(unsigned):
        raise RuntimeError("workflow catalogue digest does not match its contents")
    return catalog


class WorkflowGraphService:
    """Serve the immutable catalogue and persist validated admin compositions."""

    def __init__(
        self,
        pool: "ConnectionPool",
        catalog_path: Path = DEFAULT_CATALOG_PATH,
    ) -> None:
        self.pool = pool
        self.catalog = load_catalog(catalog_path)
        self.nodes = {node["id"]: node for node in self.catalog["nodes"]}
        self.allowed_edges = {
            (edge["source"], edge["target"])
            for edge in self.catalog["edges"]
            if edge["type"] in {"next", "calls", "handled_by"}
        }

    def validate(self, definition: dict[str, Any]) -> dict[str, Any]:
        name = str(definition.get("name", "")).strip()
        description = str(definition.get("description", "")).strip()
        actor_role = str(definition.get("actor_role", "")).strip().upper()
        raw_node_ids = definition.get("node_ids", [])
        node_ids = (
            [str(node_id).strip() for node_id in raw_node_ids]
            if isinstance(raw_node_ids, list)
            else []
        )
        errors: list[dict[str, str]] = []
        if not 3 <= len(name) <= 100:
            errors.append(
                {"code": "INVALID_NAME", "message": "Name must be 3-100 characters."}
            )
        if len(description) > 500:
            errors.append(
                {
                    "code": "INVALID_DESCRIPTION",
                    "message": "Description must be at most 500 characters.",
                }
            )
        allowed_roles = {
            "PUBLIC",
            "CUSTOMER",
            "BANK_ADMIN",
            "RISK_ANALYST",
            "COMPLIANCE_AUDITOR",
            "ASPIS_AUDITOR",
            "ASPIS_ADMIN",
            "SYSTEM",
        }
        if actor_role not in allowed_roles:
            errors.append(
                {"code": "INVALID_ACTOR", "message": "Actor role is not recognised."}
            )
        if not 2 <= len(node_ids) <= 160:
            errors.append(
                {
                    "code": "INVALID_LENGTH",
                    "message": "A workflow must contain 2-160 nodes.",
                }
            )
        missing = sorted({node_id for node_id in node_ids if node_id not in self.nodes})
        for node_id in missing:
            errors.append(
                {
                    "code": "UNKNOWN_NODE",
                    "message": f"Unknown catalogue node: {node_id}",
                }
            )
        if node_ids and node_ids[0] in self.nodes:
            start = self.nodes[node_ids[0]]
            expected_start = "function" if actor_role == "SYSTEM" else "route"
            if start.get("kind") != expected_start:
                errors.append(
                    {
                        "code": "INVALID_START",
                        "message": (
                            "A SYSTEM workflow must begin at a function."
                            if actor_role == "SYSTEM"
                            else "A user workflow must begin at an authorized route."
                        ),
                    }
                )
            roles = start.get("roles")
            if roles and actor_role not in roles:
                errors.append(
                    {
                        "code": "ACTOR_FORBIDDEN",
                        "message": f"{actor_role} cannot enter {start['label']}.",
                    }
                )
        for source, target in zip(node_ids, node_ids[1:]):
            if (
                source in self.nodes
                and target in self.nodes
                and (source, target) not in self.allowed_edges
            ):
                errors.append(
                    {
                        "code": "DISCONNECTED_EDGE",
                        "message": f"No extracted transition exists from {source} to {target}.",
                    }
                )
        return {
            "valid": not errors,
            "errors": errors,
            "normalized": {
                "name": name,
                "description": description,
                "actor_role": actor_role,
                "node_ids": node_ids,
            },
            "graph_digest": self.catalog["graph_digest"],
        }

    def overview(self) -> dict[str, Any]:
        with self.pool.connection() as connection:
            rows = connection.execute(
                """
                SELECT workflow_id, name, description, actor_role, node_ids,
                       graph_digest, created_by, created_at, updated_at
                FROM workflow_definitions
                WHERE repository_graph_snapshot_id IS NULL
                ORDER BY created_at DESC
                LIMIT 100
                """
            ).fetchall()
        custom = []
        for row in rows:
            item = dict(row)
            result = self.validate(item)
            item["valid"] = (
                result["valid"] and item["graph_digest"] == self.catalog["graph_digest"]
            )
            item["validation_errors"] = result["errors"]
            item["stale"] = item["graph_digest"] != self.catalog["graph_digest"]
            item["documentation_path"] = None
            item["documentation"] = self.render_documentation(item)
            custom.append(item)
        return {**self.catalog, "custom_flows": custom}

    def render_documentation(self, definition: dict[str, Any]) -> str:
        """Render a custom flow reference from the same immutable node facts."""

        name = str(definition.get("name", "Custom workflow"))
        actor = str(definition.get("actor_role", "UNKNOWN"))
        description = str(definition.get("description", "")).strip()
        node_ids = definition.get("node_ids", [])
        validation_summary = (
            "PASS — every adjacent transition exists in the extracted graph"
            if definition.get("valid", True)
            else "FAIL — this saved path is stale or no longer validates"
        )
        lines = [
            f"# Workflow: {name}",
            "",
            "This document is generated deterministically from a saved path through ",
            f"catalogue `{self.catalog['graph_digest']}`.",
            "",
            f"- **Actor:** `{actor}`",
            f"- **Validation:** {validation_summary}",
        ]
        if description:
            lines.extend(["", description])
        lines.extend(["", "## Selected code path", ""])
        for index, node_id in enumerate(node_ids, start=1):
            node = self.nodes.get(str(node_id))
            if node is None:
                lines.append(f"{index}. **Missing node** — `{node_id}`")
                continue
            evidence = (
                node.get("signature")
                or node.get("condition")
                or (
                    f"{node.get('operation')} {', '.join(node.get('tables', []))}"
                    if node.get("operation")
                    else None
                )
                or node.get("symbol")
                or node.get("function_symbol")
                or node["id"]
            )
            rendered = str(evidence).replace("`", "'")
            lines.append(
                f"{index}. **{node['kind']} — {node['label']}** — `{rendered}`"
            )
        return "\n".join(lines) + "\n"

    def create(
        self,
        definition: dict[str, Any],
        *,
        created_by: UUID,
        audit_fields: dict[str, object],
    ) -> dict[str, Any]:
        result = self.validate(definition)
        if not result["valid"]:
            raise BantamError(
                "INVALID_WORKFLOW",
                "; ".join(error["message"] for error in result["errors"]),
                422,
            )
        normalized = result["normalized"]
        workflow_id = uuid4()
        from psycopg.types.json import Jsonb

        from bantam import audit

        with self.pool.connection() as connection:
            with connection.transaction():
                row = connection.execute(
                    """
                    INSERT INTO workflow_definitions (
                        workflow_id, name, description, actor_role, node_ids,
                        graph_digest, created_by
                    ) VALUES (%s,%s,%s,%s,%s,%s,%s)
                    RETURNING workflow_id, name, description, actor_role,
                              node_ids, graph_digest, created_by,
                              created_at, updated_at
                    """,
                    (
                        workflow_id,
                        normalized["name"],
                        normalized["description"],
                        normalized["actor_role"],
                        Jsonb(normalized["node_ids"]),
                        self.catalog["graph_digest"],
                        created_by,
                    ),
                ).fetchone()
                event = {
                    **audit_fields,
                    "action": "WORKFLOW_CREATED",
                    "resource_type": "workflow_definition",
                    "resource_id": str(workflow_id),
                    "metadata": {
                        "name": normalized["name"],
                        "actor_role": normalized["actor_role"],
                        "node_count": len(normalized["node_ids"]),
                        "graph_digest": self.catalog["graph_digest"],
                    },
                }
                audit.record(connection, **event)
        created = {
            **dict(row),
            "valid": True,
            "stale": False,
            "validation_errors": [],
            "documentation_path": None,
        }
        created["documentation"] = self.render_documentation(created)
        return created


def _write_catalog(root: Path, output: Path) -> None:
    catalog = build_catalog(root)
    output.write_text(_canonical_json(catalog) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build Bantam's deterministic workflow catalogue"
    )
    parser.add_argument("command", choices=("build", "check"))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, default=DEFAULT_CATALOG_PATH)
    arguments = parser.parse_args(argv)
    generated = build_catalog(arguments.root)
    rendered = _canonical_json(generated) + "\n"
    if arguments.command == "build":
        arguments.output.write_text(rendered, encoding="utf-8")
        return 0
    if (
        not arguments.output.is_file()
        or arguments.output.read_text(encoding="utf-8") != rendered
    ):
        print("workflow catalogue is stale; run: python -m bantam.workflow_graph build")
        return 1
    print(f"workflow catalogue is current ({generated['graph_digest'][:12]})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
