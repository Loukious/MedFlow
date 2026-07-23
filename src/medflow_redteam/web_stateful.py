from __future__ import annotations

import hashlib
import json
import re
import secrets
import time
import uuid
import warnings
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
import schemathesis
import yaml
from hypothesis.errors import NonInteractiveExampleWarning
from requests import Response, Session
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from .tools import validate_target


SCHEMA_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/openapi.yml",
    "/swagger.json",
    "/swagger.yaml",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/swagger/v1/swagger.json",
    "/ui/openapi.json",
]
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
AUTH_DENIAL_MARKERS = {
    "access denied",
    "authentication required",
    "authorization required",
    "forbidden",
    "invalid token",
    "login required",
    "missing authorization",
    "missing token",
    "not authorized",
    "permission denied",
    "sign in",
    "unauthorized",
}
SENSITIVE_FIELDS = {
    "accesstoken",
    "admin",
    "apikey",
    "authtoken",
    "credential",
    "email",
    "isadmin",
    "jwt",
    "password",
    "private",
    "role",
    "secret",
    "token",
}
STATE_CHANGING_GET_MARKERS = {
    "bootstrap",
    "create",
    "delete",
    "drop",
    "initialize",
    "logout",
    "populate",
    "reset",
    "send",
    "setup",
    "trigger",
}
OWNER_POLICY_MARKERS = {
    "current user",
    "only owner",
    "only the owner",
    "owner may",
    "private",
    "secret",
}
ADMIN_POLICY_MARKERS = {"admin only", "admins only", "only admin", "only administrators"}
disable_warnings(InsecureRequestWarning)


@dataclass
class ApiOperation:
    method: str
    path: str
    operation_id: str
    summary: str
    description: str
    protected: bool
    path_parameters: list[dict[str, Any]]
    query_parameters: list[dict[str, Any]]
    request_schema: dict[str, Any]
    response_schema: dict[str, Any]
    tags: list[str]
    schemathesis_operation: Any = field(repr=False)

    @property
    def label(self) -> str:
        return f"{self.method} {self.path}"

    @property
    def policy_text(self) -> str:
        return " ".join([self.operation_id, self.summary, self.description, " ".join(self.tags)]).lower()

    @property
    def role(self) -> str:
        if self.method == "POST" and not self.path_parameters:
            return "create"
        if self.method == "GET" and self.path_parameters:
            return "read"
        if self.method == "GET":
            return "list"
        if self.method in {"PUT", "PATCH"}:
            return "update"
        if self.method == "DELETE":
            return "delete"
        return "other"

    @property
    def owner_scoped(self) -> bool:
        return any(marker in self.policy_text for marker in OWNER_POLICY_MARKERS)

    @property
    def admin_only(self) -> bool:
        return any(marker in self.policy_text for marker in ADMIN_POLICY_MARKERS)

    @property
    def safe_read(self) -> bool:
        if self.method not in {"GET", "HEAD"}:
            return False
        tokens = set(re.findall(r"[a-z]+", self.policy_text))
        return not bool(tokens & STATE_CHANGING_GET_MARKERS)


@dataclass
class ApiDocument:
    schema_url: str
    base_url: str
    title: str
    version: str
    raw_schema: dict[str, Any]
    operations: list[ApiOperation]
    schemathesis_schema: Any = field(repr=False)


@dataclass
class Principal:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    owned_object_ids: list[str] = field(default_factory=list)
    identity_values: dict[str, str] = field(default_factory=dict)
    ephemeral: bool = False


@dataclass
class Exchange:
    operation: ApiOperation
    principal: str
    status: int | None
    url: str
    elapsed_ms: float
    response_text: str = ""
    response_json: Any = None
    response_fields: list[str] = field(default_factory=list)
    schema_errors: list[str] = field(default_factory=list)
    error: str = ""
    request_path_parameters: dict[str, Any] = field(default_factory=dict)
    request_body_fields: list[str] = field(default_factory=list)

    @property
    def successful(self) -> bool:
        return self.status is not None and 200 <= self.status < 300 and not looks_like_auth_denial(self.response_text)

    def safe_trace(self) -> dict[str, Any]:
        return {
            "operation": self.operation.label,
            "principal": self.principal,
            "status": self.status,
            "url": safe_url(self.url),
            "elapsed_ms": self.elapsed_ms,
            "response_bytes": len(self.response_text.encode("utf-8", errors="ignore")),
            "response_hash": sha256_short(self.response_text),
            "response_fields": self.response_fields[:40],
            "schema_errors": [redact_secret_text(item) for item in self.schema_errors[:4]],
            "error": redact_secret_text(self.error[:240]),
            "request_path_parameters": {
                key: safe_reference(value) for key, value in self.request_path_parameters.items()
            },
            "request_body_fields": self.request_body_fields,
        }


@dataclass
class RequestBudget:
    maximum: int
    used: int = 0

    @property
    def remaining(self) -> int:
        return self.maximum - self.used

    def consume(self) -> None:
        if self.used >= self.maximum:
            raise BudgetExhausted(f"Stateful API request budget of {self.maximum} was exhausted.")
        self.used += 1


class BudgetExhausted(RuntimeError):
    pass


def run_stateful_api_assessment(
    target: str,
    ports: list[int],
    *,
    observed_urls: list[str] | None = None,
    auth_contexts: list[Any] | None = None,
    execution_mode: str = "safe",
    max_requests: int = 40,
    max_workflows: int = 8,
) -> dict[str, Any]:
    """Run bounded OpenAPI workflows and deterministic cross-principal checks."""
    started = time.monotonic()
    target = validate_target(target)
    max_requests = max(1, min(int(max_requests), 200))
    max_workflows = max(1, min(int(max_workflows), 30))
    supplied_principals = [principal_from_context(item) for item in auth_contexts or []]
    budget = RequestBudget(max_requests)
    discovery = discover_openapi_document(
        target,
        ports,
        observed_urls=observed_urls or [],
        principal=supplied_principals[0] if supplied_principals else None,
        budget=budget,
    )
    document = discovery.get("document")
    if document is None:
        return {
            "enabled": True,
            "status": "no_schema",
            "engine": f"schemathesis/{schemathesis.__version__}",
            "schema_attempts": discovery["attempts"],
            "operations": [],
            "dependencies": [],
            "principals": [safe_principal(item) for item in supplied_principals],
            "workflows": [],
            "request_traces": [],
            "findings": [],
            "request_budget": {"maximum": budget.maximum, "used": budget.used},
            "elapsed_seconds": round(time.monotonic() - started, 3),
        }

    session = Session()
    traces: list[dict[str, Any]] = []
    workflows: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    principals = supplied_principals
    dependencies = build_operation_dependencies(document.operations)

    try:
        if execution_mode == "aggressive_lab" and len(principals) < 2:
            bootstrapped, bootstrap_workflows, bootstrap_traces = bootstrap_principals(
                document,
                session,
                budget,
                count=2 - len(principals),
            )
            principals = [*principals, *bootstrapped]
            workflows.extend(bootstrap_workflows)
            traces.extend(bootstrap_traces)
        read_findings, read_workflows, read_traces = run_read_only_differentials(
            document,
            principals,
            session,
            budget,
            max_workflows=max_workflows,
        )
        findings.extend(read_findings)
        workflows.extend(read_workflows)
        traces.extend(read_traces)
        if execution_mode == "aggressive_lab" and principals:
            write_findings, write_workflows, write_traces = run_stateful_resource_workflows(
                document,
                dependencies,
                principals,
                session,
                budget,
                max_workflows=max_workflows,
            )
            findings.extend(write_findings)
            workflows.extend(write_workflows)
            traces.extend(write_traces)
    except BudgetExhausted as exc:
        errors.append(str(exc))

    findings = dedupe_findings(findings)
    return {
        "enabled": True,
        "status": "completed",
        "engine": f"schemathesis/{schemathesis.__version__}",
        "schema": {
            "url": document.schema_url,
            "base_url": document.base_url,
            "title": document.title,
            "version": document.version,
        },
        "schema_attempts": discovery["attempts"],
        "operations": [operation_summary(item) for item in document.operations],
        "dependencies": dependencies,
        "principals": [safe_principal(item) for item in principals],
        "workflows": workflows[: max_workflows * 3],
        "request_traces": traces,
        "findings": findings,
        "errors": errors,
        "request_budget": {"maximum": budget.maximum, "used": budget.used},
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def discover_openapi_document(
    target: str,
    ports: list[int],
    *,
    observed_urls: list[str],
    principal: Principal | None,
    budget: RequestBudget,
) -> dict[str, Any]:
    candidates: list[str] = []
    for url in observed_urls:
        path = urlparse(url).path.lower()
        if any(marker in path for marker in ["openapi", "swagger", "api-docs"]):
            candidates.append(url)
    for port in ports:
        origin = origin_for_target(target, port)
        candidates.extend(urljoin(origin + "/", path.lstrip("/")) for path in SCHEMA_PATHS)
    candidates = dedupe(candidates)
    headers = {"User-Agent": "MedFlow-StatefulAPI/0.1"}
    cookies: dict[str, str] = {}
    if principal:
        headers.update(principal.headers)
        cookies.update(principal.cookies)
    attempts: list[dict[str, Any]] = []
    for candidate in candidates[:40]:
        if budget.remaining <= 0:
            break
        budget.consume()
        try:
            response = requests.get(
                candidate,
                headers=headers,
                cookies=cookies,
                timeout=5,
                allow_redirects=False,
                verify=False,
            )
            attempts.append(
                {
                    "url": candidate,
                    "status": response.status_code,
                    "content_type": response.headers.get("content-type", "")[:80],
                    "bytes": len(response.content),
                }
            )
            if response.status_code != 200 or len(response.content) > 2 * 1024 * 1024:
                continue
            payload = parse_schema_payload(response.text)
            if not is_openapi_schema(payload):
                continue
            schema = schemathesis.openapi.from_dict(payload)
            operations = extract_operations(payload, schema)
            if not operations:
                continue
            info = payload.get("info") or {}
            return {
                "document": ApiDocument(
                    schema_url=candidate,
                    base_url=schema_base_url(candidate, payload),
                    title=str(info.get("title") or "OpenAPI"),
                    version=str(info.get("version") or payload.get("openapi") or payload.get("swagger") or ""),
                    raw_schema=payload,
                    operations=operations,
                    schemathesis_schema=schema,
                ),
                "attempts": attempts,
            }
        except Exception as exc:
            attempts.append({"url": candidate, "error": f"{type(exc).__name__}: {exc}"[:240]})
    return {"document": None, "attempts": attempts}


def parse_schema_payload(text: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = yaml.safe_load(text)
    return payload if isinstance(payload, dict) else {}


def is_openapi_schema(payload: dict[str, Any]) -> bool:
    return bool(payload.get("paths")) and bool(payload.get("openapi") or payload.get("swagger"))


def extract_operations(raw_schema: dict[str, Any], schema: Any) -> list[ApiOperation]:
    operations: list[ApiOperation] = []
    global_security = raw_schema.get("security") or []
    for result in schema.get_all_operations():
        try:
            operation = result.ok()
        except Exception:
            continue
        raw_operation = operation.definition.raw
        path_item = (raw_schema.get("paths") or {}).get(operation.path) or {}
        parameters = [*(path_item.get("parameters") or []), *(raw_operation.get("parameters") or [])]
        path_parameters = [
            resolve_local_ref(raw_schema, item)
            for item in parameters
            if isinstance(item, dict) and item.get("in") == "path"
        ]
        query_parameters = [
            resolve_local_ref(raw_schema, item)
            for item in parameters
            if isinstance(item, dict) and item.get("in") == "query"
        ]
        request_schema = request_body_schema(raw_schema, raw_operation)
        response_schema = successful_response_schema(raw_schema, raw_operation)
        security = raw_operation["security"] if "security" in raw_operation else global_security
        operations.append(
            ApiOperation(
                method=str(operation.method).upper(),
                path=str(operation.path),
                operation_id=str(raw_operation.get("operationId") or operation.label),
                summary=str(raw_operation.get("summary") or ""),
                description=str(raw_operation.get("description") or ""),
                protected=bool(security),
                path_parameters=path_parameters,
                query_parameters=query_parameters,
                request_schema=request_schema,
                response_schema=response_schema,
                tags=[str(item) for item in raw_operation.get("tags") or []],
                schemathesis_operation=operation,
            )
        )
    return sorted(operations, key=lambda item: (item.path, item.method))


def request_body_schema(raw_schema: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any]:
    request_body = resolve_local_ref(raw_schema, operation.get("requestBody") or {})
    content = request_body.get("content") or {}
    for media_type in ["application/json", "application/*+json"]:
        if media_type in content:
            return resolve_local_ref(raw_schema, (content[media_type] or {}).get("schema") or {})
    for parameter in operation.get("parameters") or []:
        if isinstance(parameter, dict) and parameter.get("in") == "body":
            return resolve_local_ref(raw_schema, parameter.get("schema") or {})
    return {}


def successful_response_schema(raw_schema: dict[str, Any], operation: dict[str, Any]) -> dict[str, Any]:
    responses = operation.get("responses") or {}
    for status, response in responses.items():
        if not str(status).startswith("2"):
            continue
        resolved = resolve_local_ref(raw_schema, response or {})
        content = resolved.get("content") or {}
        for media_type, media in content.items():
            if "json" in str(media_type):
                return resolve_local_ref(raw_schema, (media or {}).get("schema") or {})
        if resolved.get("schema"):
            return resolve_local_ref(raw_schema, resolved["schema"])
    return {}


def resolve_local_ref(document: dict[str, Any], value: Any, depth: int = 0) -> Any:
    if depth > 12 or not isinstance(value, dict):
        return value
    reference = value.get("$ref")
    if isinstance(reference, str) and reference.startswith("#/"):
        resolved: Any = document
        for part in reference[2:].split("/"):
            resolved = resolved.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(resolved, dict) else {}
        return resolve_local_ref(document, resolved, depth + 1)
    return {
        key: resolve_local_ref(document, nested, depth + 1)
        if isinstance(nested, dict)
        else [resolve_local_ref(document, item, depth + 1) for item in nested]
        if isinstance(nested, list)
        else nested
        for key, nested in value.items()
    }


def build_operation_dependencies(operations: list[ApiOperation]) -> list[dict[str, Any]]:
    dependencies: list[dict[str, Any]] = []
    creators = [item for item in operations if item.role == "create"]
    consumers = [item for item in operations if item.role in {"read", "update", "delete"} and item.path_parameters]
    for creator in creators:
        creator_collection = collection_path(creator.path)
        for consumer in consumers:
            if collection_path(consumer.path) != creator_collection:
                continue
            parameter = str(consumer.path_parameters[0].get("name") or "")
            dependencies.append(
                {
                    "producer": creator.label,
                    "consumer": consumer.label,
                    "resource": creator_collection,
                    "parameter": parameter,
                    "relationship": "response_or_request_value",
                }
            )
    return dependencies


def run_read_only_differentials(
    document: ApiDocument,
    principals: list[Principal],
    session: Session,
    budget: RequestBudget,
    *,
    max_workflows: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    workflows: list[dict[str, Any]] = []
    traces: list[dict[str, Any]] = []
    owner = principals[0] if principals else None
    alternate = principals[1] if len(principals) > 1 else None
    anonymous = Principal(name="anonymous")
    workflow_count = 0
    for operation in document.operations:
        if workflow_count >= max_workflows or not operation.safe_read or not operation.protected:
            continue
        path_values = candidate_path_values(operation, owner)
        if operation.path_parameters and not path_values:
            continue
        owner_exchange = send_operation(
            document,
            operation,
            owner or anonymous,
            session,
            budget,
            path_parameters=path_values,
        )
        traces.append(owner_exchange.safe_trace())
        if not owner_exchange.successful:
            continue
        workflow: dict[str, Any] = {
            "kind": "read_only_auth_differential",
            "operation": operation.label,
            "steps": [owner_exchange.safe_trace()],
            "result": "no_finding",
        }
        if alternate:
            alternate_exchange = send_operation(
                document,
                operation,
                alternate,
                session,
                budget,
                path_parameters=path_values,
            )
            traces.append(alternate_exchange.safe_trace())
            workflow["steps"].append(alternate_exchange.safe_trace())
            owned_reference = any(str(value) in owner.owned_object_ids for value in path_values.values()) if owner else False
            if owned_reference and confirms_cross_principal_access(operation, owner_exchange, alternate_exchange):
                repeat = send_operation(
                    document,
                    operation,
                    alternate,
                    session,
                    budget,
                    path_parameters=path_values,
                )
                traces.append(repeat.safe_trace())
                workflow["steps"].append(repeat.safe_trace())
                if repeat.successful:
                    findings.append(
                        cross_principal_finding(operation, owner_exchange, alternate_exchange, repeat, path_values)
                    )
                    workflow["result"] = "confirmed_vulnerability"
        anonymous_exchange = send_operation(
            document,
            operation,
            anonymous,
            session,
            budget,
            path_parameters=path_values,
        )
        traces.append(anonymous_exchange.safe_trace())
        workflow["steps"].append(anonymous_exchange.safe_trace())
        if confirms_ignored_auth(owner_exchange, anonymous_exchange):
            repeat = send_operation(
                document,
                operation,
                anonymous,
                session,
                budget,
                path_parameters=path_values,
            )
            traces.append(repeat.safe_trace())
            workflow["steps"].append(repeat.safe_trace())
            if repeat.successful:
                findings.append(ignored_auth_finding(operation, owner_exchange, anonymous_exchange, repeat))
                workflow["result"] = "confirmed_vulnerability"
        workflows.append(workflow)
        workflow_count += 1
    return findings, workflows, traces


def run_stateful_resource_workflows(
    document: ApiDocument,
    dependencies: list[dict[str, Any]],
    principals: list[Principal],
    session: Session,
    budget: RequestBudget,
    *,
    max_workflows: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    workflows: list[dict[str, Any]] = []
    traces: list[dict[str, Any]] = []
    owner = principals[0]
    alternate = principals[1] if len(principals) > 1 else None
    operation_by_label = {item.label: item for item in document.operations}
    grouped: dict[str, list[dict[str, Any]]] = {}
    for dependency in dependencies:
        grouped.setdefault(dependency["producer"], []).append(dependency)
    for producer_label, edges in list(grouped.items())[:max_workflows]:
        read_edges = [
            edge
            for edge in edges
            if operation_by_label[edge["consumer"]].role == "read"
        ]
        cleanup_edge = next(
            (
                edge
                for edge in edges
                if operation_by_label[edge["consumer"]].role == "delete"
            ),
            None,
        )
        if not read_edges:
            continue
        read_request_reserve = 5 if alternate else 3
        minimum_requests = 1 + read_request_reserve + (1 if cleanup_edge else 0)
        if budget.remaining < minimum_requests:
            break
        creator = operation_by_label[producer_label]
        if creator.method not in WRITE_METHODS or not creator.request_schema:
            continue
        body = synthesize_object(creator.request_schema, role=owner.name, purpose="resource")
        create_exchange = send_operation(
            document,
            creator,
            owner,
            session,
            budget,
            body=body,
        )
        traces.append(create_exchange.safe_trace())
        workflow: dict[str, Any] = {
            "kind": "create_access_cleanup",
            "producer": creator.label,
            "steps": [create_exchange.safe_trace()],
            "result": "create_failed",
            "cleanup": "not_required",
        }
        if not create_exchange.successful:
            workflows.append(workflow)
            continue
        workflow["result"] = "created"
        cleanup_operation = operation_by_label[cleanup_edge["consumer"]] if cleanup_edge else None
        cleanup_reference: str | None = None
        if cleanup_edge:
            cleanup_reference = extract_resource_reference(
                cleanup_edge["parameter"],
                create_exchange.response_json,
                body,
            )
        for dependency in read_edges:
            cleanup_reserve = 1 if cleanup_operation and cleanup_reference else 0
            if budget.remaining < read_request_reserve + cleanup_reserve:
                break
            consumer = operation_by_label[dependency["consumer"]]
            parameter_name = dependency["parameter"]
            reference = extract_resource_reference(
                parameter_name,
                create_exchange.response_json,
                body,
            )
            if reference is None:
                continue
            path_parameters = {parameter_name: reference}
            owner_read = send_operation(
                document,
                consumer,
                owner,
                session,
                budget,
                path_parameters=path_parameters,
            )
            traces.append(owner_read.safe_trace())
            workflow["steps"].append(owner_read.safe_trace())
            if not owner_read.successful:
                continue
            if alternate:
                alternate_read = send_operation(
                    document,
                    consumer,
                    alternate,
                    session,
                    budget,
                    path_parameters=path_parameters,
                )
                traces.append(alternate_read.safe_trace())
                workflow["steps"].append(alternate_read.safe_trace())
                if confirms_cross_principal_access(consumer, owner_read, alternate_read):
                    repeat = send_operation(
                        document,
                        consumer,
                        alternate,
                        session,
                        budget,
                        path_parameters=path_parameters,
                    )
                    traces.append(repeat.safe_trace())
                    workflow["steps"].append(repeat.safe_trace())
                    if repeat.successful:
                        findings.append(
                            cross_principal_finding(
                                consumer,
                                owner_read,
                                alternate_read,
                                repeat,
                                path_parameters,
                                created_in_workflow=True,
                            )
                        )
                        workflow["result"] = "confirmed_vulnerability"
            anonymous = Principal(name="anonymous")
            anonymous_read = send_operation(
                document,
                consumer,
                anonymous,
                session,
                budget,
                path_parameters=path_parameters,
            )
            traces.append(anonymous_read.safe_trace())
            workflow["steps"].append(anonymous_read.safe_trace())
            if confirms_ignored_auth(owner_read, anonymous_read):
                repeat = send_operation(
                    document,
                    consumer,
                    anonymous,
                    session,
                    budget,
                    path_parameters=path_parameters,
                )
                traces.append(repeat.safe_trace())
                workflow["steps"].append(repeat.safe_trace())
                if repeat.successful:
                    findings.append(ignored_auth_finding(consumer, owner_read, anonymous_read, repeat))
                    workflow["result"] = "confirmed_vulnerability"
        if cleanup_operation and cleanup_reference:
            cleanup_parameter = str(cleanup_operation.path_parameters[0].get("name") or "")
            cleanup = send_operation(
                document,
                cleanup_operation,
                owner,
                session,
                budget,
                path_parameters={cleanup_parameter: cleanup_reference},
            )
            traces.append(cleanup.safe_trace())
            workflow["steps"].append(cleanup.safe_trace())
            workflow["cleanup"] = "verified" if cleanup.successful else "failed"
        else:
            workflow["cleanup"] = "not_available"
        workflows.append(workflow)
    return findings, workflows, traces


def bootstrap_principals(
    document: ApiDocument,
    session: Session,
    budget: RequestBudget,
    *,
    count: int,
) -> tuple[list[Principal], list[dict[str, Any]], list[dict[str, Any]]]:
    register = find_semantic_operation(document.operations, {"register", "signup", "sign up"}, method="POST")
    login = find_semantic_operation(document.operations, {"login", "signin", "sign in", "token"}, method="POST")
    if register is None or login is None or not register.request_schema or not login.request_schema:
        return [], [], []
    principals: list[Principal] = []
    workflows: list[dict[str, Any]] = []
    traces: list[dict[str, Any]] = []
    for index in range(count):
        if budget.remaining < 2:
            break
        role = f"medflow_user_{index + 1}"
        identity = identity_values(register.request_schema, role)
        register_body = synthesize_object(register.request_schema, role=role, purpose="identity", known=identity)
        anonymous = Principal(name="anonymous")
        registered = send_operation(document, register, anonymous, session, budget, body=register_body)
        traces.append(registered.safe_trace())
        workflow: dict[str, Any] = {
            "kind": "ephemeral_identity_bootstrap",
            "principal": role,
            "steps": [registered.safe_trace()],
            "result": "registration_failed",
        }
        if not registered.successful:
            workflows.append(workflow)
            continue
        login_body = synthesize_object(login.request_schema, role=role, purpose="login", known=identity)
        logged_in = send_operation(document, login, anonymous, session, budget, body=login_body)
        traces.append(logged_in.safe_trace())
        workflow["steps"].append(logged_in.safe_trace())
        token = extract_token(logged_in.response_json)
        if not logged_in.successful or not token:
            workflow["result"] = "login_failed"
            workflows.append(workflow)
            continue
        headers, cookies = token_auth(document.raw_schema, token)
        owned_ids = [
            value
            for key, value in identity.items()
            if normalized_name(key) in {"name", "user", "username", "userid", "user_id"}
        ]
        principals.append(
            Principal(
                name=role,
                headers=headers,
                cookies=cookies,
                owned_object_ids=owned_ids,
                identity_values=identity,
                ephemeral=True,
            )
        )
        workflow["result"] = "authenticated"
        workflows.append(workflow)
    return principals, workflows, traces


def send_operation(
    document: ApiDocument,
    operation: ApiOperation,
    principal: Principal,
    session: Session,
    budget: RequestBudget,
    *,
    path_parameters: dict[str, Any] | None = None,
    body: Any = None,
) -> Exchange:
    budget.consume()
    started = time.monotonic()
    path_parameters = path_parameters or {}
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", NonInteractiveExampleWarning)
            case = operation.schemathesis_operation.as_strategy().example()
        case.headers = {}
        case.cookies = {}
        if path_parameters:
            case.path_parameters = {**(case.path_parameters or {}), **path_parameters}
        if body is not None:
            case.body = body
            case.media_type = "application/json"
        response = case.call(
            base_url=document.base_url,
            session=session,
            headers=dict(principal.headers),
            cookies=dict(principal.cookies),
            timeout=6,
            allow_redirects=False,
            verify=False,
        )
        response_text = bounded_response_text(response)
        payload = response_json(response)
        schema_errors: list[str] = []
        try:
            case.validate_response(response)
        except (Exception, BaseExceptionGroup) as exc:
            schema_errors.extend(schema_failure_types(exc))
        return Exchange(
            operation=operation,
            principal=principal.name,
            status=response.status_code,
            url=response.request.url,
            elapsed_ms=round((time.monotonic() - started) * 1000, 2),
            response_text=response_text,
            response_json=payload,
            response_fields=sorted(json_field_names(payload)),
            schema_errors=schema_errors,
            request_path_parameters=case.path_parameters or {},
            request_body_fields=sorted(body.keys()) if isinstance(body, dict) else [],
        )
    except Exception as exc:
        return Exchange(
            operation=operation,
            principal=principal.name,
            status=None,
            url=materialize_url(document.base_url, operation.path, path_parameters),
            elapsed_ms=round((time.monotonic() - started) * 1000, 2),
            error=f"{type(exc).__name__}: {exc}",
            request_path_parameters=path_parameters,
            request_body_fields=sorted(body.keys()) if isinstance(body, dict) else [],
        )


def candidate_path_values(operation: ApiOperation, owner: Principal | None) -> dict[str, Any]:
    values: dict[str, Any] = {}
    owned = list(owner.owned_object_ids) if owner else []
    for index, parameter in enumerate(operation.path_parameters):
        name = str(parameter.get("name") or "")
        schema = parameter.get("schema") or {}
        if index < len(owned):
            values[name] = owned[index]
        elif "example" in schema:
            values[name] = schema["example"]
        elif "default" in schema:
            values[name] = schema["default"]
        elif schema.get("enum"):
            values[name] = schema["enum"][0]
    return values


def confirms_cross_principal_access(
    operation: ApiOperation,
    owner: Exchange,
    alternate: Exchange,
) -> bool:
    if not owner.successful or not alternate.successful:
        return False
    if not (operation.owner_scoped or sensitive_response(operation, owner)):
        return False
    return materially_equivalent(owner, alternate)


def confirms_ignored_auth(owner: Exchange, anonymous: Exchange) -> bool:
    return owner.successful and anonymous.successful and materially_equivalent(owner, anonymous)


def materially_equivalent(left: Exchange, right: Exchange) -> bool:
    shared_fields = set(left.response_fields) & set(right.response_fields)
    if shared_fields & SENSITIVE_FIELDS:
        return True
    similarity = response_similarity(left.response_text, right.response_text)
    if left.response_json is not None and right.response_json is not None:
        if json_shape(left.response_json) == json_shape(right.response_json) and similarity >= 0.65:
            return True
    return similarity >= 0.90


def cross_principal_finding(
    operation: ApiOperation,
    owner: Exchange,
    alternate: Exchange,
    repeat: Exchange,
    path_parameters: dict[str, Any],
    *,
    created_in_workflow: bool = False,
) -> dict[str, Any]:
    reference = ", ".join(f"{key}={safe_reference(value)}" for key, value in path_parameters.items())
    confidence = "high" if created_in_workflow or operation.owner_scoped else "medium"
    return {
        "type": "bola_stateful_confirmed",
        "severity": "high",
        "confidence": confidence,
        "url": materialize_url_from_exchange(owner),
        "parameter": ",".join(path_parameters),
        "evidence": (
            f"A resource associated with {owner.principal} ({reference}) was returned to "
            f"{alternate.principal} twice with HTTP {alternate.status}/{repeat.status}."
        ),
        "proof": (
            f"Replay sequence: {owner.operation.label} as {owner.principal}, then the same object as "
            f"{alternate.principal} twice. Shared response fields: "
            f"{', '.join(sorted(set(owner.response_fields) & set(alternate.response_fields))[:12]) or 'same JSON shape'}."
        ),
        "cwe": "CWE-639",
        "owasp": "API1:2023-Broken Object Level Authorization",
        "status": "confirmed_vulnerability",
    }


def ignored_auth_finding(
    operation: ApiOperation,
    owner: Exchange,
    anonymous: Exchange,
    repeat: Exchange,
) -> dict[str, Any]:
    proof = (
        "Authenticated baseline and two anonymous replays returned the same JSON shape or shared "
        "sensitive response fields."
        if owner.principal != "anonymous"
        else "Three anonymous requests returned materially equivalent data from an operation marked as protected."
    )
    return {
        "type": "ignored_api_authentication",
        "severity": "high",
        "confidence": "high",
        "url": materialize_url_from_exchange(owner),
        "parameter": "",
        "evidence": (
            f"OpenAPI marks {operation.label} as protected, but anonymous requests returned "
            f"HTTP {anonymous.status} and {repeat.status} with materially equivalent data."
        ),
        "proof": proof,
        "cwe": "CWE-306",
        "owasp": "API2:2023-Broken Authentication",
        "status": "confirmed_vulnerability",
    }


def sensitive_response(operation: ApiOperation, exchange: Exchange) -> bool:
    schema_fields = schema_property_names(operation.response_schema)
    return bool((schema_fields | set(exchange.response_fields)) & SENSITIVE_FIELDS)


def synthesize_object(
    schema: dict[str, Any],
    *,
    role: str,
    purpose: str,
    known: dict[str, str] | None = None,
) -> dict[str, Any]:
    known = known or {}
    properties = schema.get("properties") or {}
    output: dict[str, Any] = {}
    for name, property_schema in list(properties.items())[:20]:
        normalized = normalized_name(name)
        known_value = lookup_known_value(known, normalized)
        if known_value is not None:
            output[name] = known_value
        else:
            output[name] = synthesize_value(property_schema or {}, name, role, purpose)
    return output


def synthesize_value(schema: dict[str, Any], name: str, role: str, purpose: str) -> Any:
    normalized = normalized_name(name)
    suffix = secrets.token_hex(4)
    if normalized in {"username", "user", "userid", "user_id", "login"}:
        return f"{safe_slug(role)}_{suffix}"
    if "password" in normalized or normalized in {"pass", "passwd"}:
        return f"Mf!{suffix}Aa9"
    if "email" in normalized:
        return f"{safe_slug(role)}_{suffix}@example.test"
    if "secret" in normalized:
        return f"MEDFLOW_PROOF_{suffix}"
    if normalized in {"admin", "isadmin", "superuser", "issuperuser"}:
        return False
    if normalized in {"role", "roles", "userrole"}:
        enum = schema.get("enum") or []
        ordinary = next(
            (value for value in enum if str(value).lower() in {"basic", "member", "standard", "user"}),
            None,
        )
        if ordinary is not None:
            return ordinary
        return [] if schema.get("type") == "array" else "user"
    if any(marker in normalized for marker in ["title", "name", "slug"]):
        return f"medflow-{safe_slug(role)}-{suffix}"
    if schema.get("example") is not None:
        example = schema["example"]
        if isinstance(example, str) and purpose in {"identity", "resource"}:
            return f"{example[:30]}-{suffix}"
        return example
    if schema.get("default") is not None:
        return schema["default"]
    if schema.get("enum"):
        return schema["enum"][0]
    value_type = schema.get("type")
    value_format = schema.get("format")
    if value_format == "uuid":
        return str(uuid.uuid4())
    if value_format in {"date", "date-time"}:
        return "2030-01-01" if value_format == "date" else "2030-01-01T00:00:00Z"
    if value_type == "integer":
        return int(schema.get("minimum", 1))
    if value_type == "number":
        return float(schema.get("minimum", 1.0))
    if value_type == "boolean":
        return False
    if value_type == "array":
        return [synthesize_value(schema.get("items") or {}, name, role, purpose)]
    if value_type == "object":
        return synthesize_object(schema, role=role, purpose=purpose)
    return f"medflow-{safe_slug(role)}-{suffix}"


def identity_values(schema: dict[str, Any], role: str) -> dict[str, str]:
    return {
        name: str(synthesize_value(property_schema or {}, name, role, "identity"))
        for name, property_schema in (schema.get("properties") or {}).items()
    }


def extract_resource_reference(parameter_name: str, response_payload: Any, request_body: dict[str, Any]) -> str | None:
    aliases = name_aliases(parameter_name)
    for key, value in request_body.items():
        if normalized_name(key) in aliases and scalar_reference(value):
            return str(value)
    for key, value in walk_json_items(response_payload):
        if normalized_name(key) in aliases and scalar_reference(value):
            return str(value)
    return None


def extract_token(payload: Any) -> str | None:
    for key, value in walk_json_items(payload):
        normalized = normalized_name(key)
        if any(marker in normalized for marker in ["accesstoken", "authtoken", "bearertoken", "jwt", "token"]):
            if isinstance(value, str) and len(value) >= 12:
                return value
    return None


def token_auth(schema: dict[str, Any], token: str) -> tuple[dict[str, str], dict[str, str]]:
    schemes = ((schema.get("components") or {}).get("securitySchemes") or {})
    for definition in schemes.values():
        resolved = resolve_local_ref(schema, definition)
        if resolved.get("type") == "apiKey":
            location = resolved.get("in")
            name = str(resolved.get("name") or "X-API-Key")
            if location == "cookie":
                return {}, {name: token}
            return {name: token}, {}
        if resolved.get("type") == "http" and str(resolved.get("scheme")).lower() == "bearer":
            return {"Authorization": f"Bearer {token}"}, {}
    return {"Authorization": f"Bearer {token}"}, {}


def principal_from_context(context: Any) -> Principal:
    headers = {str(key): str(value) for key, value in getattr(context, "headers", {}).items()}
    cookies = {str(key): str(value) for key, value in getattr(context, "cookies", {}).items()}
    return Principal(
        name=str(getattr(context, "name", "principal")),
        headers=headers,
        cookies=cookies,
        owned_object_ids=[str(value) for value in getattr(context, "owned_object_ids", [])],
    )


def safe_principal(principal: Principal) -> dict[str, Any]:
    return {
        "name": principal.name,
        "header_names": sorted(principal.headers),
        "cookie_names": sorted(principal.cookies),
        "owned_object_ids": [safe_reference(value) for value in principal.owned_object_ids],
        "ephemeral": principal.ephemeral,
    }


def operation_summary(operation: ApiOperation) -> dict[str, Any]:
    return {
        "label": operation.label,
        "operation_id": operation.operation_id,
        "summary": operation.summary,
        "protected": operation.protected,
        "role": operation.role,
        "path_parameters": [str(item.get("name") or "") for item in operation.path_parameters],
        "request_fields": sorted((operation.request_schema.get("properties") or {}).keys()),
        "response_fields": sorted(schema_property_names(operation.response_schema)),
        "owner_scoped": operation.owner_scoped,
        "admin_only": operation.admin_only,
    }


def find_semantic_operation(
    operations: list[ApiOperation],
    markers: set[str],
    *,
    method: str,
) -> ApiOperation | None:
    ranked = []
    for operation in operations:
        if operation.method != method:
            continue
        text = operation.policy_text.replace("_", " ")
        score = sum(1 for marker in markers if marker in text)
        if score:
            ranked.append((score, operation))
    return max(ranked, key=lambda item: item[0])[1] if ranked else None


def schema_base_url(schema_url: str, schema: dict[str, Any]) -> str:
    parsed_schema = urlparse(schema_url)
    origin = f"{parsed_schema.scheme}://{parsed_schema.netloc}"
    base_path = ""
    if schema.get("openapi"):
        servers = schema.get("servers") or []
        if servers:
            configured = str((servers[0] or {}).get("url") or "")
            if configured:
                base_path = urlparse(configured).path
    elif schema.get("swagger"):
        base_path = str(schema.get("basePath") or "")
    return origin + ("/" + base_path.strip("/") if base_path.strip("/") else "")


def origin_for_target(target: str, port: int) -> str:
    scheme = "https" if int(port) in {443, 8443} else "http"
    default_port = (scheme == "http" and int(port) == 80) or (scheme == "https" and int(port) == 443)
    return f"{scheme}://{target}" if default_port else f"{scheme}://{target}:{int(port)}"


def collection_path(path: str) -> str:
    parts = [part for part in path.strip("/").split("/") if part]
    concrete = []
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            break
        concrete.append(part)
    return "/" + "/".join(concrete)


def materialize_url(base_url: str, path: str, values: dict[str, Any]) -> str:
    rendered = path
    for key, value in values.items():
        rendered = rendered.replace("{" + key + "}", requests.utils.quote(str(value), safe=""))
    return urljoin(base_url.rstrip("/") + "/", rendered.lstrip("/"))


def materialize_url_from_exchange(exchange: Exchange) -> str:
    return exchange.url.split("?", 1)[0]


def bounded_response_text(response: Response) -> str:
    return response.content[:65536].decode(response.encoding or "utf-8", errors="replace")


def response_json(response: Response) -> Any:
    try:
        return response.json()
    except (ValueError, requests.JSONDecodeError):
        return None


def json_field_names(value: Any) -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            fields.add(normalized_name(key))
            fields.update(json_field_names(nested))
    elif isinstance(value, list):
        for item in value[:100]:
            fields.update(json_field_names(item))
    return fields


def schema_property_names(schema: Any) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    fields = {normalized_name(name) for name in (schema.get("properties") or {})}
    for nested in (schema.get("properties") or {}).values():
        fields.update(schema_property_names(nested))
    fields.update(schema_property_names(schema.get("items")))
    for keyword in ("allOf", "anyOf", "oneOf"):
        for nested in schema.get(keyword) or []:
            fields.update(schema_property_names(nested))
    return fields


def schema_failure_types(exc: BaseException) -> list[str]:
    pending = [exc]
    names: set[str] = set()
    while pending:
        current = pending.pop()
        nested = getattr(current, "exceptions", ())
        if nested:
            pending.extend(nested)
        else:
            names.add(type(current).__name__)
    return sorted(names) or [type(exc).__name__]


def json_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): json_shape(nested) for key, nested in sorted(value.items())}
    if isinstance(value, list):
        return [json_shape(value[0])] if value else []
    return type(value).__name__


def response_similarity(left: str, right: str) -> float:
    left_normalized = normalize_response(left)
    right_normalized = normalize_response(right)
    if not left_normalized or not right_normalized:
        return 0.0
    return SequenceMatcher(None, left_normalized, right_normalized).ratio()


def normalize_response(value: str) -> str:
    value = re.sub(r"\s+", " ", value.lower())
    value = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<uuid>", value)
    value = re.sub(r"\b\d{8,}\b", "<number>", value)
    return value[:16000]


def looks_like_auth_denial(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in AUTH_DENIAL_MARKERS)


def walk_json_items(value: Any) -> list[tuple[str, Any]]:
    output: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            output.append((str(key), nested))
            output.extend(walk_json_items(nested))
    elif isinstance(value, list):
        for nested in value[:100]:
            output.extend(walk_json_items(nested))
    return output


def lookup_known_value(known: dict[str, str], normalized: str) -> str | None:
    aliases = name_aliases(normalized)
    for key, value in known.items():
        if normalized_name(key) in aliases:
            return value
    return None


def name_aliases(value: str) -> set[str]:
    normalized = normalized_name(value)
    aliases = {normalized}
    for suffix in ["id", "title", "name"]:
        if normalized.endswith(suffix) and len(normalized) > len(suffix):
            aliases.add(normalized[: -len(suffix)])
    if normalized in {"book", "booktitle"}:
        aliases.update({"book", "booktitle", "title"})
    if normalized in {"user", "userid", "username"}:
        aliases.update({"user", "userid", "username", "name"})
    return aliases


def normalized_name(value: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value).lower())


def scalar_reference(value: Any) -> bool:
    return isinstance(value, (str, int)) and bool(str(value))


def safe_reference(value: Any) -> str:
    text = str(value)
    if len(text) <= 80 and not looks_secret(text):
        return text
    return f"sha256:{sha256_short(text)}"


def looks_secret(value: str) -> bool:
    return len(value) > 80 or value.count(".") == 2 or value.lower().startswith(("bearer ", "eyj"))


def sha256_short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def safe_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:30] or "principal"


def dedupe(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    output = []
    for finding in findings:
        key = (
            str(finding.get("type") or ""),
            str(finding.get("url") or ""),
            str(finding.get("parameter") or ""),
        )
        if key not in seen:
            seen.add(key)
            output.append(finding)
    return output


def safe_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.query:
        return value
    query_names = [
        part.split("=", 1)[0]
        for part in parsed.query.split("&")
        if part.split("=", 1)[0]
    ]
    query = "&".join(f"{name}=<redacted>" for name in query_names)
    return parsed._replace(query=query).geturl()


def redact_secret_text(value: str) -> str:
    value = re.sub(
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        "<redacted-jwt>",
        value,
    )
    return re.sub(
        r'(?i)("?(?:access_token|auth_token|token|password|secret)"?\s*[:=]\s*")[^"]+(")',
        r"\1<redacted>\2",
        value,
    )
