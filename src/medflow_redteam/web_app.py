from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from difflib import SequenceMatcher
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from medflow_graph.memory import GraphStore
from medflow_ti.config import ROOT, load_settings

from .tools import validate_target
from .web_browser import collect_browser_observations
from .web_executor import execute_planned_probes
from .web_kb import query_web_appsec
from .web_reasoner import assess_web_observations, plan_web_probes
from .web_stateful import run_stateful_api_assessment


DEFAULT_PATHS = ["/"]
GRAPH_PATH = ROOT / "data" / "graph" / "web_observation_graph.json"
MAX_SCRIPT_ASSETS = 6
MAX_HTML_BYTES = 32768
MAX_SCRIPT_BYTES = 2 * 1024 * 1024
MAX_API_DESCRIPTION_BYTES = 512 * 1024


@dataclass
class WebParam:
    name: str
    location: str
    value: str = ""
    classifications: list[str] = field(default_factory=list)


@dataclass
class WebAuthContext:
    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    owned_object_ids: list[str] = field(default_factory=list)


@dataclass
class WebRoute:
    url: str
    method: str = "GET"
    status: int | None = None
    title: str = ""
    content_type: str = ""
    content_length: int = 0
    body_hash: str = ""
    response_signals: list[str] = field(default_factory=list)
    params: list[WebParam] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class WebFinding:
    type: str
    severity: str
    confidence: str
    url: str
    parameter: str = ""
    evidence: str = ""
    proof: str = ""
    cwe: str = ""
    owasp: str = ""
    status: str = "suspected"


@dataclass
class WebAssessment:
    target: str
    ports: list[int]
    routes: list[WebRoute]
    findings: list[WebFinding]
    browser_observations: dict[str, Any]
    planned_probes: list[dict[str, Any]]
    probe_results: list[dict[str, Any]]
    stateful_api: dict[str, Any]
    kb_context: list[dict[str, Any]]
    auth_contexts: list[dict[str, Any]]
    graph_summary: dict[str, int]
    elapsed_seconds: float


class LinkFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self._in_title = False
        self.title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self._in_title = True
        if tag.lower() in {"a", "link", "script"}:
            href = attr.get("href") or attr.get("src")
            if href:
                self.links.append(href)
        if tag.lower() == "form":
            self._current_form = {
                "method": (attr.get("method") or "GET").upper(),
                "action": attr.get("action") or "",
                "inputs": [],
            }
        if tag.lower() in {"input", "textarea", "select"} and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": attr.get("name") or "",
                    "type": attr.get("type") or tag.lower(),
                    "value": attr.get("value") or "",
                }
            )

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)

    @property
    def title(self) -> str:
        return re.sub(r"\s+", " ", " ".join(self.title_parts)).strip()


def run_web_assessment(
    target: str,
    ports: list[int],
    *,
    paths: list[str] | None = None,
    max_depth: int = 1,
    max_routes: int = 30,
    graph_path: Path = GRAPH_PATH,
    use_kb: bool = True,
    auth_contexts: list[WebAuthContext] | None = None,
    provider: str = "gpt_oss",
    use_llm: bool = False,
    stateful_api: bool = False,
    execution_mode: str = "safe",
    stateful_max_requests: int = 40,
    stateful_max_workflows: int = 8,
) -> dict[str, Any]:
    started = time.monotonic()
    target = validate_target(target)
    auth_contexts = auth_contexts or []
    primary_context = auth_contexts[0] if auth_contexts else None
    routes = crawl_web(target, ports, paths=paths, max_depth=max_depth, max_routes=max_routes, auth_context=primary_context)
    browser_observations = (
        collect_browser_observations([route.url for route in routes if route.status and 200 <= route.status < 300])
        if use_llm or stateful_api
        else {"available": False, "reason": "Browser collection disabled."}
    )
    planned_probes = plan_web_probes(web_planning_context(routes, browser_observations), provider) if use_llm else []
    probe_results = execute_planned_probes(planned_probes, web_observations(routes), auth_headers=auth_headers(primary_context)) if planned_probes else []
    stateful_result = (
        run_stateful_api_assessment(
            target,
            ports,
            observed_urls=[
                *[route.url for route in routes],
                *[
                    str(item.get("url") or "")
                    for item in browser_observations.get("requests", [])
                    if item.get("url")
                ],
            ],
            auth_contexts=auth_contexts,
            execution_mode=execution_mode,
            max_requests=stateful_max_requests,
            max_workflows=stateful_max_workflows,
        )
        if stateful_api
        else {"enabled": False, "status": "disabled", "findings": [], "request_traces": []}
    )
    findings = run_safe_web_probes(
        routes,
        provider=provider,
        use_llm=use_llm,
        probe_results=probe_results,
    )
    findings.extend(WebFinding(**item) for item in stateful_result.get("findings", []))
    if len(auth_contexts) >= 2:
        findings.extend(run_idor_confirmation(routes, auth_contexts[0], auth_contexts[1]))
        findings = dedupe_findings(findings)
    kb_context = retrieve_web_context(routes, findings) if use_kb else []
    findings = dedupe_findings(findings)
    graph = persist_web_observation_graph(
        target,
        ports,
        routes,
        findings,
        graph_path,
        stateful_api=stateful_result,
    )
    assessment = WebAssessment(
        target=target,
        ports=ports,
        routes=routes,
        findings=findings,
        browser_observations=browser_observations,
        planned_probes=planned_probes,
        probe_results=probe_results,
        stateful_api=stateful_result,
        kb_context=kb_context,
        auth_contexts=[redact_auth_context(context) for context in auth_contexts],
        graph_summary=graph.summary(),
        elapsed_seconds=round(time.monotonic() - started, 3),
    )
    return asdict(assessment)


def crawl_web(
    target: str,
    ports: list[int],
    *,
    paths: list[str] | None = None,
    max_depth: int = 1,
    max_routes: int = 30,
    auth_context: WebAuthContext | None = None,
) -> list[WebRoute]:
    queue: list[tuple[str, int]] = []
    for port in ports:
        base = base_url(target, port)
        for path in paths or DEFAULT_PATHS:
            queue.append((urljoin(base, path.lstrip("/")), 0))
    seen: set[str] = set()
    routes: list[WebRoute] = []
    while queue and len(routes) < max_routes:
        url, depth = queue.pop(0)
        normalized = normalize_url(url)
        if normalized in seen:
            continue
        seen.add(normalized)
        route = fetch_route(url, auth_context=auth_context)
        route.params.extend(query_params_from_url(route.url))
        for form in route.forms:
            for item in form.get("inputs", []):
                if item.get("name"):
                    route.params.append(
                        WebParam(
                            name=str(item.get("name")),
                            location="form",
                            value=str(item.get("value") or ""),
                            classifications=[],
                        )
                    )
        routes.append(route)
        if depth >= max_depth:
            continue
        ordered_links = sorted(route.links[:30], key=route_link_priority)
        script_assets = 0
        for link in ordered_links:
            absolute = urljoin(route.url, link)
            if not same_origin(absolute, route.url):
                continue
            if is_script_asset(absolute):
                if script_assets >= MAX_SCRIPT_ASSETS:
                    continue
                script_assets += 1
            item = (absolute, depth + 1)
            if looks_like_api_route(absolute):
                queue.insert(0, item)
            else:
                queue.append(item)
    return routes


def fetch_route(url: str, auth_context: WebAuthContext | None = None) -> WebRoute:
    started = time.monotonic()
    try:
        request = build_request(url, auth_context=auth_context)
        with urlopen(request, timeout=5) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            content_type = headers.get("content-type", "")
            body_limit = response_body_limit(url, content_type)
            body_bytes = response.read(body_limit)
            body = body_bytes.decode("utf-8", errors="replace")
            parser = LinkFormParser()
            parser.feed(body)
            discovered_links = parser.links
            if is_javascript_response(url, content_type):
                discovered_links = [*discovered_links, *extract_client_routes(body)]
            if urlparse(url).path.endswith("/robots.txt"):
                discovered_links = [*discovered_links, *extract_robots_routes(body)]
            return WebRoute(
                url=url,
                status=response.status,
                title=parser.title,
                content_type=content_type,
                content_length=len(body_bytes),
                body_hash=sha1_short(body),
                response_signals=response_signals(body, content_type),
                params=[],
                forms=parser.forms,
                links=dedupe_strings(discovered_links),
            )
    except Exception as exc:
        return WebRoute(url=url, error=str(exc), body_hash=sha1_short(f"{type(exc).__name__}:{exc}:{started}"))


def run_safe_web_probes(
    routes: list[WebRoute],
    *,
    provider: str = "gpt_oss",
    use_llm: bool = False,
    probe_results: list[dict[str, Any]] | None = None,
) -> list[WebFinding]:
    findings: list[WebFinding] = []
    if use_llm:
        findings.extend(WebFinding(**item) for item in assess_web_observations(web_observations(routes), provider, probe_results))
    return dedupe_findings(findings)


def web_observations(routes: list[WebRoute]) -> list[dict[str, Any]]:
    """Create neutral, value-free facts for the LLM evidence-review agent."""
    return [
        {
            "url": route.url,
            "status": route.status,
            "title": route.title[:100],
            "content_type": route.content_type[:80],
            "bytes": route.content_length,
            "json_field_names": route.response_signals[:40],
            "form_inputs": [param.name for param in route.params if param.location == "form"][:12],
            "query_parameters": [param.name for param in route.params if param.location == "query"][:12],
        }
        for route in routes
        if route.status and 200 <= route.status < 300
    ]


def web_planning_context(routes: list[WebRoute], browser_observations: dict[str, Any]) -> dict[str, Any]:
    candidate_routes = [
        route
        for route in routes
        if route.params or "json" in route.content_type.lower() or route.status is None
    ]
    return {
        "routes": [
            {
                "url": route.url,
                "status": route.status,
                "content_type": route.content_type[:50],
                "query_parameters": [param.name for param in route.params if param.location == "query"][:8],
                "form_inputs": [param.name for param in route.params if param.location == "form"][:8],
            }
            for route in candidate_routes[:24]
        ],
        "browser": {
            "available": browser_observations.get("available", False),
            "pages": [
                {
                    "url": page.get("url"),
                    "controls": page.get("controls", [])[:12],
                    "forms": page.get("forms", [])[:5],
                }
                for page in browser_observations.get("pages", [])
                if page.get("controls") or page.get("forms")
            ][:5],
            "requests": [
                {"url": item.get("url"), "method": item.get("method")}
                for item in browser_observations.get("requests", [])
                if item.get("resource_type") in {"xhr", "fetch", "document"}
            ][:12],
        },
    }


def fetch_text(url: str, auth_context: WebAuthContext | None = None) -> dict[str, Any]:
    try:
        request = build_request(url, auth_context=auth_context)
        with urlopen(request, timeout=5) as response:
            body = response.read(32768).decode("utf-8", errors="replace")
            return {"ok": True, "status": response.status, "body": body, "content_type": response.headers.get("content-type", "")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def run_idor_confirmation(
    routes: list[WebRoute],
    owner_context: WebAuthContext,
    alternate_context: WebAuthContext,
) -> list[WebFinding]:
    """Confirm only declared owner objects accessible through a second lab context.

    Object IDs come from observed routes and must be declared in ``owned_object_ids``.
    This deliberately avoids enumeration, guessing, credential handling, and writes.
    """
    owned = {str(value) for value in owner_context.owned_object_ids if str(value)}
    if not owned:
        return []
    findings: list[WebFinding] = []
    for route in routes:
        for param in route.params:
            if str(param.value) not in owned:
                continue
            owner_response = fetch_text(route.url, auth_context=owner_context)
            alternate_response = fetch_text(route.url, auth_context=alternate_context)
            if not owner_response.get("ok") or not alternate_response.get("ok"):
                continue
            owner_body = str(owner_response.get("body", ""))
            alternate_body = str(alternate_response.get("body", ""))
            similarity = response_similarity(owner_body, alternate_body)
            if (
                int(owner_response.get("status") or 0) < 200
                or int(owner_response.get("status") or 0) >= 300
                or int(alternate_response.get("status") or 0) < 200
                or int(alternate_response.get("status") or 0) >= 300
                or similarity < 0.92
                or looks_like_auth_denial(alternate_body)
            ):
                continue
            findings.append(
                WebFinding(
                    type="idor_confirmed",
                    severity="high",
                    confidence="high",
                    url=route.url,
                    parameter=param.name,
                    evidence=(
                        f"Object {param.value} declared owned by {owner_context.name} was returned to "
                        f"{alternate_context.name} with response similarity {similarity:.2f}."
                    ),
                    proof="Two authorized lab contexts received successful materially similar responses for the same owner-declared object.",
                    cwe="CWE-639",
                    owasp="A01:2021-Broken Access Control",
                    status="confirmed_vulnerability",
                )
            )
    return findings


def build_request(url: str, auth_context: WebAuthContext | None = None) -> Request:
    headers = {"User-Agent": "MedFlow-WebAgent/0.1"}
    if auth_context:
        headers.update({str(key): str(value) for key, value in auth_context.headers.items()})
        if auth_context.cookies:
            headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in auth_context.cookies.items())
    return Request(url, headers=headers)


def auth_headers(auth_context: WebAuthContext | None) -> dict[str, str]:
    if not auth_context:
        return {}
    headers = {str(key): str(value) for key, value in auth_context.headers.items()}
    if auth_context.cookies:
        headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in auth_context.cookies.items())
    return headers


def redact_auth_context(context: WebAuthContext) -> dict[str, Any]:
    return {
        "name": context.name,
        "header_names": sorted(context.headers),
        "cookie_names": sorted(context.cookies),
        "owned_object_ids": list(context.owned_object_ids),
    }


def response_similarity(left: str, right: str) -> float:
    left_normalized = normalize_response_body(left)
    right_normalized = normalize_response_body(right)
    if not left_normalized or not right_normalized:
        return 0.0
    return SequenceMatcher(None, left_normalized, right_normalized).ratio()


def normalize_response_body(body: str) -> str:
    compact = re.sub(r"\s+", " ", body.lower())
    compact = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<uuid>", compact)
    compact = re.sub(r"\b\d{10,}\b", "<number>", compact)
    return compact[:12000]


def looks_like_auth_denial(body: str) -> bool:
    lowered = body.lower()
    return any(marker in lowered for marker in ["unauthorized", "forbidden", "access denied", "login required", "sign in to continue"])


def retrieve_web_context(routes: list[WebRoute], findings: list[WebFinding]) -> list[dict[str, Any]]:
    settings = load_settings()
    queries = []
    categories = sorted({classification for route in routes for param in route.params for classification in param.classifications})
    if categories:
        queries.append("web app testing " + " ".join(categories))
    for finding in findings[:5]:
        queries.append(f"{finding.type} {finding.cwe} {finding.owasp} testing evidence")
    if not queries:
        queries.append("web application reconnaissance route parameter testing")
    hits: dict[tuple[str, str], dict[str, Any]] = {}
    for question in queries[:6]:
        for hit in query_web_appsec(settings.chroma_dir, question, settings.embedding_model, n_results=4):
            hits[(str(hit.get("collection")), str(hit.get("id")))] = hit
    return list(hits.values())[:12]


def persist_web_observation_graph(
    target: str,
    ports: list[int],
    routes: list[WebRoute],
    findings: list[WebFinding],
    path: Path = GRAPH_PATH,
    *,
    stateful_api: dict[str, Any] | None = None,
) -> GraphStore:
    store = GraphStore.load(path)
    host = store.upsert_node("Host", target, context=f"Web assessment target {target}", stable_key=f"host:{target}").node
    for port in ports:
        port_node = store.upsert_node("Port", f"{target}:{port}", context="Observed web service port", stable_key=f"port:{target}:{port}").node
        store.add_edge(host.id, port_node.id, "HOST_HAS_PORT")
    for route in routes:
        route_node = store.upsert_node(
            "Route",
            route.url,
            context=f"{route.method} {route.status or ''} {route.title}",
            attributes={
                "status": route.status,
                "title": route.title,
                "content_type": route.content_type,
                "body_hash": route.body_hash,
            },
            stable_key=f"route:{normalize_url(route.url)}",
        ).node
        store.add_edge(host.id, route_node.id, "HOSTS_ROUTE")
        for param in route.params:
            param_node = store.upsert_node(
                "Parameter",
                f"{route.url}::{param.location}::{param.name}",
                context=f"{param.name} classifications={','.join(param.classifications)}",
                attributes={"name": param.name, "location": param.location, "classifications": param.classifications},
                stable_key=f"param:{normalize_url(route.url)}:{param.location}:{param.name}",
            ).node
            store.add_edge(route_node.id, param_node.id, "ROUTE_HAS_PARAMETER")
    for finding in findings:
        finding_node = store.upsert_node(
            "Finding",
            f"{finding.type}:{finding.url}:{finding.parameter}",
            context=f"{finding.evidence} {finding.proof}",
            attributes=asdict(finding),
            stable_key=f"finding:{finding.type}:{normalize_url(finding.url)}:{finding.parameter}",
        ).node
        route_node = store.upsert_node("Route", finding.url, stable_key=f"route:{normalize_url(finding.url)}").node
        store.add_edge(finding_node.id, route_node.id, "FINDING_ON_ROUTE")
    persist_stateful_api_graph(store, host.id, stateful_api or {})
    store.save()
    return store


def persist_stateful_api_graph(store: GraphStore, host_id: str, assessment: dict[str, Any]) -> None:
    schema = assessment.get("schema") or {}
    if not schema:
        return
    schema_node = store.upsert_node(
        "ApiSchema",
        str(schema.get("url") or schema.get("title") or "OpenAPI"),
        context=f"{schema.get('title', 'OpenAPI')} version {schema.get('version', '')}",
        attributes={
            "title": schema.get("title"),
            "version": schema.get("version"),
            "base_url": schema.get("base_url"),
            "engine": assessment.get("engine"),
        },
        stable_key=f"api-schema:{schema.get('url')}",
    ).node
    store.add_edge(host_id, schema_node.id, "HOST_EXPOSES_API_SCHEMA")
    operation_nodes: dict[str, Any] = {}
    for operation in assessment.get("operations", []):
        label = str(operation.get("label") or "")
        if not label:
            continue
        node = store.upsert_node(
            "ApiOperation",
            label,
            context=f"{operation.get('summary', '')} role={operation.get('role', '')}",
            attributes=operation,
            stable_key=f"api-operation:{schema.get('base_url')}:{label}",
        ).node
        operation_nodes[label] = node
        store.add_edge(schema_node.id, node.id, "SCHEMA_DEFINES_OPERATION")
    for dependency in assessment.get("dependencies", []):
        producer = operation_nodes.get(str(dependency.get("producer") or ""))
        consumer = operation_nodes.get(str(dependency.get("consumer") or ""))
        if not producer or not consumer:
            continue
        resource = store.upsert_node(
            "ApiResource",
            str(dependency.get("resource") or "resource"),
            context=f"Stateful API resource consumed through {dependency.get('parameter', '')}",
            attributes={
                "parameter": dependency.get("parameter"),
                "relationship": dependency.get("relationship"),
            },
            stable_key=f"api-resource:{schema.get('base_url')}:{dependency.get('resource')}",
        ).node
        store.add_edge(producer.id, resource.id, "API_OPERATION_PRODUCES")
        store.add_edge(resource.id, consumer.id, "API_OPERATION_CONSUMES")


def query_params_from_url(url: str) -> list[WebParam]:
    parsed = urlparse(url)
    params = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        params.append(WebParam(name=key, location="query", value=value))
    return params


def response_signals(body: str, content_type: str) -> list[str]:
    """Return JSON key names only, so reports never persist returned secret values."""
    if "json" not in content_type.lower():
        return []
    try:
        payload = json.loads(body)
    except (TypeError, ValueError):
        return []
    fields: set[str] = set()

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if normalized:
                    fields.add(normalized)
                visit(nested)
        elif isinstance(value, list):
            for nested in value[:100]:
                visit(nested)

    visit(payload)
    return sorted(fields)


def is_javascript_response(url: str, content_type: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith((".js", ".mjs")) or "javascript" in content_type.lower()


def response_body_limit(url: str, content_type: str) -> int:
    if is_javascript_response(url, content_type):
        return MAX_SCRIPT_BYTES
    if "json" in content_type.lower() or urlparse(url).path.lower().endswith(("openapi.json", "swagger.json")):
        return MAX_API_DESCRIPTION_BYTES
    return MAX_HTML_BYTES


def is_script_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith((".js", ".mjs"))


def route_link_priority(link: str) -> tuple[int, str]:
    path = urlparse(link).path.lower()
    name = path.rsplit("/", 1)[-1]
    if looks_like_api_route(link):
        return (0, path)
    if is_script_asset(link) and any(token in name for token in ["main", "app", "index"]):
        return (1, path)
    if not is_script_asset(link):
        return (2, path)
    return (3, path)


def looks_like_api_route(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.startswith(("/api/", "/rest/", "/graphql", "/v1/", "/v2/"))


def extract_client_routes(body: str) -> list[str]:
    """Extract static relative API paths from JavaScript without executing it."""
    candidates: list[str] = []
    pattern = re.compile(r"(?:['\"`])(/(?:api|rest|graphql|v[0-9]+)[A-Za-z0-9_./?=&%+\-]*)(?:['\"`])")
    for match in pattern.finditer(body):
        candidate = match.group(1)
        if len(candidate) > 240 or any(token in candidate for token in ["{", "}", "${", ".."]):
            continue
        candidates.append(candidate)
    template_query_pattern = re.compile(
        r"`(?:\$\{[^}]+\})?(/(?:api|rest|graphql|v[0-9]+)[A-Za-z0-9_./?=&%+\-]*\?[^`]*=)\$\{[^}]+\}[^`]*`"
    )
    for match in template_query_pattern.finditer(body):
        candidate = match.group(1)
        if len(candidate) <= 240 and ".." not in candidate:
            candidates.append(candidate)
    return dedupe_strings(candidates)


def extract_robots_routes(body: str) -> list[str]:
    routes = []
    for line in body.splitlines():
        match = re.match(r"\s*(?:allow|disallow)\s*:\s*(/[^\s#]*)", line, flags=re.I)
        if match:
            routes.append(match.group(1))
    return dedupe_strings(routes)


def dedupe_strings(values: list[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def base_url(target: str, port: int) -> str:
    scheme = "https" if int(port) in {443, 8443} else "http"
    return f"{scheme}://{target}:{int(port)}/"


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment="", path=parsed.path.rstrip("/") or "/"))


def same_origin(left: str, right: str) -> bool:
    l_parsed = urlparse(left)
    r_parsed = urlparse(right)
    return (l_parsed.scheme, l_parsed.netloc) == (r_parsed.scheme, r_parsed.netloc)


def sha1_short(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def dedupe_findings(findings: list[WebFinding]) -> list[WebFinding]:
    seen: set[tuple[str, str, str]] = set()
    output: list[WebFinding] = []
    for finding in findings:
        key = (finding.type, finding.url, finding.parameter)
        if key in seen:
            continue
        seen.add(key)
        output.append(finding)
    return output
