from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen

from medflow_graph.memory import GraphStore
from medflow_ti.config import ROOT, load_settings

from .tools import validate_target
from .web_kb import query_web_appsec


DEFAULT_PATHS = ["/", "/login", "/admin", "/api", "/robots.txt"]
SAFE_SQLI_PROBES = ["'", "\"", "')"]
XSS_MARKER = "MEDFLOW_XSS_MARKER_7f3a"
GRAPH_PATH = ROOT / "data" / "graph" / "web_observation_graph.json"


@dataclass
class WebParam:
    name: str
    location: str
    value: str = ""
    classifications: list[str] = field(default_factory=list)


@dataclass
class WebRoute:
    url: str
    method: str = "GET"
    status: int | None = None
    title: str = ""
    content_type: str = ""
    content_length: int = 0
    body_hash: str = ""
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
    kb_context: list[dict[str, Any]]
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
) -> dict[str, Any]:
    started = time.monotonic()
    target = validate_target(target)
    routes = crawl_web(target, ports, paths=paths, max_depth=max_depth, max_routes=max_routes)
    findings = run_safe_web_probes(routes)
    kb_context = retrieve_web_context(routes, findings) if use_kb else []
    graph = persist_web_observation_graph(target, ports, routes, findings, graph_path)
    assessment = WebAssessment(
        target=target,
        ports=ports,
        routes=routes,
        findings=findings,
        kb_context=kb_context,
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
        route = fetch_route(url)
        route.params.extend(query_params_from_url(route.url))
        for form in route.forms:
            for item in form.get("inputs", []):
                if item.get("name"):
                    route.params.append(
                        WebParam(
                            name=str(item.get("name")),
                            location="form",
                            value=str(item.get("value") or ""),
                            classifications=classify_parameter(str(item.get("name")), str(item.get("value") or "")),
                        )
                    )
        for param in route.params:
            if not param.classifications:
                param.classifications = classify_parameter(param.name, param.value)
        routes.append(route)
        if depth >= max_depth:
            continue
        for link in route.links[:20]:
            absolute = urljoin(route.url, link)
            if same_origin(absolute, route.url):
                queue.append((absolute, depth + 1))
    return routes


def fetch_route(url: str) -> WebRoute:
    started = time.monotonic()
    try:
        request = Request(url, headers={"User-Agent": "MedFlow-WebAgent/0.1"})
        with urlopen(request, timeout=5) as response:
            body_bytes = response.read(32768)
            body = body_bytes.decode("utf-8", errors="replace")
            parser = LinkFormParser()
            parser.feed(body)
            headers = {key.lower(): value for key, value in response.headers.items()}
            return WebRoute(
                url=url,
                status=response.status,
                title=parser.title,
                content_type=headers.get("content-type", ""),
                content_length=len(body_bytes),
                body_hash=sha1_short(body),
                params=[],
                forms=parser.forms,
                links=parser.links,
            )
    except Exception as exc:
        return WebRoute(url=url, error=str(exc), body_hash=sha1_short(f"{type(exc).__name__}:{exc}:{started}"))


def run_safe_web_probes(routes: list[WebRoute]) -> list[WebFinding]:
    findings: list[WebFinding] = []
    for route in routes:
        for param in route.params:
            if "sql_like" in param.classifications:
                finding = probe_sqli(route, param)
                if finding:
                    findings.append(finding)
            if "reflected_input" in param.classifications or "search" in param.classifications:
                finding = probe_xss_reflection(route, param)
                if finding:
                    findings.append(finding)
            if "object_id" in param.classifications:
                findings.append(
                    WebFinding(
                        type="idor_candidate",
                        severity="info",
                        confidence="low",
                        url=route.url,
                        parameter=param.name,
                        evidence=f"Parameter {param.name} looks like an object reference.",
                        proof="Two auth contexts are required before confirming IDOR.",
                        cwe="CWE-639",
                        owasp="A01:2021-Broken Access Control",
                        status="candidate",
                    )
                )
    return dedupe_findings(findings)


def probe_sqli(route: WebRoute, param: WebParam) -> WebFinding | None:
    baseline = fetch_text(route.url)
    if not baseline.get("ok"):
        return None
    for probe in SAFE_SQLI_PROBES:
        url = mutate_query_param(route.url, param.name, probe)
        result = fetch_text(url)
        if not result.get("ok"):
            continue
        body = str(result.get("body", ""))
        evidence = sql_error_signature(body)
        if evidence:
            return WebFinding(
                type="sqli_error_signal",
                severity="medium",
                confidence="medium",
                url=route.url,
                parameter=param.name,
                evidence=evidence,
                proof=f"Non-destructive SQL syntax probe changed response with database error signature using parameter {param.name}.",
                cwe="CWE-89",
                owasp="A03:2021-Injection",
                status="suspected",
            )
    return None


def probe_xss_reflection(route: WebRoute, param: WebParam) -> WebFinding | None:
    result = fetch_text(mutate_query_param(route.url, param.name, XSS_MARKER))
    if not result.get("ok"):
        return None
    body = str(result.get("body", ""))
    if XSS_MARKER not in body:
        return None
    return WebFinding(
        type="xss_reflection_signal",
        severity="low",
        confidence="medium",
        url=route.url,
        parameter=param.name,
        evidence=f"Unique marker reflected in response for parameter {param.name}.",
        proof="Inert marker reflection observed; browser execution proof not attempted.",
        cwe="CWE-79",
        owasp="A03:2021-Injection",
        status="suspected",
    )


def fetch_text(url: str) -> dict[str, Any]:
    try:
        request = Request(url, headers={"User-Agent": "MedFlow-WebAgent/0.1"})
        with urlopen(request, timeout=5) as response:
            body = response.read(32768).decode("utf-8", errors="replace")
            return {"ok": True, "status": response.status, "body": body, "content_type": response.headers.get("content-type", "")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


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
    store.save()
    return store


def query_params_from_url(url: str) -> list[WebParam]:
    parsed = urlparse(url)
    params = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        params.append(WebParam(name=key, location="query", value=value, classifications=classify_parameter(key, value)))
    for segment in parsed.path.split("/"):
        if is_object_reference(segment):
            params.append(WebParam(name="path_segment", location="path", value=segment, classifications=["object_id"]))
    return params


def classify_parameter(name: str, value: str = "") -> list[str]:
    text = f"{name} {value}".lower()
    classes: list[str] = []
    if re.search(r"\b(id|uid|user|account|patient|record|order|invoice|file|doc|document|uuid|key)\b", text) or is_object_reference(value):
        classes.append("object_id")
    if any(term in text for term in ["q", "query", "search", "keyword", "term", "filter"]):
        classes.append("search")
    if any(term in text for term in ["url", "next", "redirect", "return", "callback"]):
        classes.append("redirect")
    if any(term in text for term in ["path", "file", "template", "page", "include", "download"]):
        classes.append("file_path")
    if any(term in text for term in ["name", "message", "comment", "title", "desc", "search", "q"]):
        classes.append("reflected_input")
    if any(term in text for term in ["id", "select", "where", "sort", "order", "filter", "query", "search", "page"]):
        classes.append("sql_like")
    return sorted(set(classes)) or ["generic"]


def is_object_reference(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,10}", value or "") or re.fullmatch(r"[0-9a-fA-F-]{16,36}", value or ""))


def mutate_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    updated = []
    for key, old in pairs:
        if key == name:
            updated.append((key, value))
            found = True
        else:
            updated.append((key, old))
    if not found:
        updated.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(updated)))


def sql_error_signature(body: str) -> str:
    patterns = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"PostgreSQL.*ERROR",
        r"ORA-\d{5}",
        r"SQLite/JDBCDriver",
        r"sqlite error",
        r"unclosed quotation mark",
        r"ODBC SQL Server Driver",
    ]
    for pattern in patterns:
        match = re.search(pattern, body, flags=re.I)
        if match:
            return match.group(0)[:220]
    return ""


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
