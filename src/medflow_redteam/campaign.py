from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from medflow_compare.shared_tools import (
    SAFETY_BOUNDARY,
    call_redteam_llm,
    make_trace,
    retrieve_many,
    safety_review_tool,
)
from medflow_ti.config import Settings, load_settings
from medflow_ti.llm import LLMError, is_llm_api_error
from medflow_graph.memory import GraphStore

from .auth_contract_agent import discover_authentication_contract
from .authorization_agent import (
    build_inline_prompt_document,
    run_inline_authorization_assessment,
)
from .campaign_report import render_campaign_markdown
from .command_planner import plan_recon_strategy, plan_validation_strategy
from .evidence import (
    normalize_authorization_evidence,
    normalize_password_spray_evidence,
    normalize_validation_evidence,
    normalize_web_assessment_evidence,
    normalize_web_evidence,
    normalize_wordlist_attack_evidence,
    render_findings_table,
)
from .lab_http import validate_lab_url
from .password_spray_agent import (
    PasswordSprayAgent,
    PasswordSprayConfig,
)
from .tools import (
    ToolResult,
    default_ports_for_target,
    http_probe,
    service_scan,
    parse_open_services,
    run_selected_exploit,
    select_exploit_candidate,
    summarize_tool_result,
    tcp_connect_check,
    validate_target,
    web_control_checks,
    web_fingerprint,
    web_route_discovery,
)
from .web_app import WebAuthContext, run_web_assessment
from .wordlist_attack_agent import (
    WordlistAttackAgent,
    WordlistAttackConfig,
)


@dataclass
class AgentOutput:
    role: str
    objective: str
    tools: list[str]
    decisions: list[str]
    outputs: list[str]
    handoff: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class CampaignRun:
    goal: str
    target: str | None
    target_url: str | None
    provider: str
    report: str
    steps: list[str]
    agents: list[AgentOutput]
    sources: list[dict[str, Any]]
    tool_traces: list[Any]
    tcp: dict[str, Any] | None = None
    services: list[dict[str, str]] = field(default_factory=list)
    http: dict[str, Any] | None = None
    web_fingerprint: dict[str, Any] | None = None
    web_routes: dict[str, Any] | None = None
    capability_selection: dict[str, Any] | None = None
    capability_validation: dict[str, Any] | None = None
    graph_memory: dict[str, Any] | None = None
    recon_strategy: dict[str, Any] | None = None
    validation_strategy: dict[str, Any] | None = None
    web_checks: dict[str, Any] | None = None
    web_assessment: dict[str, Any] | None = None
    authorization_assessment: dict[str, Any] | None = None
    authentication_discovery: dict[str, Any] | None = None
    wordlist_attack: dict[str, Any] | None = None
    password_spray: dict[str, Any] | None = None
    campaign_routing: dict[str, Any] | None = None
    normalized_evidence: list[dict[str, Any]] = field(default_factory=list)
    loop_summary: dict[str, Any] | None = None
    phases: list[dict[str, Any]] = field(default_factory=list)
    tool_timeline: list[dict[str, Any]] = field(default_factory=list)
    safety_review: str = ""
    elapsed_seconds: float = 0.0
    error: str | None = None


class CampaignState(TypedDict, total=False):
    goal: str
    target: str | None
    target_url: str | None
    provider: str
    execute_recon: bool
    execute_validation: bool
    max_capabilities: int
    execution_mode: str
    metasploit_action: str
    use_llm: bool
    web_auth_contexts: list[WebAuthContext]
    stateful_api: bool
    stateful_max_requests: int
    stateful_max_workflows: int
    authorization_output_root: Path
    authorization_request_budget: int
    authorization_tool_rounds: int
    identity_output_root: Path
    autonomous_identity_enabled: bool
    wordlist_attack_config: WordlistAttackConfig | None
    password_spray_config: PasswordSprayConfig | None
    ports: list[int]
    tcp: dict[str, Any]
    nmap_result: ToolResult
    services: list[dict[str, str]]
    http: dict[str, Any]
    web_fingerprint: dict[str, Any]
    web_routes: dict[str, Any]
    capability_selection: dict[str, Any]
    capability_validation: dict[str, Any]
    graph_memory: dict[str, Any]
    recon_strategy: dict[str, Any]
    validation_strategy: dict[str, Any]
    web_checks: dict[str, Any]
    web_assessment: dict[str, Any]
    authorization_assessment: dict[str, Any]
    authentication_discovery: dict[str, Any]
    wordlist_attack: dict[str, Any]
    password_spray: dict[str, Any]
    campaign_routing: dict[str, Any]
    normalized_evidence: list[dict[str, Any]]
    loop_summary: dict[str, Any]
    phases: list[dict[str, Any]]
    tool_timeline: list[dict[str, Any]]
    sources: list[dict[str, Any]]
    agents: list[dict[str, Any]]
    report: str
    safety_review: str
    steps: list[str]
    tool_traces: list[Any]


def append_step(state: CampaignState, step: str) -> list[str]:
    return [*state.get("steps", []), step]


def append_phase(state: CampaignState, phase: str, status: str, evidence: str = "") -> list[dict[str, Any]]:
    return [
        *state.get("phases", []),
        {
            "phase": phase,
            "status": status,
            "evidence": evidence,
        },
    ]


def append_timeline(state: CampaignState, name: str, input_text: str, status: str, evidence: str = "") -> list[dict[str, Any]]:
    return [
        *state.get("tool_timeline", []),
        {
            "tool": name,
            "input": input_text[:500],
            "status": status,
            "evidence": evidence[:1200],
        },
    ]


def observation_status(payload: dict[str, Any], key: str) -> str:
    items = payload.get(key) or []
    if not items:
        return "ran_no_finding"
    successes = [item for item in items if item.get("status") and not item.get("error")]
    errors = [item for item in items if item.get("error")]
    if successes:
        return "success" if not errors else "partial_success"
    return "ran_no_finding" if errors else "not_applicable"


def findings_status(payload: dict[str, Any]) -> str:
    count = int(payload.get("count") or 0)
    return "confirmed_exposure" if count else "ran_no_finding"


def agent_to_dict(output: AgentOutput) -> dict[str, Any]:
    return asdict(output)


def compact_services(services: list[dict[str, str]]) -> str:
    if not services:
        return "No live service evidence was collected."
    return "\n".join(
        f"- {item.get('port')}/{item.get('service')}: {item.get('version', '')}"
        for item in services[:12]
    )


def http_ports_from_services(services: list[dict[str, str]]) -> list[int]:
    ports = []
    for service in services:
        port = service.get("port", "")
        label = f"{service.get('service', '')} {service.get('version', '')}".lower()
        if not port.isdigit():
            continue
        numeric_port = int(port)
        if "http" in label or numeric_port in {80, 443, 5000, 8000, 8080, 8443}:
            ports.append(numeric_port)
    return sorted(set(ports))


def http_ports_from_scan(scan_output: str, open_ports: list[int]) -> list[int]:
    """Recover HTTP ports when Nmap has an unknown service label but captured HTTP evidence."""
    lowered = scan_output.lower()
    http_markers = ["http/1.", "http/2", "content-type:", "set-cookie:", "x-frame-options:", "server:"]
    if any(marker in lowered for marker in http_markers):
        return sorted(set(open_ports))
    return []


def open_ports_from_tcp(tcp: dict[str, Any]) -> list[int]:
    return sorted(int(port) for port, result in tcp.items() if result.get("open") and str(port).isdigit())


def infer_services_from_ports(open_ports: list[int]) -> list[dict[str, str]]:
    names = {
        21: "ftp",
        22: "ssh",
        25: "smtp",
        53: "domain",
        80: "http",
        110: "pop3",
        139: "netbios-ssn",
        143: "imap",
        443: "https",
        445: "microsoft-ds",
        3306: "mysql",
        5000: "http",
        8000: "http",
        8080: "http",
        8443: "https",
    }
    return [
        {
            "port": str(port),
            "protocol": "tcp",
            "service": names.get(port, "unknown"),
            "version": "open port inferred from TCP check",
        }
        for port in open_ports
    ]


def build_campaign_queries(goal: str, services: list[dict[str, str]] | None = None) -> list[str]:
    service_terms = " ".join(
        f"{item.get('service', '')} {item.get('version', '')}"
        for item in (services or [])[:10]
    ).strip()
    return [
        f"authorized healthcare red team campaign {goal}",
        f"red team reconnaissance attack path planning {service_terms}",
        "identity attack MFA fatigue password spraying device registration detection",
        "web API attack healthcare portal authorization business logic detection",
        "blockchain smart contract permission monitoring healthcare fraud threat intelligence",
        "ATT&CK mapping reporting remediation red team exercise",
    ]


def fallback_agent_output(role: str, goal: str, tools: list[str], decisions: list[str], outputs: list[str], handoff: str) -> dict[str, Any]:
    return agent_to_dict(
        AgentOutput(
            role=role,
            objective=goal,
            tools=tools,
            decisions=decisions,
            outputs=outputs,
            handoff=handoff,
        )
    )


def call_role_llm(
    state: CampaignState,
    settings: Settings,
    role: str,
    role_prompt: str,
    fallback: dict[str, Any],
) -> dict[str, Any]:
    if not state.get("use_llm", True):
        return fallback
    prompt = f"""
You are the {role} in an authorized MedFlow red-team campaign planning graph.

{SAFETY_BOUNDARY}

High-level campaign goal:
{state["goal"]}

Explicit web target URL:
{state.get("target_url") or "none"}

Configured one-account password-wordlist execution:
{"yes" if state.get("wordlist_attack_config") else "no"}

Configured password-spray execution:
{"yes" if state.get("password_spray_config") else "no"}

Observed services:
{compact_services(state.get("services", []))}

Prior agent outputs:
{json.dumps(compact_agents_for_prompt(state.get("agents", [])), indent=2)}

Retrieved evidence, compact:
{json.dumps([{
    "collection": hit.get("collection"),
    "id": hit.get("id"),
    "score": round(float(hit.get("score") or 0), 3),
    "label": " ".join(str((hit.get("metadata") or {}).get(key, "")) for key in ["mitre_id", "name"]).strip(),
    "text": (hit.get("document") or "")[:550],
} for hit in state.get("sources", [])[:8]], indent=2)}

{role_prompt}

Return strict JSON with keys:
role, objective, tools, decisions, outputs, handoff.
Use arrays for tools, decisions, and outputs.
Keep it safe: validation, telemetry, detection, and reporting level only.
"""
    try:
        raw = call_redteam_llm(prompt, settings=settings, provider=state.get("provider", "gpt_oss"))
        parsed = parse_json_object(raw)
        return {
            "role": scalarize(parsed.get("role"), role),
            "objective": scalarize(parsed.get("objective"), state["goal"]),
            "tools": listify(parsed.get("tools")),
            "decisions": listify(parsed.get("decisions")),
            "outputs": listify(parsed.get("outputs")),
            "handoff": scalarize(parsed.get("handoff"), fallback.get("handoff", "")),
        }
    except Exception as exc:
        if not is_llm_api_error(exc) and not isinstance(exc, (LLMError, RuntimeError, ValueError, json.JSONDecodeError)):
            raise
        fallback = {**fallback}
        fallback["handoff"] = f"{fallback.get('handoff', '')} LLM fallback used: {exc}"
        return fallback


def parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        stripped = stripped.removeprefix("json").strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise json.JSONDecodeError("No JSON object found", stripped, 0)
    return json.loads(stripped[start : end + 1])


def listify(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if value is None:
        return []
    return [str(value)]


def scalarize(value: Any, fallback: Any = "") -> str:
    if isinstance(value, list):
        return "; ".join(str(item) for item in value)
    if value is None:
        return str(fallback)
    return str(value)


def truncate_value(value: Any, max_chars: int = 900) -> Any:
    if isinstance(value, str):
        return value if len(value) <= max_chars else value[:max_chars].rstrip() + "...[truncated]"
    if isinstance(value, list):
        return [truncate_value(item, max_chars=max_chars) for item in value[:8]]
    if isinstance(value, dict):
        return {key: truncate_value(item, max_chars=max_chars) for key, item in list(value.items())[:12]}
    return value


def compact_agents_for_prompt(agents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    compacted = []
    for agent in agents[-6:]:
        evidence = agent.get("evidence") or {}
        compacted.append(
            {
                "role": agent.get("role"),
                "objective": agent.get("objective"),
                "tools": agent.get("tools", [])[:8],
                "decisions": agent.get("decisions", [])[:6],
                "outputs": agent.get("outputs", [])[:6],
                "handoff": truncate_value(agent.get("handoff", ""), 600),
                "evidence_summary": summarize_evidence_for_prompt(evidence),
            }
        )
    return compacted


def campaign_agent_selected(state: CampaignState, agent_name: str) -> bool:
    selected = (state.get("campaign_routing") or {}).get("selected_agents")
    if not selected:
        return True
    return agent_name in {str(item) for item in selected}


def summarize_evidence_for_prompt(evidence: dict[str, Any]) -> dict[str, Any]:
    services = evidence.get("services") or []
    tcp = evidence.get("tcp") or {}
    routes = (evidence.get("web_routes") or {}).get("web_routes") or []
    http = (evidence.get("http") or {}).get("http_probe") or []
    fingerprints = (evidence.get("web_fingerprint") or {}).get("web_fingerprints") or []
    return {
        "service_count": len(services),
        "services": services[:10],
        "open_tcp_ports": [port for port, result in list(tcp.items()) if isinstance(result, dict) and result.get("open")][:30],
        "http_successes": [item for item in http if item.get("status")][:8],
        "route_successes": [item for item in routes if item.get("status")][:10],
        "artifact_signals": [item for item in routes if item.get("artifact_signal")][:10],
        "web_fingerprints": [item for item in fingerprints if item.get("status")][:6],
    }


def compact_reporting_draft(state: CampaignState) -> dict[str, Any]:
    validation = state.get("capability_validation") or {}
    selection = state.get("capability_selection") or {}
    routes = (state.get("web_routes") or {}).get("web_routes") or []
    fingerprints = (state.get("web_fingerprint") or {}).get("web_fingerprints") or []
    timeline = state.get("tool_timeline", [])
    graph_hits = (state.get("graph_memory") or {}).get("hits") or []
    return {
        "goal": state["goal"],
        "target": state.get("target"),
        "target_url": state.get("target_url"),
        "campaign_routing": truncate_value(state.get("campaign_routing", {}), 700),
        "services": state.get("services", [])[:20],
        "web_routes_observed": [item for item in routes if item.get("status")][:12],
        "web_artifact_signals": [item for item in routes if item.get("artifact_signal")][:12],
        "web_fingerprints": [item for item in fingerprints if item.get("status")][:8],
        "web_checks": truncate_value(state.get("web_checks", {}), 700),
        "web_assessment": truncate_value(state.get("web_assessment", {}), 900),
        "authorization_assessment": truncate_value(
            state.get("authorization_assessment", {}),
            1_200,
        ),
        "authentication_discovery": truncate_value(
            state.get("authentication_discovery", {}),
            1_200,
        ),
        "wordlist_attack": truncate_value(
            state.get("wordlist_attack", {}),
            1_200,
        ),
        "password_spray": truncate_value(
            state.get("password_spray", {}),
            1_200,
        ),
        "graph_memory_hits": [
            {
                "type": hit.get("type"),
                "name": hit.get("name"),
                "score": hit.get("score"),
            }
            for hit in graph_hits[:10]
        ],
        "selected_capabilities": [
            {
                "id": item.get("id"),
                "score": item.get("score"),
                "why": truncate_value(item.get("score_explanation", ""), 220),
            }
            for item in selection.get("selected_candidates", [])[:8]
        ],
        "validation_summary": {
            "attempted": validation.get("attempted", 0),
            "successful": validation.get("successful", 0),
            "status_counts": validation.get("status_counts", {}),
            "results": [
                {
                    "id": item.get("selected_exploit_id"),
                    "status": item.get("status"),
                    "verified": item.get("verified"),
                    "evidence": truncate_value(item.get("proof_output") or item.get("reason") or "", 260),
                }
                for item in validation.get("results", [])[:10]
            ],
        },
        "normalized_evidence": truncate_value(state.get("normalized_evidence", []), 350),
        "tool_timeline": [
            {
                "tool": item.get("tool"),
                "status": item.get("status"),
                "evidence": truncate_value(item.get("evidence", ""), 180),
            }
            for item in timeline[-15:]
        ],
        "agents": compact_agents_for_prompt(state.get("agents", [])),
    }


def apply_validation_strategy(selection: dict[str, Any], strategy: dict[str, Any]) -> dict[str, Any]:
    selected_ids = [str(item) for item in strategy.get("selected_ids", [])]
    candidates = selection.get("candidates") or selection.get("selected_candidates") or []
    by_id = {str(item.get("id")): item for item in candidates if item.get("id")}
    selected = [by_id[cap_id] for cap_id in selected_ids if cap_id in by_id]
    updated = {**selection}
    updated["selected_candidates"] = selected
    updated["selected"] = selected[0] if selected else None
    updated["llm_validation_strategy"] = {key: value for key, value in strategy.items() if key != "llm_raw"}
    return updated


def plan_campaign_routing(
    state: CampaignState,
    settings: Settings,
) -> dict[str, Any]:
    autonomous_identity_available = bool(
        state.get("autonomous_identity_enabled")
        and state.get("target_url")
        and state.get("use_llm", True)
    )
    fallback_agents = [
        "reconnaissance",
        "identity_attack",
        "web_api_attack",
        "blockchain_security",
        "reporting",
    ]
    if state.get("execute_validation"):
        fallback_agents.append("capability_validation")
    if state.get("wordlist_attack_config"):
        fallback_agents.append("wordlist_attack")
    if state.get("password_spray_config"):
        fallback_agents.append("password_spray")
    if state.get("target_url") and state.get("use_llm", True):
        fallback_agents.append("authorization_assessment")
    fallback = {
        "selected_agents": fallback_agents,
        "run_authorization_assessment": bool(
            state.get("target_url") and state.get("use_llm", True)
        ),
        "authorization_reason": (
            "Fallback routing selected bounded web authorization analysis for the explicit URL."
            if state.get("target_url") and state.get("use_llm", True)
            else "No LLM-backed URL authorization workflow is available for this run."
        ),
        "generated_by": "deterministic_fallback",
    }
    if not state.get("use_llm", True):
        return fallback

    prompt = f"""
You are routing an authorized red-team campaign to internal specialist agents. The caller must not
select specialists manually.

Campaign objective:
{state["goal"]}

Explicit network target:
{state.get("target") or "none"}

Explicit web target URL:
{state.get("target_url") or "none"}

Available specialists:
- reconnaissance: attack-surface and service discovery
- capability_validation: service-specific validation
- identity_attack: directory, authentication, MFA, and identity paths
- wordlist_attack: many candidate passwords against one configured lab identity
- password_spray: lockout-aware common-credential validation on an explicitly configured login
- web_api_attack: routes, inputs, API behavior, and application vulnerabilities
- authorization_assessment: bounded same-origin object-level, function-level, role, tenant, and
  session-boundary testing driven by an LLM HTTP planner
- blockchain_security: smart contracts, wallets, and chain-specific controls
- reporting: evidence synthesis

Select specialists from the objective and target type. Select authorization_assessment when the
objective requests or reasonably includes access-control testing and the explicit URL permits
same-origin HTTP evidence collection. Do not select it for a network-only target or a goal that
clearly excludes web authorization. A broad web/API security assessment may include it.
Select wordlist_attack and/or password_spray when the objective explicitly requests that credential
test and either a manual execution configuration is present or autonomous authentication-contract
discovery is available. Do not infer permission for credential testing from a generic web test.
The aggressive-lab execution mode and private target allowlist remain the non-LLM authorization
gate.

Manual wordlist configuration present:
{"yes" if state.get("wordlist_attack_config") else "no"}

Manual password-spray configuration present:
{"yes" if state.get("password_spray_config") else "no"}

Autonomous authentication-contract discovery available:
{"yes" if autonomous_identity_available else "no"}

Return only one JSON object:
{{
  "selected_agents": ["reconnaissance", "web_api_attack", "reporting"],
  "run_authorization_assessment": true,
  "authorization_reason": "one concise evidence-based routing reason"
}}
""".strip()
    try:
        raw = call_redteam_llm(
            prompt,
            settings=settings,
            provider=state.get("provider", "gpt_oss"),
        )
        parsed = parse_json_object(raw)
        allowed_agents = {
            "reconnaissance",
            "capability_validation",
            "identity_attack",
            "wordlist_attack",
            "password_spray",
            "web_api_attack",
            "authorization_assessment",
            "blockchain_security",
            "reporting",
        }
        selected_agents = [
            str(item)
            for item in parsed.get("selected_agents") or []
            if str(item) in allowed_agents
        ]
        run_authorization = parsed.get("run_authorization_assessment")
        if not isinstance(run_authorization, bool):
            raise ValueError("Routing response omitted a boolean authorization decision.")
        if run_authorization and not state.get("target_url"):
            raise ValueError("Authorization assessment requires an explicit target URL.")
        if run_authorization:
            for required in ("web_api_attack", "authorization_assessment"):
                if required not in selected_agents:
                    selected_agents.append(required)
        if state.get("execute_recon") and "reconnaissance" not in selected_agents:
            selected_agents.append("reconnaissance")
        if (
            state.get("execute_validation")
            and "capability_validation" not in selected_agents
        ):
            selected_agents.append("capability_validation")
        if (
            state.get("wordlist_attack_config")
            and "wordlist_attack" not in selected_agents
        ):
            selected_agents.append("wordlist_attack")
        if (
            state.get("password_spray_config")
            and "password_spray" not in selected_agents
        ):
            selected_agents.append("password_spray")
        if not autonomous_identity_available:
            if (
                not state.get("wordlist_attack_config")
                and "wordlist_attack" in selected_agents
            ):
                selected_agents.remove("wordlist_attack")
            if (
                not state.get("password_spray_config")
                and "password_spray" in selected_agents
            ):
                selected_agents.remove("password_spray")
        if "reporting" not in selected_agents:
            selected_agents.append("reporting")
        return {
            "selected_agents": selected_agents,
            "run_authorization_assessment": run_authorization,
            "authorization_reason": str(
                parsed.get("authorization_reason") or "No routing reason supplied."
            )[:1_000],
            "generated_by": f"llm:{state.get('provider', 'gpt_oss')}",
        }
    except Exception as exc:
        if not is_llm_api_error(exc) and not isinstance(
            exc,
            (LLMError, RuntimeError, ValueError, json.JSONDecodeError),
        ):
            raise
        return {
            **fallback,
            "fallback_error": f"{type(exc).__name__}: {exc}",
        }


def compact_authorization_assessment(run: Any, provider: str) -> dict[str, Any]:
    assessment = run.assessment
    return {
        "status": "completed",
        "provider": provider,
        "overall_security_posture": assessment.get("overall_security_posture"),
        "test_summary": assessment.get("test_summary", ""),
        "tests": [
            {
                "test_id": item.get("test_id"),
                "name": item.get("name"),
                "result": item.get("result"),
                "summary": item.get("summary"),
                "action_ids": item.get("action_ids", []),
            }
            for item in assessment.get("tests", [])
        ],
        "findings": assessment.get("findings", []),
        "limitations": assessment.get("limitations", []),
        "http_requests": len(run.observations),
        "artifacts": {
            "run_dir": str(run.run_dir),
            "report": str(run.report_path),
            "assessment": str(run.assessment_path),
            "evidence": str(run.evidence_path),
            "execution_log": str(run.execution_log_path),
        },
    }


def build_campaign_graph(
    settings: Settings,
    provider: str = "gpt_oss",
    n_results: int = 5,
    graph_memory_path: Path | None = None,
):
    def gather_context(state: CampaignState) -> CampaignState:
        sources = retrieve_many(build_campaign_queries(state["goal"]), settings=settings, n_results=n_results)
        return {
            "sources": sources,
            "steps": append_step(state, "campaign orchestrator retrieved ATT&CK and red-team context"),
            "phases": append_phase(state, "scope validation", "success", "Safety boundary and campaign scope initialized."),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("retrieve_many", state["goal"], json.dumps(sources[:6], indent=2)),
            ],
            "tool_timeline": append_timeline(state, "retrieve_many", state["goal"], "success", f"Retrieved {len(sources)} context item(s)."),
        }

    def campaign_orchestrator(state: CampaignState) -> CampaignState:
        routing = plan_campaign_routing(state, settings)
        fallback = fallback_agent_output(
            "Campaign Orchestrator Agent",
            state["goal"],
            ["LangGraph", "MedFlow knowledge base", "shared safety boundary"],
            [
                "Define an authorized campaign with scoped validation phases.",
                "Route work to reconnaissance, identity, web/API, blockchain, and reporting agents.",
                "Require every role to produce evidence, guardrails, and a handoff.",
            ],
            [
                "Campaign charter",
                "Role tasking",
                "Success criteria centered on telemetry, detections, and remediation",
            ],
            "Reconnaissance Agent should collect attack-surface evidence before other agents refine their paths.",
        )
        output = call_role_llm(
            state,
            settings,
            "Campaign Orchestrator Agent",
            f"""
Create the overall campaign charter. Define phases, role tasking, constraints, decision points,
and success criteria. Do not provide exploit instructions.

Internal specialist routing decision:
{json.dumps(routing, indent=2)}
""",
            fallback,
        )
        output["evidence"] = {"campaign_routing": routing}
        return {
            "campaign_routing": routing,
            "agents": [*state.get("agents", []), output],
            "steps": append_step(state, "campaign orchestrator created the campaign charter"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace(
                    "campaign_specialist_router",
                    state["goal"],
                    json.dumps(routing, indent=2),
                ),
                make_trace(
                    "campaign_orchestrator",
                    state["goal"],
                    json.dumps(output, indent=2),
                ),
            ],
            "tool_timeline": append_timeline(
                state,
                "campaign_specialist_router",
                state["goal"],
                routing.get("generated_by", "unknown"),
                json.dumps(routing, indent=2),
            ),
        }

    def reconnaissance_agent(state: CampaignState) -> CampaignState:
        if not campaign_agent_selected(state, "reconnaissance"):
            return {
                "steps": append_step(
                    state,
                    "campaign router skipped the reconnaissance agent",
                ),
                "phases": append_phase(
                    state,
                    "reconnaissance",
                    "not_applicable",
                    "Not selected by the Campaign Orchestrator.",
                ),
            }
        tcp = state.get("tcp")
        services = state.get("services", [])
        http = state.get("http")
        web_routes = state.get("web_routes")
        fingerprints = state.get("web_fingerprint")
        web_checks = state.get("web_checks")
        web_assessment = state.get("web_assessment")
        traces = state.get("tool_traces", [])
        steps = state.get("steps", [])
        if state.get("execute_recon") and state.get("target"):
            target = validate_target(str(state["target"]))
            ports = state.get("ports") or default_ports_for_target(target)
            tcp = tcp_connect_check(target, ports=ports)
            open_ports = open_ports_from_tcp(tcp)
            recon_strategy = plan_recon_strategy(
                state["goal"],
                target,
                tcp,
                ports,
                provider=state.get("provider", "gpt_oss"),
                use_llm=state.get("use_llm", False),
            )
            service_scan_ports = recon_strategy.get("service_scan_ports") or open_ports or ports
            scan_profile = f"llm:{state.get('provider', 'gpt_oss')}" if state.get("use_llm") else None
            nmap_result = service_scan(target, ports=service_scan_ports, profile=scan_profile)
            services = parse_open_services(nmap_result.stdout)
            if not services and open_ports:
                services = infer_services_from_ports(open_ports)
            http_ports = (
                recon_strategy.get("http_probe_ports")
                or http_ports_from_services(services)
                or http_ports_from_scan(nmap_result.stdout, open_ports)
            )
            if http_ports:
                http = http_probe(target, ports=http_ports)
                fingerprints = web_fingerprint(target, ports=http_ports)
                web_routes = web_route_discovery(target, ports=http_ports)
                web_assessment = run_web_assessment(
                    target,
                    http_ports,
                    max_depth=2,
                    max_routes=80,
                    auth_contexts=state.get("web_auth_contexts", []),
                    provider=state.get("provider", "gpt_oss"),
                    use_llm=state.get("use_llm", False),
                    stateful_api=state.get("stateful_api", False),
                    execution_mode=state.get("execution_mode", "safe"),
                    stateful_max_requests=state.get("stateful_max_requests", 40),
                    stateful_max_workflows=state.get("stateful_max_workflows", 8),
                )
                http_status = observation_status(http, "http_probe")
                fingerprint_status = observation_status(fingerprints, "web_fingerprints")
                route_status = observation_status(web_routes, "web_routes")
                web_assessment_status = "confirmed_exposure" if web_assessment.get("findings") else "ran_no_finding"
            else:
                skip_reason = "No HTTP-like open services were observed; skipped web probing."
                http = {"http_probe": [], "skipped": True, "reason": skip_reason}
                fingerprints = {"web_fingerprints": [], "skipped": True, "reason": skip_reason}
                web_routes = {"web_routes": [], "skipped": True, "reason": skip_reason}
                web_assessment = {"routes": [], "findings": [], "skipped": True, "reason": skip_reason}
                http_status = "not_applicable"
                fingerprint_status = "not_applicable"
                route_status = "not_applicable"
                web_assessment_status = "not_applicable"
            web_checks = web_control_checks(web_routes, fingerprints)
            recon_step = "reconnaissance agent executed runtime TCP, service, and HTTP probes against the allowlisted target" if http_ports else "reconnaissance agent executed runtime TCP and service probes; skipped web probing because no HTTP-like services were observed"
            steps = [*steps, recon_step]
            timeline = state.get("tool_timeline", [])
            timeline = [
                *timeline,
                {"tool": "tcp_connect_check", "input": target, "status": "success", "evidence": f"{len(open_ports)} open TCP port(s)"},
                {"tool": "recon_strategy_planner", "input": target, "status": recon_strategy.get("generated_by", "unknown"), "evidence": json.dumps({k: v for k, v in recon_strategy.items() if k != "llm_raw"}, indent=2)[:1200]},
                {"tool": "service_scan", "input": " ".join(nmap_result.command or []), "status": "success" if nmap_result.returncode == 0 else "tool_error", "evidence": summarize_tool_result(nmap_result, max_chars=1200)},
                {"tool": "http_probe", "input": target, "status": http_status, "evidence": json.dumps(http, indent=2)[:1200]},
                {"tool": "web_fingerprint", "input": target, "status": fingerprint_status, "evidence": json.dumps(fingerprints, indent=2)[:1200]},
                {"tool": "web_route_discovery", "input": target, "status": route_status, "evidence": json.dumps(web_routes, indent=2)[:1200]},
                {"tool": "web_control_checks", "input": target, "status": findings_status(web_checks), "evidence": json.dumps(web_checks, indent=2)[:1200]},
                {"tool": "browser_web_collector", "input": target, "status": "success" if web_assessment.get("browser_observations", {}).get("available") else "not_applicable", "evidence": json.dumps(web_assessment.get("browser_observations", {}), indent=2)[:1200]},
                {"tool": "llm_web_planner", "input": target, "status": "success" if web_assessment.get("planned_probes") else "ran_no_finding", "evidence": json.dumps(web_assessment.get("planned_probes", []), indent=2)[:1200]},
                {"tool": "bounded_web_executor", "input": target, "status": "success" if web_assessment.get("probe_results") else "not_applicable", "evidence": json.dumps(web_assessment.get("probe_results", []), indent=2)[:1200]},
                {
                    "tool": "stateful_api_agent",
                    "input": target,
                    "status": web_assessment.get("stateful_api", {}).get("status", "not_applicable"),
                    "evidence": json.dumps(
                        {
                            "schema": web_assessment.get("stateful_api", {}).get("schema"),
                            "operations": len(web_assessment.get("stateful_api", {}).get("operations", [])),
                            "workflows": len(web_assessment.get("stateful_api", {}).get("workflows", [])),
                            "findings": web_assessment.get("stateful_api", {}).get("findings", []),
                            "request_budget": web_assessment.get("stateful_api", {}).get("request_budget"),
                        },
                        indent=2,
                    )[:1200],
                },
                {"tool": "web_app_assessment", "input": target, "status": web_assessment_status, "evidence": json.dumps({"routes": len(web_assessment.get("routes", [])), "findings": web_assessment.get("findings", []), "graph_summary": web_assessment.get("graph_summary", {})}, indent=2)[:1200]},
            ]
            traces = [
                *traces,
                make_trace("tcp_connect_check", target, json.dumps(tcp, indent=2)),
                make_trace("recon_strategy_planner", target, json.dumps(recon_strategy, indent=2)),
                make_trace("service_scan", " ".join(nmap_result.command or []), summarize_tool_result(nmap_result)),
                make_trace("http_probe", target, json.dumps(http, indent=2)),
                make_trace("web_fingerprint", target, json.dumps(fingerprints, indent=2)),
                make_trace("web_route_discovery", target, json.dumps(web_routes, indent=2)),
                make_trace("web_control_checks", target, json.dumps(web_checks, indent=2)),
                make_trace("web_app_assessment", target, json.dumps(web_assessment, indent=2)),
            ]
            sources = retrieve_many(build_campaign_queries(state["goal"], services), settings=settings, n_results=n_results)
        else:
            sources = state.get("sources", [])
            timeline = state.get("tool_timeline", [])

        graph_memory = state.get("graph_memory", {})
        if services:
            try:
                store = GraphStore.load(graph_memory_path or Path("data/graph/medflow_graph.json"))
                graph_memory = store.campaign_memory(state.get("target"), services, limit=10)
                timeline = [
                    *timeline,
                    {
                        "tool": "graph_memory_search",
                        "input": str(state.get("target") or state["goal"]),
                        "status": "success",
                        "evidence": f"{len(graph_memory.get('hits', []))} prior graph item(s) matched.",
                    },
                ]
            except Exception as exc:
                graph_memory = {"error": repr(exc), "hits": []}
                timeline = [
                    *timeline,
                    {
                        "tool": "graph_memory_search",
                        "input": str(state.get("target") or state["goal"]),
                        "status": "tool_error",
                        "evidence": repr(exc),
                    },
                ]

        fallback = fallback_agent_output(
            "Reconnaissance Agent",
            state["goal"],
            ["runtime TCP check", "runtime service scan", "runtime HTTP probes", "asset inventory placeholder"],
            [
                "Use only allowlisted targets for active probing.",
                "Classify exposed services and likely attack surfaces.",
                "Pass observed infrastructure context to downstream agents.",
            ],
            ["Attack-surface summary", "Infrastructure evidence", "Recon handoff"],
            "Identity and Web/API agents should use discovered services to focus validation ideas.",
        )
        output = call_role_llm(
            {**state, "services": services, "sources": sources, "agents": state.get("agents", [])},
            settings,
            "Reconnaissance Agent",
            """
Act as a separate reconnaissance agent. Summarize assets, attack surfaces, likely infrastructure class,
tools used or proposed, and the handoff to identity/web/API/blockchain agents.
""",
            fallback,
        )
        output["evidence"] = {
            "services": services,
            "http": http or {},
            "web_fingerprint": fingerprints or {},
            "web_routes": web_routes or {},
            "web_assessment": web_assessment or {},
            "tcp": tcp or {},
        }
        return {
            "tcp": tcp,
            "services": services,
            "http": http,
            "web_fingerprint": fingerprints,
            "web_routes": web_routes,
            "web_checks": web_checks,
            "web_assessment": web_assessment,
            "recon_strategy": recon_strategy if state.get("execute_recon") and state.get("target") else state.get("recon_strategy"),
            "graph_memory": graph_memory,
            "sources": sources,
            "agents": [*state.get("agents", []), output],
            "steps": [*steps, "reconnaissance agent produced infrastructure handoff"],
            "phases": append_phase({**state, "phases": state.get("phases", [])}, "reconnaissance", "success" if services else "ran_no_finding", f"Observed {len(services)} service(s)."),
            "tool_traces": [*traces, make_trace("reconnaissance_agent", state["goal"], json.dumps(output, indent=2))],
            "tool_timeline": [*timeline, {"tool": "reconnaissance_agent", "input": state["goal"], "status": "success", "evidence": output.get("handoff", "")}],
        }

    def capability_validation_agent(state: CampaignState) -> CampaignState:
        if not campaign_agent_selected(state, "capability_validation"):
            return {
                "steps": append_step(
                    state,
                    "campaign router skipped the capability validation agent",
                ),
                "phases": append_phase(
                    state,
                    "validation execution",
                    "not_applicable",
                    "Not selected by the Campaign Orchestrator.",
                ),
            }
        if not state.get("execute_validation", False):
            return {
                "steps": append_step(state, "skipped capability validation execution"),
                "phases": append_phase(state, "validation execution", "not_applicable", "Capability validation was not requested."),
            }
        if not state.get("target"):
            return {
                "steps": append_step(state, "skipped capability validation because no target was supplied"),
                "phases": append_phase(state, "validation execution", "not_applicable", "No live target was supplied."),
            }
        if not state.get("services"):
            return {
                "steps": append_step(state, "skipped capability validation because no open services were observed"),
                "phases": append_phase(state, "validation execution", "not_applicable", "No open services were observed."),
            }

        selection = select_exploit_candidate(
            str(state["target"]),
            state.get("services", []),
            limit=state.get("max_capabilities", 5),
            web_routes={**state.get("web_routes", {}), "web_fingerprints": (state.get("web_fingerprint") or {}).get("web_fingerprints", [])},
            graph_memory=state.get("graph_memory"),
        )
        validation_strategy = plan_validation_strategy(
            state["goal"],
            str(state["target"]),
            state.get("services", []),
            selection,
            max_capabilities=state.get("max_capabilities", 5),
            provider=state.get("provider", "gpt_oss"),
            use_llm=state.get("use_llm", False),
        )
        selection = apply_validation_strategy(selection, validation_strategy)
        validation = run_selected_exploit(
            str(state["target"]),
            selection,
            execution_mode=state.get("execution_mode", "safe"),
            metasploit_action=state.get("metasploit_action", "check"),
            provider=state.get("provider", "gpt_oss"),
            use_llm=state.get("use_llm", False),
        )
        output = agent_to_dict(
            AgentOutput(
                role="Capability Validation Agent",
                objective="Select and execute applicable validation capabilities from observed service evidence.",
                tools=["generated Python validation tools", "gated Metasploit runner", "provider metadata ranking", "capability cache"],
                decisions=[
                    f"Selected {len(selection.get('selected_candidates', []))} capability candidate(s).",
                    f"Execution mode: {state.get('execution_mode', 'safe')}.",
                    f"Metasploit action: {state.get('metasploit_action', 'check')}.",
                    "Treat positive proof as verification; do not treat clean tool exit as exploitation success.",
                ],
                outputs=[
                    f"Attempted {validation.get('attempted', 0)} validation action(s).",
                    f"Verified {validation.get('successful', 0)} validation result(s).",
                ],
                handoff="Reporting Agent should include selected capabilities, failed checks, and positive evidence separately.",
                evidence={"selection": selection, "validation": validation},
            )
        )
        return {
            "capability_selection": selection,
            "capability_validation": validation,
            "validation_strategy": validation_strategy,
            "agents": [*state.get("agents", []), output],
            "steps": append_step(state, "capability validation agent selected and executed matching validation tools"),
            "phases": append_phase(
                state,
                "validation execution",
                "success" if validation.get("successful", 0) else "ran_no_finding",
                f"{validation.get('successful', 0)}/{validation.get('attempted', 0)} capability checks produced positive evidence.",
            ),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("select_exploit_candidate", str(state["target"]), json.dumps(selection, indent=2)),
                make_trace("validation_strategy_planner", str(state["target"]), json.dumps(validation_strategy, indent=2)),
                make_trace("run_selected_exploit", str(state["target"]), json.dumps(validation, indent=2)),
            ],
            "tool_timeline": [
                *state.get("tool_timeline", []),
                {
                    "tool": "validation_strategy_planner",
                    "input": str(state["target"]),
                    "status": validation_strategy.get("generated_by", "unknown"),
                    "evidence": json.dumps({k: v for k, v in validation_strategy.items() if k != "llm_raw"}, indent=2)[:1200],
                },
                {
                    "tool": "select_exploit_candidate",
                    "input": str(state["target"]),
                    "status": selection.get("decision", "unknown"),
                    "evidence": json.dumps(
                        [
                            {
                                "id": item.get("id"),
                                "score": item.get("score"),
                                "why": item.get("score_explanation"),
                            }
                            for item in selection.get("selected_candidates", [])
                        ],
                        indent=2,
                    )[:1200],
                },
                *[
                    {
                        "tool": item.get("runner") or item.get("selected_exploit_id", ""),
                        "input": item.get("selected_exploit_id", ""),
                        "status": item.get("status", "unknown"),
                        "evidence": (item.get("proof_output") or item.get("reason") or "")[:1200],
                    }
                    for item in validation.get("results", [])
                ],
            ],
        }

    def authentication_contract_agent(state: CampaignState) -> CampaignState:
        wants_wordlist = campaign_agent_selected(state, "wordlist_attack")
        wants_spray = campaign_agent_selected(state, "password_spray")
        missing_wordlist = wants_wordlist and not state.get(
            "wordlist_attack_config"
        )
        missing_spray = wants_spray and not state.get(
            "password_spray_config"
        )
        if not (missing_wordlist or missing_spray):
            return {
                "steps": append_step(
                    state,
                    "authentication contract discovery was not needed",
                )
            }

        target_url = str(state.get("target_url") or "")
        if not state.get("autonomous_identity_enabled") or not target_url:
            public = {
                "status": "blocked_by_safety_policy",
                "generated_by": "policy_gate",
                "confidence": "low",
                "contract": None,
                "evidence": [],
                "missing_prerequisites": [
                    "Autonomous credential testing requires an LLM-enabled private URL "
                    "campaign in aggressive_lab mode."
                ],
                "reasoning": "",
            }
            return {
                "authentication_discovery": public,
                "steps": append_step(
                    state,
                    "authentication contract discovery was blocked by its execution gate",
                ),
                "phases": append_phase(
                    state,
                    "authentication contract discovery",
                    "blocked_by_safety_policy",
                    public["missing_prerequisites"][0],
                ),
                "tool_timeline": append_timeline(
                    state,
                    "authentication_contract_agent",
                    target_url,
                    "blocked_by_safety_policy",
                    json.dumps(public, indent=2),
                ),
            }

        discovery = discover_authentication_contract(
            state["goal"],
            target_url,
            provider=state.get("provider", "gpt_oss"),
            require_wordlist_identity=missing_wordlist,
        )
        public = discovery.public_result()
        wordlist_config = state.get("wordlist_attack_config")
        spray_config = state.get("password_spray_config")
        contract = discovery.contract
        trace_root = state.get(
            "identity_output_root",
            Path("reports/redteam_campaign/identity_agents"),
        )
        trace_stamp = (
            f"{time.strftime('%Y%m%d-%H%M%S')}-"
            f"{time.time_ns() % 1_000_000_000:09d}"
        )
        if contract and missing_wordlist and contract.wordlist_identity:
            wordlist_config = WordlistAttackConfig(
                target_url=target_url,
                endpoint=contract.endpoint,
                username=contract.wordlist_identity,
                username_field=contract.username_field,
                password_field=contract.password_field,
                request_format=contract.request_format,
                static_fields=dict(contract.static_fields),
                headers=dict(contract.headers),
                success_statuses=contract.success_statuses,
                failure_statuses=contract.failure_statuses,
                success_json_paths=contract.success_json_paths,
                execution_mode=state.get("execution_mode", "safe"),
                execute=True,
                trace_path=trace_root
                / f"wordlist_attempts_{trace_stamp}.jsonl",
            )
        if contract and missing_spray:
            spray_config = PasswordSprayConfig(
                target_url=target_url,
                endpoint=contract.endpoint,
                username_template=contract.username_template,
                username_field=contract.username_field,
                password_field=contract.password_field,
                request_format=contract.request_format,
                static_fields=dict(contract.static_fields),
                headers=dict(contract.headers),
                success_statuses=contract.success_statuses,
                failure_statuses=contract.failure_statuses,
                success_json_paths=contract.success_json_paths,
                execution_mode=state.get("execution_mode", "safe"),
                execute=True,
                trace_path=trace_root
                / f"password_spray_attempts_{trace_stamp}.jsonl",
            )

        output = agent_to_dict(
            AgentOutput(
                role="Authentication Contract Agent",
                objective=(
                    "Discover the authorized lab login contract before credential "
                    "validation without submitting credentials during discovery."
                ),
                tools=[
                    "bounded same-origin HTTP inspector",
                    "HTML form and API-description parser",
                    f"{state.get('provider', 'gpt_oss')} evidence reasoner",
                ],
                decisions=[
                    "Accept only endpoints, fields, and headers grounded in prompt or target evidence.",
                    "Treat a wordlist identity as a supplied prerequisite rather than a guess.",
                    "Keep target response content and header values out of the campaign summary.",
                ],
                outputs=[
                    f"Discovery status: {public['status']}",
                    (
                        f"Login endpoint: {public.get('contract', {}).get('endpoint')}"
                        if public.get("contract")
                        else "No executable login contract"
                    ),
                    (
                        "Missing prerequisites: "
                        + ", ".join(public.get("missing_prerequisites") or [])
                        if public.get("missing_prerequisites")
                        else "No missing prerequisites"
                    ),
                ],
                handoff=(
                    "The wordlist and password-spray agents receive only the validated "
                    "runtime contract."
                ),
                evidence=public,
            )
        )
        phase_status = {
            "ready": "success",
            "partial": "inconclusive",
            "missing_prerequisite": "inconclusive",
            "tool_error": "tool_error",
        }.get(public["status"], "ran_no_finding")
        return {
            "authentication_discovery": public,
            "wordlist_attack_config": wordlist_config,
            "password_spray_config": spray_config,
            "agents": [*state.get("agents", []), output],
            "steps": append_step(
                state,
                "authentication contract agent completed evidence-grounded discovery",
            ),
            "phases": append_phase(
                state,
                "authentication contract discovery",
                phase_status,
                (
                    f"status={public['status']}; "
                    f"resources={len(public.get('evidence') or [])}; "
                    f"missing={len(public.get('missing_prerequisites') or [])}."
                ),
            ),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace(
                    "authentication_contract_agent",
                    target_url,
                    json.dumps(public, indent=2),
                ),
            ],
            "tool_timeline": append_timeline(
                state,
                "authentication_contract_agent",
                target_url,
                phase_status,
                json.dumps(public, indent=2),
            ),
        }

    def wordlist_attack_agent(state: CampaignState) -> CampaignState:
        config = state.get("wordlist_attack_config")
        selected = campaign_agent_selected(state, "wordlist_attack")
        if selected and not config:
            discovery = state.get("authentication_discovery") or {}
            result = {
                "agent": "Wordlist Attack Agent",
                "status": "missing_prerequisite",
                "target_url": state.get("target_url"),
                "attempted": 0,
                "successful": 0,
                "successes": [],
                "stop_reason": "authentication_contract_unavailable",
                "missing_prerequisites": discovery.get(
                    "missing_prerequisites",
                    ["No validated authentication contract was available."],
                ),
            }
            return {
                "wordlist_attack": result,
                "steps": append_step(
                    state,
                    "wordlist attack agent stopped because its authentication prerequisites were unavailable",
                ),
                "phases": append_phase(
                    state,
                    "password wordlist validation",
                    "inconclusive",
                    "; ".join(result["missing_prerequisites"]),
                ),
                "tool_timeline": append_timeline(
                    state,
                    "wordlist_attack_agent",
                    str(state.get("target_url") or ""),
                    "missing_prerequisite",
                    json.dumps(result, indent=2),
                ),
            }
        if not config or not selected:
            return {
                "steps": append_step(
                    state,
                    "campaign router skipped the wordlist attack agent",
                )
            }
        try:
            result = WordlistAttackAgent(config).run()
        except Exception as exc:
            result = {
                "agent": "Wordlist Attack Agent",
                "status": "tool_error",
                "target_url": config.target_url,
                "endpoint": config.endpoint,
                "error": f"{type(exc).__name__}: {exc}",
                "successes": [],
            }
        output = agent_to_dict(
            AgentOutput(
                role="Wordlist Attack Agent",
                objective=(
                    "Test a bounded password wordlist against one explicitly configured "
                    "identity on the authorized lab origin."
                ),
                tools=[
                    "SecLists common-credential subset",
                    "same-origin HTTP authentication client",
                    "lockout and rate-limit circuit breaker",
                ],
                decisions=[
                    "Reject targets outside the configured local lab allowlist.",
                    "Stop on the first accepted credential, HTTP 423/429, or the attempt budget.",
                    "Never retain plaintext passwords, response values, or session tokens.",
                ],
                outputs=[
                    f"{result.get('attempted', 0)} candidate password(s) tested",
                    f"{result.get('successful', 0)} accepted credential(s)",
                    f"Complete attempt trace: {result.get('trace_path') or 'not requested'}",
                ],
                handoff=(
                    "Identity and reporting specialists should compare this concentrated "
                    "attack with the Password Spray Agent's distributed attempt pattern."
                ),
                evidence=result,
            )
        )
        status = result.get("status", "tool_error")
        return {
            "wordlist_attack": result,
            "agents": [*state.get("agents", []), output],
            "steps": append_step(
                state,
                "wordlist attack agent completed bounded one-account credential validation",
            ),
            "phases": append_phase(
                state,
                "password wordlist validation",
                status,
                (
                    f"{result.get('successful', 0)}/{result.get('attempted', 0)} "
                    f"attempt(s) authenticated; stop={result.get('stop_reason', 'tool_error')}."
                ),
            ),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace(
                    "wordlist_attack_agent",
                    config.target_url,
                    json.dumps(truncate_value(result, 1_200), indent=2),
                ),
            ],
            "tool_timeline": append_timeline(
                state,
                "wordlist_attack_agent",
                config.target_url,
                status,
                json.dumps(
                    {
                        "endpoint": result.get("endpoint"),
                        "attempted": result.get("attempted", 0),
                        "successful": result.get("successful", 0),
                        "outcome_counts": result.get("outcome_counts", {}),
                        "stop_reason": result.get("stop_reason"),
                        "trace_path": result.get("trace_path"),
                        "error": result.get("error"),
                    },
                    indent=2,
                ),
            ),
        }

    def identity_attack_agent(state: CampaignState) -> CampaignState:
        if not campaign_agent_selected(state, "identity_attack"):
            return {
                "steps": append_step(
                    state,
                    "campaign router skipped the identity attack agent",
                )
            }
        fallback = fallback_agent_output(
            "Identity Attack Agent",
            state["goal"],
            ["BloodHound placeholder", "SharpHound placeholder", "Impacket placeholder", "Kerbrute placeholder", "IdP/SIEM telemetry"],
            [
                "Model identity paths without attempting real logins.",
                "Validate controls with synthetic password-spray, MFA-fatigue, and device-registration telemetry.",
                "Prioritize detections for suspicious MFA approvals and new device enrollment.",
            ],
            ["Identity attack path hypotheses", "Telemetry requirements", "Detection validation checklist"],
            "Web/API agent should connect identity outcomes to portal authorization and session controls.",
        )
        output = call_role_llm(
            state,
            settings,
            "Identity Attack Agent",
            """
Act as a separate identity attack agent. Produce safe identity validation objectives using BloodHound,
SharpHound, Impacket, and Kerbrute as tool families, but do not include live attack commands or credential steps.
Focus on AD relationships, risky paths, MFA fatigue, device registration, and detection telemetry.
""",
            fallback,
        )
        return {
            "agents": [*state.get("agents", []), output],
            "steps": append_step(state, "identity attack agent produced identity validation path"),
            "tool_traces": [*state.get("tool_traces", []), make_trace("identity_attack_agent", state["goal"], json.dumps(output, indent=2))],
        }

    def password_spray_agent(state: CampaignState) -> CampaignState:
        config = state.get("password_spray_config")
        selected = campaign_agent_selected(state, "password_spray")
        if selected and not config:
            discovery = state.get("authentication_discovery") or {}
            result = {
                "agent": "Password Spray Agent",
                "status": "missing_prerequisite",
                "target_url": state.get("target_url"),
                "attempted": 0,
                "successful": 0,
                "successes": [],
                "stop_reason": "authentication_contract_unavailable",
                "missing_prerequisites": discovery.get(
                    "missing_prerequisites",
                    ["No validated authentication contract was available."],
                ),
            }
            return {
                "password_spray": result,
                "steps": append_step(
                    state,
                    "password spray agent stopped because its authentication prerequisites were unavailable",
                ),
                "phases": append_phase(
                    state,
                    "password spray validation",
                    "inconclusive",
                    "; ".join(result["missing_prerequisites"]),
                ),
                "tool_timeline": append_timeline(
                    state,
                    "password_spray_agent",
                    str(state.get("target_url") or ""),
                    "missing_prerequisite",
                    json.dumps(result, indent=2),
                ),
            }
        if not config or not selected:
            return {
                "steps": append_step(
                    state,
                    "campaign router skipped the password spray agent",
                )
            }
        try:
            result = PasswordSprayAgent(config).run()
        except Exception as exc:
            result = {
                "agent": "Password Spray Agent",
                "status": "tool_error",
                "target_url": config.target_url,
                "endpoint": config.endpoint,
                "error": f"{type(exc).__name__}: {exc}",
                "successes": [],
            }
        output = agent_to_dict(
            AgentOutput(
                role="Password Spray Agent",
                objective=(
                    "Validate common credentials against an explicitly configured lab "
                    "authentication contract using a bounded spray pattern."
                ),
                tools=[
                    "SecLists username and common-credential subsets",
                    "same-origin HTTP authentication client",
                    "lockout and rate-limit circuit breaker",
                ],
                decisions=[
                    "Try one candidate password across identities before advancing.",
                    "Stop immediately on HTTP 423/429 or the configured success threshold.",
                    "Never retain plaintext passwords, response values, or session tokens.",
                ],
                outputs=[
                    f"{result.get('attempted', 0)} authentication attempt(s)",
                    f"{result.get('successful', 0)} accepted credential(s)",
                    f"Stop reason: {result.get('stop_reason', 'tool error')}",
                ],
                handoff=(
                    "Identity and reporting specialists should map any accepted credential "
                    "to password policy, MFA, lockout, and detection controls."
                ),
                evidence=result,
            )
        )
        status = result.get("status", "tool_error")
        return {
            "password_spray": result,
            "agents": [*state.get("agents", []), output],
            "steps": append_step(
                state,
                "password spray agent completed bounded authentication validation",
            ),
            "phases": append_phase(
                state,
                "password spray validation",
                status,
                (
                    f"{result.get('successful', 0)}/{result.get('attempted', 0)} "
                    f"attempt(s) authenticated; stop={result.get('stop_reason', 'tool_error')}."
                ),
            ),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace(
                    "password_spray_agent",
                    config.target_url,
                    json.dumps(truncate_value(result, 1_200), indent=2),
                ),
            ],
            "tool_timeline": append_timeline(
                state,
                "password_spray_agent",
                config.target_url,
                status,
                json.dumps(
                    {
                        "endpoint": result.get("endpoint"),
                        "attempted": result.get("attempted", 0),
                        "successful": result.get("successful", 0),
                        "outcome_counts": result.get("outcome_counts", {}),
                        "stop_reason": result.get("stop_reason"),
                        "trace_path": result.get("trace_path"),
                        "error": result.get("error"),
                    },
                    indent=2,
                ),
            ),
        }

    def web_api_attack_agent(state: CampaignState) -> CampaignState:
        if not (
            campaign_agent_selected(state, "web_api_attack")
            or campaign_agent_selected(state, "authorization_assessment")
        ):
            return {
                "steps": append_step(
                    state,
                    "campaign router skipped the web/API attack agent",
                ),
                "authorization_assessment": {
                    "status": "not_selected",
                    "routing_reason": (
                        state.get("campaign_routing") or {}
                    ).get("authorization_reason", ""),
                },
            }
        routing = state.get("campaign_routing") or {}
        authorization_assessment: dict[str, Any] = {}
        traces = list(state.get("tool_traces", []))
        timeline = list(state.get("tool_timeline", []))
        steps = list(state.get("steps", []))
        phases = list(state.get("phases", []))
        if routing.get("run_authorization_assessment") and state.get("target_url"):
            try:
                authorization_run = run_inline_authorization_assessment(
                    state["goal"],
                    str(state["target_url"]),
                    output_root=state.get(
                        "authorization_output_root",
                        Path("reports/redteam_campaign/authorization"),
                    ),
                    request_budget=state.get("authorization_request_budget", 30),
                    max_tool_rounds=state.get("authorization_tool_rounds", 3),
                    provider=state.get("provider", "gpt_oss"),
                    allow_mutating_methods=(
                        state.get("execution_mode", "safe") == "aggressive_lab"
                    ),
                )
                authorization_assessment = compact_authorization_assessment(
                    authorization_run,
                    state.get("provider", "gpt_oss"),
                )
                posture = str(
                    authorization_assessment.get("overall_security_posture")
                    or "unknown"
                )
                authorization_status = {
                    "vulnerable": "confirmed_exposure",
                    "secure": "success",
                    "inconclusive": "inconclusive",
                }.get(posture, "ran_no_finding")
                timeline.append(
                    {
                        "tool": "autonomous_authorization_subworkflow",
                        "input": str(state["target_url"]),
                        "status": authorization_status,
                        "evidence": json.dumps(
                            {
                                "posture": posture,
                                "tests": authorization_assessment.get("tests", []),
                                "http_requests": authorization_assessment.get(
                                    "http_requests", 0
                                ),
                                "artifacts": authorization_assessment.get(
                                    "artifacts", {}
                                ),
                            },
                            indent=2,
                        )[:1_200],
                    }
                )
                phases = append_phase(
                    {**state, "phases": phases},
                    "authorization assessment",
                    authorization_status,
                    (
                        f"Internal Web/API subworkflow made "
                        f"{authorization_assessment.get('http_requests', 0)} bounded HTTP "
                        f"request(s); posture={posture}."
                    ),
                )
                steps.append(
                    "web/API agent completed the routed autonomous authorization subworkflow"
                )
                traces.append(
                    make_trace(
                        "autonomous_authorization_subworkflow",
                        str(state["target_url"]),
                        json.dumps(authorization_assessment, indent=2),
                    )
                )
            except Exception as exc:
                authorization_assessment = {
                    "status": "tool_error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "routing_reason": routing.get("authorization_reason", ""),
                }
                timeline.append(
                    {
                        "tool": "autonomous_authorization_subworkflow",
                        "input": str(state["target_url"]),
                        "status": "tool_error",
                        "evidence": authorization_assessment["error"][:1_200],
                    }
                )
                phases = append_phase(
                    {**state, "phases": phases},
                    "authorization assessment",
                    "tool_error",
                    authorization_assessment["error"],
                )
                steps.append(
                    "web/API agent recorded an authorization subworkflow error"
                )
        elif state.get("target_url"):
            authorization_assessment = {
                "status": "not_selected",
                "routing_reason": routing.get("authorization_reason", ""),
            }

        fallback = fallback_agent_output(
            "Web/API Attack Agent",
            state["goal"],
            ["Burp Suite placeholder", "OWASP ZAP placeholder", "Postman placeholder", "HTTP probe evidence"],
            [
                "Discover portal/API endpoints through passive and authenticated-test evidence.",
                "Validate authorization and business-logic controls with synthetic users.",
                "Avoid destructive fuzzing and real patient data access.",
            ],
            ["Endpoint validation plan", "Authorization test matrix", "Healthcare-specific business logic checks"],
            "Reporting Agent should map web/API checks to findings, controls, and limitations.",
        )
        output = call_role_llm(
            {**state, "authorization_assessment": authorization_assessment},
            settings,
            "Web/API Attack Agent",
            f"""
Act as a separate web and API attack agent. Use Burp Suite, OWASP ZAP, and Postman as tool families.
Focus on endpoint discovery, authorization control validation, business logic abuse hypotheses,
logging expectations, and safe test data.

Internally routed authorization evidence:
{json.dumps(authorization_assessment, indent=2)[:6_000]}
""",
            fallback,
        )
        output["evidence"] = {
            "campaign_routing": routing,
            "authorization_assessment": authorization_assessment,
        }
        return {
            "authorization_assessment": authorization_assessment,
            "agents": [*state.get("agents", []), output],
            "steps": [
                *steps,
                "web/API attack agent produced portal and API validation path",
            ],
            "phases": phases,
            "tool_traces": [
                *traces,
                make_trace(
                    "web_api_attack_agent",
                    state["goal"],
                    json.dumps(output, indent=2),
                ),
            ],
            "tool_timeline": timeline,
        }

    def blockchain_security_agent(state: CampaignState) -> CampaignState:
        if not campaign_agent_selected(state, "blockchain_security"):
            return {
                "steps": append_step(
                    state,
                    "campaign router skipped the blockchain security agent",
                )
            }
        goal_text = state["goal"].lower()
        blockchain_in_scope = any(term in goal_text for term in ["blockchain", "smart contract", "wallet", "token", "chain"])
        fallback = fallback_agent_output(
            "Blockchain Security Agent",
            state["goal"],
            ["Slither placeholder", "Mythril placeholder", "Hardhat placeholder"],
            [
                "Determine whether blockchain components are in scope.",
                "If in scope, validate smart-contract permissions, event logs, and unusual wallet activity.",
                "If not in scope, record a non-applicability decision and monitoring assumptions.",
            ],
            ["Blockchain scope decision", "Smart-contract validation plan if applicable", "Fraud-monitoring telemetry expectations"],
            "Reporting Agent should include blockchain as applicable or explicitly out of scope.",
        )
        output = call_role_llm(
            state,
            settings,
            "Blockchain Security Agent",
            f"""
Act as a separate blockchain security agent. Blockchain in-scope hint: {blockchain_in_scope}.
Use Slither, Mythril, and Hardhat as tool families. If the goal does not mention blockchain, clearly state
that blockchain testing is not applicable for this campaign and list only monitoring assumptions.
""",
            fallback,
        )
        output["evidence"] = {"blockchain_in_scope": blockchain_in_scope}
        return {
            "agents": [*state.get("agents", []), output],
            "steps": append_step(state, "blockchain security agent produced scope decision"),
            "tool_traces": [*state.get("tool_traces", []), make_trace("blockchain_security_agent", state["goal"], json.dumps(output, indent=2))],
        }

    def reporting_agent(state: CampaignState) -> CampaignState:
        draft = compact_reporting_draft(state)
        safety_review = safety_review_tool(json.dumps(draft, indent=2))
        prompt = f"""
You are the Reporting Agent for a MedFlow multi-agent red-team campaign.

{SAFETY_BOUNDARY}

Campaign state:
{json.dumps(draft, indent=2)}

Safety review:
{safety_review}

Write the final campaign brief with:
1. Executive summary
2. Multi-agent workflow
3. Campaign phases
4. Role-by-role outputs
5. Tool integrations
6. Evidence and telemetry to collect
7. ATT&CK/detection mapping from retrieved evidence only
8. Safety constraints
9. Limitations and next implementation work
"""
        fallback_report = deterministic_campaign_report(state, safety_review)
        try:
            if not state.get("use_llm", True):
                raise RuntimeError("LLM disabled for deterministic campaign run.")
            report = call_redteam_llm(prompt, settings=settings, provider=state.get("provider", "gpt_oss"))
        except Exception as exc:
            if not is_llm_api_error(exc) and not isinstance(exc, (LLMError, RuntimeError)):
                raise
            report = f"{fallback_report}\n\nLLM fallback used: {exc}"
        output = agent_to_dict(
            AgentOutput(
                role="Reporting Agent",
                objective="Convert role outputs into executive and technical campaign reporting.",
                tools=["Markdown report", "JSON trace", "ATT&CK evidence", "safety review"],
                decisions=["Separate observed evidence from planning assumptions.", "Record safety constraints and missing integrations."],
                outputs=["Final campaign brief", "Role-by-role summary", "Limitations and next work"],
                handoff="Campaign report is ready for milestone evidence and implementation planning.",
                evidence={"safety_review": safety_review},
            )
        )
        return {
            "agents": [*state.get("agents", []), output],
            "report": report,
            "safety_review": safety_review,
            "steps": append_step(state, "reporting agent produced final campaign brief"),
            "phases": append_phase(state, "reporting", "success", "Final campaign report and JSON trace produced."),
            "tool_traces": [*state.get("tool_traces", []), make_trace("reporting_agent", state["goal"], report)],
            "tool_timeline": [
                *state.get("tool_timeline", []),
                {"tool": "reporting_agent", "input": state["goal"], "status": "success", "evidence": "Final report generated."},
            ],
        }

    graph = StateGraph(CampaignState)
    graph.add_node("gather_context", gather_context)
    graph.add_node("campaign_orchestrator", campaign_orchestrator)
    graph.add_node("reconnaissance_agent", reconnaissance_agent)
    graph.add_node("capability_validation_agent", capability_validation_agent)
    graph.add_node(
        "authentication_contract_agent",
        authentication_contract_agent,
    )
    graph.add_node("wordlist_attack_agent", wordlist_attack_agent)
    graph.add_node("identity_attack_agent", identity_attack_agent)
    graph.add_node("password_spray_agent", password_spray_agent)
    graph.add_node("web_api_attack_agent", web_api_attack_agent)
    graph.add_node("blockchain_security_agent", blockchain_security_agent)
    graph.add_node("reporting_agent", reporting_agent)

    graph.set_entry_point("gather_context")
    graph.add_edge("gather_context", "campaign_orchestrator")
    graph.add_edge("campaign_orchestrator", "reconnaissance_agent")
    graph.add_edge("reconnaissance_agent", "capability_validation_agent")
    graph.add_edge(
        "capability_validation_agent",
        "authentication_contract_agent",
    )
    graph.add_edge("authentication_contract_agent", "wordlist_attack_agent")
    graph.add_edge("wordlist_attack_agent", "identity_attack_agent")
    graph.add_edge("identity_attack_agent", "password_spray_agent")
    graph.add_edge("password_spray_agent", "web_api_attack_agent")
    graph.add_edge("web_api_attack_agent", "blockchain_security_agent")
    graph.add_edge("blockchain_security_agent", "reporting_agent")
    graph.add_edge("reporting_agent", END)
    return graph.compile()


def deterministic_campaign_report(state: CampaignState, safety_review: str) -> str:
    lines = [
        "# MedFlow Multi-Agent Red-Team Campaign",
        "",
        f"Goal: {state['goal']}",
        (
            f"Target: {state.get('target_url') or state.get('target') or 'tabletop / no live target'}"
        ),
        "",
        "## Multi-Agent Workflow",
    ]
    for agent in state.get("agents", []):
        lines.extend(
            [
                f"### {agent.get('role')}",
                f"Objective: {agent.get('objective')}",
                "Tools: " + ", ".join(agent.get("tools", [])),
                "Decisions:",
                *[f"- {item}" for item in agent.get("decisions", [])],
                "Outputs:",
                *[f"- {item}" for item in agent.get("outputs", [])],
                f"Handoff: {agent.get('handoff', '')}",
                "",
            ]
        )
    lines.extend(["## Campaign Phases"])
    for phase in state.get("phases", []):
        lines.append(f"- {phase.get('phase')}: {phase.get('status')} - {phase.get('evidence', '')}")
    graph_memory = state.get("graph_memory") or {}
    if graph_memory.get("hits"):
        lines.extend(
            [
                "",
                "## Graph Memory Used",
                *[
                    f"- {hit.get('type')} `{hit.get('name')}` score={hit.get('score')}"
                    for hit in graph_memory.get("hits", [])[:8]
                ],
            ]
        )
    if state.get("tool_timeline"):
        lines.extend(["", "## Tool Timeline"])
        for item in state.get("tool_timeline", [])[:30]:
            lines.append(f"- {item.get('tool')}: {item.get('status')} - {item.get('evidence', '')[:180]}")
    authorization = state.get("authorization_assessment") or {}
    if authorization:
        lines.extend(
            [
                "",
                "## Authorization Assessment",
                f"- Status: {authorization.get('status', 'unknown')}",
                f"- Posture: {authorization.get('overall_security_posture', 'not assessed')}",
                f"- HTTP requests: {authorization.get('http_requests', 0)}",
                *[
                    f"- {item.get('name')}: {item.get('result')} - {item.get('summary', '')}"
                    for item in authorization.get("tests", [])
                ],
            ]
        )
    authentication_discovery = state.get("authentication_discovery") or {}
    if authentication_discovery:
        contract = authentication_discovery.get("contract") or {}
        lines.extend(
            [
                "",
                "## Authentication Contract Discovery",
                f"- Status: {authentication_discovery.get('status', 'unknown')}",
                f"- Endpoint: {contract.get('endpoint', 'not discovered')}",
                (
                    "- Request fields: "
                    f"{contract.get('username_field', 'unknown')}, "
                    f"{contract.get('password_field', 'unknown')}"
                ),
                (
                    "- Missing prerequisites: "
                    + (
                        "; ".join(
                            authentication_discovery.get(
                                "missing_prerequisites",
                                [],
                            )
                        )
                        or "none"
                    )
                ),
            ]
        )
    wordlist_result = state.get("wordlist_attack") or {}
    if wordlist_result:
        lines.extend(
            [
                "",
                "## Password Wordlist Validation",
                f"- Status: {wordlist_result.get('status', 'unknown')}",
                f"- Attempts: {wordlist_result.get('attempted', 0)}",
                f"- Accepted credentials: {wordlist_result.get('successful', 0)}",
                f"- Stop reason: {wordlist_result.get('stop_reason', 'unknown')}",
            ]
        )
    spray_result = state.get("password_spray") or {}
    if spray_result:
        lines.extend(
            [
                "",
                "## Password Spray Validation",
                f"- Status: {spray_result.get('status', 'unknown')}",
                f"- Attempts: {spray_result.get('attempted', 0)}",
                f"- Accepted credentials: {spray_result.get('successful', 0)}",
                f"- Stop reason: {spray_result.get('stop_reason', 'unknown')}",
            ]
        )
    evidence = state.get("normalized_evidence", [])
    if evidence:
        lines.extend(["", "## Normalized Findings", render_findings_table(evidence)])
    lines.extend(
        [
            "## Safety Review",
            safety_review,
            "",
            "## Limitations",
            "- Tool families such as BloodHound, Burp Suite, ZAP, Slither, Mythril, and Hardhat are represented as role-level integrations until their local adapters are implemented.",
            "- Active probing only runs when an allowlisted target is supplied with execute_recon enabled.",
            "- Capability validation only runs when execute_validation is enabled and open services are observed.",
        ]
    )
    return "\n".join(lines)


def run_campaign(
    goal: str,
    target: str | None = None,
    ports: list[int] | None = None,
    provider: str = "gpt_oss",
    execute_recon: bool = False,
    execute_validation: bool = False,
    max_capabilities: int = 5,
    execution_mode: str = "safe",
    metasploit_action: str = "check",
    use_llm: bool = True,
    n_results: int = 5,
    graph_memory_path: Path | None = None,
    loop: bool = False,
    max_rounds: int = 3,
    max_tools: int = 12,
    max_failed_rounds: int = 2,
    stop_on_success: bool = True,
    web_auth_contexts: list[WebAuthContext] | None = None,
    stateful_api: bool = False,
    stateful_max_requests: int = 40,
    stateful_max_workflows: int = 8,
    target_url: str | None = None,
    authorization_output_root: Path | None = None,
    authorization_request_budget: int = 30,
    authorization_tool_rounds: int = 3,
    identity_output_root: Path | None = None,
    wordlist_attack_config: WordlistAttackConfig | None = None,
    password_spray_config: PasswordSprayConfig | None = None,
) -> CampaignRun:
    started = time.perf_counter()
    settings = load_settings()
    if target and target_url:
        raise ValueError("Supply either a network target or an HTTP(S) target URL, not both.")
    if target:
        target = validate_target(target)
    if target_url:
        target_url = target_url.strip()
        if not target_url:
            target_url = None
        else:
            build_inline_prompt_document(goal, target_url)
    autonomous_identity_enabled = False
    if target_url and use_llm and execution_mode == "aggressive_lab":
        try:
            validate_lab_url(target_url)
            autonomous_identity_enabled = True
        except ValueError:
            autonomous_identity_enabled = False
    for label, config in (
        ("wordlist attack", wordlist_attack_config),
        ("password spray", password_spray_config),
    ):
        if config and not target_url:
            raise ValueError(f"{label} configuration requires --url/target_url.")
        if (
            config
            and target_url
            and config.target_url.rstrip("/") != target_url.rstrip("/")
        ):
            raise ValueError(
                f"{label} target must exactly match the campaign target URL."
            )
    initial: CampaignState = {
        "goal": goal,
        "target": target,
        "target_url": target_url,
        "provider": provider,
        "execute_recon": execute_recon or execute_validation,
        "execute_validation": execute_validation,
        "max_capabilities": max_capabilities,
        "execution_mode": execution_mode,
        "metasploit_action": metasploit_action,
        "use_llm": use_llm,
        "web_auth_contexts": web_auth_contexts or [],
        "stateful_api": stateful_api,
        "stateful_max_requests": max(1, min(stateful_max_requests, 200)),
        "stateful_max_workflows": max(1, min(stateful_max_workflows, 30)),
        "authorization_output_root": authorization_output_root
        or Path("reports/redteam_campaign/authorization"),
        "authorization_request_budget": max(
            1, min(authorization_request_budget, 50)
        ),
        "authorization_tool_rounds": max(1, min(authorization_tool_rounds, 5)),
        "identity_output_root": identity_output_root
        or Path("reports/redteam_campaign/identity_agents"),
        "autonomous_identity_enabled": autonomous_identity_enabled,
        "wordlist_attack_config": wordlist_attack_config,
        "password_spray_config": password_spray_config,
        "ports": ports or (default_ports_for_target(target) if target else []),
        "steps": [],
        "phases": [],
        "agents": [],
        "sources": [],
        "tool_traces": [],
        "tool_timeline": [],
        "graph_memory": {},
        "recon_strategy": {},
        "validation_strategy": {},
        "web_checks": {},
        "web_assessment": {},
        "authorization_assessment": {},
        "authentication_discovery": {},
        "wordlist_attack": {},
        "password_spray": {},
        "campaign_routing": {},
        "normalized_evidence": [],
        "loop_summary": {},
    }
    try:
        graph = build_campaign_graph(settings, provider=provider, n_results=n_results, graph_memory_path=graph_memory_path)
        final_state = graph.invoke(initial)
        if loop and execute_validation:
            final_state = run_validation_loop(
                final_state,
                max_rounds=max_rounds,
                max_tools=max_tools,
                max_failed_rounds=max_failed_rounds,
                stop_on_success=stop_on_success,
            )
        final_state["normalized_evidence"] = [
            *normalize_web_evidence(final_state.get("web_checks")),
            *normalize_web_assessment_evidence(final_state.get("web_assessment")),
            *normalize_authorization_evidence(
                final_state.get("authorization_assessment"),
                target_url=target_url,
            ),
            *normalize_wordlist_attack_evidence(
                final_state.get("wordlist_attack"),
            ),
            *normalize_password_spray_evidence(
                final_state.get("password_spray"),
            ),
            *normalize_validation_evidence(final_state.get("capability_validation")),
        ]
        if final_state.get("normalized_evidence"):
            final_state["report"] = f"{final_state.get('report', '')}\n\n## Normalized Findings\n{render_findings_table(final_state['normalized_evidence'])}"
        elapsed = time.perf_counter() - started
        return CampaignRun(
            goal=goal,
            target=target,
            target_url=target_url,
            provider=provider,
            report=final_state.get("report", ""),
            steps=final_state.get("steps", []),
            agents=[AgentOutput(**item) for item in final_state.get("agents", [])],
            sources=final_state.get("sources", []),
            tool_traces=final_state.get("tool_traces", []),
            tcp=final_state.get("tcp"),
            services=final_state.get("services", []),
            http=final_state.get("http"),
            web_fingerprint=final_state.get("web_fingerprint"),
            web_routes=final_state.get("web_routes"),
            web_assessment=final_state.get("web_assessment"),
            authorization_assessment=final_state.get(
                "authorization_assessment"
            ),
            authentication_discovery=final_state.get(
                "authentication_discovery"
            ),
            wordlist_attack=final_state.get("wordlist_attack"),
            password_spray=final_state.get("password_spray"),
            campaign_routing=final_state.get("campaign_routing"),
            capability_selection=final_state.get("capability_selection"),
            capability_validation=final_state.get("capability_validation"),
            graph_memory=final_state.get("graph_memory"),
            recon_strategy=final_state.get("recon_strategy"),
            validation_strategy=final_state.get("validation_strategy"),
            web_checks=final_state.get("web_checks"),
            normalized_evidence=final_state.get("normalized_evidence", []),
            loop_summary=final_state.get("loop_summary"),
            phases=final_state.get("phases", []),
            tool_timeline=final_state.get("tool_timeline", []),
            safety_review=final_state.get("safety_review", ""),
            elapsed_seconds=elapsed,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        return CampaignRun(
            goal=goal,
            target=target,
            target_url=target_url,
            provider=provider,
            report="",
            steps=initial["steps"],
            phases=initial["phases"],
            agents=[],
            sources=[],
            tool_traces=[],
            tool_timeline=[],
            graph_memory={},
            web_checks={},
            web_assessment={},
            authorization_assessment={},
            authentication_discovery={},
            wordlist_attack={},
            password_spray={},
            campaign_routing=initial.get("campaign_routing"),
            normalized_evidence=[],
            loop_summary={},
            elapsed_seconds=elapsed,
            error=repr(exc),
        )


def run_validation_loop(
    state: CampaignState,
    *,
    max_rounds: int,
    max_tools: int,
    max_failed_rounds: int,
    stop_on_success: bool,
) -> CampaignState:
    if not state.get("target") or not state.get("services"):
        state["loop_summary"] = {"enabled": True, "rounds": 0, "stop_reason": "missing_target_or_services"}
        return state
    attempted_ids = {
        str(item.get("selected_exploit_id"))
        for item in (state.get("capability_validation") or {}).get("results", [])
        if item.get("selected_exploit_id")
    }
    total_tools = len(attempted_ids)
    failed_rounds = 0
    rounds: list[dict[str, Any]] = []
    if stop_on_success and (state.get("capability_validation") or {}).get("successful", 0):
        state["loop_summary"] = {"enabled": True, "rounds": 0, "stop_reason": "initial_success", "attempted_ids": sorted(attempted_ids)}
        return state

    combined_results = list((state.get("capability_validation") or {}).get("results", []))
    stop_reason = "max_rounds"
    for round_index in range(2, max_rounds + 1):
        if total_tools >= max_tools:
            stop_reason = "tool_budget_exhausted"
            break
        selection = select_exploit_candidate(
            str(state["target"]),
            state.get("services", []),
            limit=max(
                1,
                min(
                    max_tools,
                    len(attempted_ids) + max(1, min(state.get("max_capabilities", 5), max_tools - total_tools)),
                ),
            ),
            web_routes={**state.get("web_routes", {}), "web_fingerprints": (state.get("web_fingerprint") or {}).get("web_fingerprints", [])},
            graph_memory=state.get("graph_memory"),
        )
        selected = [
            item for item in selection.get("selected_candidates", [])
            if str(item.get("id")) not in attempted_ids
        ]
        selection["selected_candidates"] = selected
        selection["selected"] = selected[0] if selected else None
        if not selected:
            stop_reason = "no_new_capabilities"
            break
        validation_strategy = plan_validation_strategy(
            state["goal"],
            str(state["target"]),
            state.get("services", []),
            {**selection, "candidates": selected},
            max_capabilities=max(1, min(state.get("max_capabilities", 5), max_tools - total_tools)),
            provider=state.get("provider", "gpt_oss"),
            use_llm=state.get("use_llm", False),
        )
        selection = apply_validation_strategy({**selection, "candidates": selected}, validation_strategy)
        if not selection.get("selected_candidates"):
            stop_reason = "planner_selected_no_new_capabilities"
            break
        validation = run_selected_exploit(
            str(state["target"]),
            selection,
            execution_mode=state.get("execution_mode", "safe"),
            metasploit_action=state.get("metasploit_action", "check"),
            provider=state.get("provider", "gpt_oss"),
            use_llm=state.get("use_llm", False),
        )
        for item in validation.get("results", []):
            if item.get("selected_exploit_id"):
                attempted_ids.add(str(item["selected_exploit_id"]))
        total_tools += validation.get("attempted", 0)
        combined_results.extend(validation.get("results", []))
        success = validation.get("successful", 0)
        failed_rounds = 0 if success else failed_rounds + 1
        rounds.append(
            {
                "round": round_index,
                "attempted": validation.get("attempted", 0),
                "successful": success,
                "status_counts": validation.get("status_counts", {}),
            }
        )
        state["tool_timeline"] = [
            *state.get("tool_timeline", []),
            {
                "tool": "closed_loop_validation_strategy",
                "input": f"round {round_index}",
                "status": validation_strategy.get("generated_by", "unknown"),
                "evidence": json.dumps({k: v for k, v in validation_strategy.items() if k != "llm_raw"}, indent=2)[:1200],
            },
            {
                "tool": "closed_loop_validation",
                "input": f"round {round_index}",
                "status": "success" if success else "ran_no_finding",
                "evidence": json.dumps(rounds[-1], indent=2),
            },
        ]
        if stop_on_success and success:
            stop_reason = "success"
            break
        if failed_rounds >= max_failed_rounds:
            stop_reason = "failed_round_budget_exhausted"
            break

    successful = [item for item in combined_results if item.get("verified")]
    state["capability_validation"] = {
        **(state.get("capability_validation") or {}),
        "results": combined_results,
        "attempted": len(combined_results),
        "successful": len(successful),
        "verified": bool(successful),
        "status_counts": validation_status_counts(combined_results),
    }
    state["loop_summary"] = {
        "enabled": True,
        "rounds": len(rounds),
        "stop_reason": stop_reason,
        "max_rounds": max_rounds,
        "max_tools": max_tools,
        "attempted_ids": sorted(attempted_ids),
        "rounds_detail": rounds,
    }
    state["phases"] = append_phase(state, "closed-loop validation", stop_reason, f"{len(rounds)} additional round(s), {len(successful)} positive result(s) total.")
    return state


def validation_status_counts(results: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in results:
        status = str(item.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def save_campaign_run(run: CampaignRun, output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    json_path = output_dir / f"redteam_campaign_{stamp}.json"
    md_path = output_dir / f"redteam_campaign_{stamp}.md"
    payload = asdict(run)
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    md_path.write_text(
        render_campaign_markdown(
            payload,
            artifact_paths={"json": json_path.name},
        ),
        encoding="utf-8",
    )
    return {"json": json_path, "markdown": md_path}
