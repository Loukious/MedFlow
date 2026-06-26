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

from .tools import (
    ToolResult,
    default_ports_for_target,
    http_probe,
    nmap_service_scan,
    parse_nmap_open_services,
    run_selected_exploit,
    select_exploit_candidate,
    summarize_tool_result,
    tcp_connect_check,
    validate_target,
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
    provider: str
    report: str
    steps: list[str]
    agents: list[AgentOutput]
    sources: list[dict[str, Any]]
    tool_traces: list[Any]
    tcp: dict[str, Any] | None = None
    services: list[dict[str, str]] = field(default_factory=list)
    http: dict[str, Any] | None = None
    capability_selection: dict[str, Any] | None = None
    capability_validation: dict[str, Any] | None = None
    safety_review: str = ""
    elapsed_seconds: float = 0.0
    error: str | None = None


class CampaignState(TypedDict, total=False):
    goal: str
    target: str | None
    provider: str
    execute_recon: bool
    execute_validation: bool
    max_capabilities: int
    execution_mode: str
    use_llm: bool
    ports: list[int]
    tcp: dict[str, Any]
    nmap_result: ToolResult
    services: list[dict[str, str]]
    http: dict[str, Any]
    capability_selection: dict[str, Any]
    capability_validation: dict[str, Any]
    sources: list[dict[str, Any]]
    agents: list[dict[str, Any]]
    report: str
    safety_review: str
    steps: list[str]
    tool_traces: list[Any]


def append_step(state: CampaignState, step: str) -> list[str]:
    return [*state.get("steps", []), step]


def agent_to_dict(output: AgentOutput) -> dict[str, Any]:
    return asdict(output)


def compact_services(services: list[dict[str, str]]) -> str:
    if not services:
        return "No live service evidence was collected."
    return "\n".join(
        f"- {item.get('port')}/{item.get('service')}: {item.get('version', '')}"
        for item in services[:12]
    )


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

Observed services:
{compact_services(state.get("services", []))}

Prior agent outputs:
{json.dumps(state.get("agents", []), indent=2)}

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
        raw = call_redteam_llm(prompt, settings=settings, provider=state.get("provider", "llama"))
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


def build_campaign_graph(settings: Settings, provider: str = "llama", n_results: int = 5):
    def gather_context(state: CampaignState) -> CampaignState:
        sources = retrieve_many(build_campaign_queries(state["goal"]), settings=settings, n_results=n_results)
        return {
            "sources": sources,
            "steps": append_step(state, "campaign orchestrator retrieved ATT&CK and red-team context"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("retrieve_many", state["goal"], json.dumps(sources[:6], indent=2)),
            ],
        }

    def campaign_orchestrator(state: CampaignState) -> CampaignState:
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
            """
Create the overall campaign charter. Define phases, role tasking, constraints, decision points,
and success criteria. Do not provide exploit instructions.
""",
            fallback,
        )
        return {
            "agents": [*state.get("agents", []), output],
            "steps": append_step(state, "campaign orchestrator created the campaign charter"),
            "tool_traces": [*state.get("tool_traces", []), make_trace("campaign_orchestrator", state["goal"], json.dumps(output, indent=2))],
        }

    def reconnaissance_agent(state: CampaignState) -> CampaignState:
        tcp = state.get("tcp")
        services = state.get("services", [])
        http = state.get("http")
        traces = state.get("tool_traces", [])
        steps = state.get("steps", [])
        if state.get("execute_recon") and state.get("target"):
            target = validate_target(str(state["target"]))
            ports = state.get("ports") or default_ports_for_target(target)
            tcp = tcp_connect_check(target, ports=ports)
            nmap_result = nmap_service_scan(target, ports=ports)
            services = parse_nmap_open_services(nmap_result.stdout)
            http = http_probe(target)
            steps = [*steps, "reconnaissance agent executed TCP, Nmap, and HTTP probes against the allowlisted target"]
            traces = [
                *traces,
                make_trace("tcp_connect_check", target, json.dumps(tcp, indent=2)),
                make_trace("nmap_service_scan", " ".join(nmap_result.command or []), summarize_tool_result(nmap_result)),
                make_trace("http_probe", target, json.dumps(http, indent=2)),
            ]
            sources = retrieve_many(build_campaign_queries(state["goal"], services), settings=settings, n_results=n_results)
        else:
            sources = state.get("sources", [])

        fallback = fallback_agent_output(
            "Reconnaissance Agent",
            state["goal"],
            ["Nmap", "HTTP probing", "DNS enumeration placeholder", "asset inventory placeholder"],
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
        output["evidence"] = {"services": services, "http": http or {}, "tcp": tcp or {}}
        return {
            "tcp": tcp,
            "services": services,
            "http": http,
            "sources": sources,
            "agents": [*state.get("agents", []), output],
            "steps": [*steps, "reconnaissance agent produced infrastructure handoff"],
            "tool_traces": [*traces, make_trace("reconnaissance_agent", state["goal"], json.dumps(output, indent=2))],
        }

    def capability_validation_agent(state: CampaignState) -> CampaignState:
        if not state.get("execute_validation", False):
            return {"steps": append_step(state, "skipped capability validation execution")}
        if not state.get("target"):
            return {"steps": append_step(state, "skipped capability validation because no target was supplied")}
        if not state.get("services"):
            return {"steps": append_step(state, "skipped capability validation because no open services were observed")}

        selection = select_exploit_candidate(
            str(state["target"]),
            state.get("services", []),
            limit=state.get("max_capabilities", 5),
        )
        validation = run_selected_exploit(
            str(state["target"]),
            selection,
            execution_mode=state.get("execution_mode", "safe"),
        )
        output = agent_to_dict(
            AgentOutput(
                role="Capability Validation Agent",
                objective="Select and execute applicable validation capabilities from observed service evidence.",
                tools=["Metasploit check/auxiliary adapters", "Nuclei templates", "Nmap NSE scripts", "internal validation runners"],
                decisions=[
                    f"Selected {len(selection.get('selected_candidates', []))} capability candidate(s).",
                    f"Execution mode: {state.get('execution_mode', 'safe')}.",
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
            "agents": [*state.get("agents", []), output],
            "steps": append_step(state, "capability validation agent selected and executed matching validation tools"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("select_exploit_candidate", str(state["target"]), json.dumps(selection, indent=2)),
                make_trace("run_selected_exploit", str(state["target"]), json.dumps(validation, indent=2)),
            ],
        }

    def identity_attack_agent(state: CampaignState) -> CampaignState:
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

    def web_api_attack_agent(state: CampaignState) -> CampaignState:
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
            state,
            settings,
            "Web/API Attack Agent",
            """
Act as a separate web and API attack agent. Use Burp Suite, OWASP ZAP, and Postman as tool families.
Focus on endpoint discovery, authorization control validation, business logic abuse hypotheses,
logging expectations, and safe test data.
""",
            fallback,
        )
        return {
            "agents": [*state.get("agents", []), output],
            "steps": append_step(state, "web/API attack agent produced portal and API validation path"),
            "tool_traces": [*state.get("tool_traces", []), make_trace("web_api_attack_agent", state["goal"], json.dumps(output, indent=2))],
        }

    def blockchain_security_agent(state: CampaignState) -> CampaignState:
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
        draft = {
            "goal": state["goal"],
            "target": state.get("target"),
            "agents": state.get("agents", []),
            "services": state.get("services", []),
            "capability_selection": state.get("capability_selection", {}),
            "capability_validation": state.get("capability_validation", {}),
        }
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
            report = call_redteam_llm(prompt, settings=settings, provider=state.get("provider", "llama"))
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
            "tool_traces": [*state.get("tool_traces", []), make_trace("reporting_agent", state["goal"], report)],
        }

    graph = StateGraph(CampaignState)
    graph.add_node("gather_context", gather_context)
    graph.add_node("campaign_orchestrator", campaign_orchestrator)
    graph.add_node("reconnaissance_agent", reconnaissance_agent)
    graph.add_node("capability_validation_agent", capability_validation_agent)
    graph.add_node("identity_attack_agent", identity_attack_agent)
    graph.add_node("web_api_attack_agent", web_api_attack_agent)
    graph.add_node("blockchain_security_agent", blockchain_security_agent)
    graph.add_node("reporting_agent", reporting_agent)

    graph.set_entry_point("gather_context")
    graph.add_edge("gather_context", "campaign_orchestrator")
    graph.add_edge("campaign_orchestrator", "reconnaissance_agent")
    graph.add_edge("reconnaissance_agent", "capability_validation_agent")
    graph.add_edge("capability_validation_agent", "identity_attack_agent")
    graph.add_edge("identity_attack_agent", "web_api_attack_agent")
    graph.add_edge("web_api_attack_agent", "blockchain_security_agent")
    graph.add_edge("blockchain_security_agent", "reporting_agent")
    graph.add_edge("reporting_agent", END)
    return graph.compile()


def deterministic_campaign_report(state: CampaignState, safety_review: str) -> str:
    lines = [
        "# MedFlow Multi-Agent Red-Team Campaign",
        "",
        f"Goal: {state['goal']}",
        f"Target: {state.get('target') or 'tabletop / no live target'}",
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
    provider: str = "llama",
    execute_recon: bool = False,
    execute_validation: bool = False,
    max_capabilities: int = 5,
    execution_mode: str = "safe",
    use_llm: bool = True,
    n_results: int = 5,
) -> CampaignRun:
    started = time.perf_counter()
    settings = load_settings()
    if target:
        target = validate_target(target)
    initial: CampaignState = {
        "goal": goal,
        "target": target,
        "provider": provider,
        "execute_recon": execute_recon or execute_validation,
        "execute_validation": execute_validation,
        "max_capabilities": max_capabilities,
        "execution_mode": execution_mode,
        "use_llm": use_llm,
        "ports": ports or (default_ports_for_target(target) if target else []),
        "steps": [],
        "agents": [],
        "sources": [],
        "tool_traces": [],
    }
    try:
        graph = build_campaign_graph(settings, provider=provider, n_results=n_results)
        final_state = graph.invoke(initial)
        elapsed = time.perf_counter() - started
        return CampaignRun(
            goal=goal,
            target=target,
            provider=provider,
            report=final_state.get("report", ""),
            steps=final_state.get("steps", []),
            agents=[AgentOutput(**item) for item in final_state.get("agents", [])],
            sources=final_state.get("sources", []),
            tool_traces=final_state.get("tool_traces", []),
            tcp=final_state.get("tcp"),
            services=final_state.get("services", []),
            http=final_state.get("http"),
            capability_selection=final_state.get("capability_selection"),
            capability_validation=final_state.get("capability_validation"),
            safety_review=final_state.get("safety_review", ""),
            elapsed_seconds=elapsed,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        return CampaignRun(
            goal=goal,
            target=target,
            provider=provider,
            report="",
            steps=initial["steps"],
            agents=[],
            sources=[],
            tool_traces=[],
            elapsed_seconds=elapsed,
            error=repr(exc),
        )


def save_campaign_run(run: CampaignRun, output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    json_path = output_dir / f"redteam_campaign_{stamp}.json"
    md_path = output_dir / f"redteam_campaign_{stamp}.md"
    payload = asdict(run)
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    md_path.write_text(render_campaign_markdown(payload), encoding="utf-8")
    return {"json": json_path, "markdown": md_path}


def render_campaign_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# MedFlow Red-Team Campaign Run",
        "",
        f"- Goal: {payload.get('goal')}",
        f"- Target: {payload.get('target') or 'tabletop / no live target'}",
        f"- Provider: {payload.get('provider')}",
        f"- Elapsed seconds: {payload.get('elapsed_seconds'):.2f}",
        "",
        "## Capability Validation",
        json.dumps(payload.get("capability_validation") or {"status": "not run"}, indent=2),
        "",
        "## Steps",
        *[f"- {step}" for step in payload.get("steps", [])],
        "",
        "## Agents",
    ]
    for agent in payload.get("agents", []):
        lines.extend(
            [
                f"### {agent.get('role')}",
                f"Objective: {agent.get('objective')}",
                "",
                "Tools:",
                *[f"- {item}" for item in agent.get("tools", [])],
                "",
                "Decisions:",
                *[f"- {item}" for item in agent.get("decisions", [])],
                "",
                "Outputs:",
                *[f"- {item}" for item in agent.get("outputs", [])],
                "",
                f"Handoff: {agent.get('handoff', '')}",
                "",
            ]
        )
    lines.extend(["## Report", payload.get("report", ""), ""])
    return "\n".join(lines)
