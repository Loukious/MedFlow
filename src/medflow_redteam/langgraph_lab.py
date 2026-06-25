from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from medflow_compare.shared_tools import call_redteam_llm, make_trace, retrieve_many, safety_review_tool
from medflow_ti.config import Settings, load_settings

from .tools import (
    ToolResult,
    default_ports_for_target,
    DEFAULT_TARGET,
    http_probe,
    nmap_safe_scripts,
    nmap_service_scan,
    parse_nmap_open_services,
    run_selected_exploit,
    select_exploit_candidate,
    summarize_tool_result,
    tcp_connect_check,
)


@dataclass
class LabRun:
    target: str
    provider: str
    report: str
    steps: list[str]
    tool_traces: list[Any]
    sources: list[dict[str, Any]]
    tcp: dict[str, Any]
    services: list[dict[str, str]]
    http: dict[str, Any]
    nmap: dict[str, Any]
    safe_scripts: dict[str, Any] | None = None
    exploit_selection: dict[str, Any] | None = None
    exploit_validation: dict[str, Any] | None = None
    kill_chain: list[dict[str, Any]] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    error: str | None = None


class LabState(TypedDict, total=False):
    target: str
    ports: list[int]
    provider: str
    use_sudo: bool
    run_safe_scripts: bool
    run_exploit_validation: bool
    max_exploit_candidates: int
    execution_mode: str
    tcp: dict[str, Any]
    nmap_result: ToolResult
    safe_script_result: ToolResult
    services: list[dict[str, str]]
    http: dict[str, Any]
    exploit_selection: dict[str, Any]
    exploit_validation: dict[str, Any]
    kill_chain: list[dict[str, Any]]
    evidence_queries: list[str]
    sources: list[dict[str, Any]]
    report: str
    safety_review: str
    steps: list[str]
    tool_traces: list[Any]


def append_step(state: LabState, step: str) -> list[str]:
    return [*state.get("steps", []), step]


def build_evidence_queries(target: str, services: list[dict[str, str]], http: dict[str, Any]) -> list[str]:
    service_terms = " ".join(
        f"{item.get('service', '')} {item.get('version', '')}" for item in services[:10]
    ).strip()
    http_terms = " ".join(
        f"{item.get('server', '')} {item.get('title', '')}" for item in http.get("http_probe", []) if not item.get("error")
    ).strip()
    return [
        f"red team validation exposed services {service_terms}",
        f"web api attack agent healthcare portal {http_terms}",
        "ATT&CK initial access valid accounts web service external remote services detection",
        "authorized red team reconnaissance service discovery vulnerability validation reporting",
    ]


def build_kill_chain_summary(state: LabState) -> list[dict[str, Any]]:
    services = state.get("services", [])
    selection = state.get("exploit_selection") or {}
    exploit = state.get("exploit_validation") or {}
    open_service_labels = [
        f"{service.get('port')}/{service.get('service')}"
        for service in services
        if service.get("port") and service.get("service")
    ]
    chain = [
        {
            "phase": "Reconnaissance",
            "status": "success" if services else "failed",
            "evidence": f"Discovered {len(services)} open services: {', '.join(open_service_labels[:8])}",
        },
        {
            "phase": "Target selection",
            "status": "success" if selection.get("selected") else "skipped",
            "evidence": (
                "; ".join(
                    f"{item.get('name')} because: {', '.join(item.get('reasons', []))}"
                    for item in selection.get("selected_candidates", [])
                )
            )
            if selection.get("selected_candidates")
            else selection.get("reason", "No exploit selected."),
        },
        {
            "phase": "Exploitation",
            "status": "success" if exploit.get("exploited") else ("skipped" if not exploit else "failed"),
            "evidence": "; ".join(
                f"{item.get('selected_exploit_id')}: {item.get('proof_goal') or item.get('reason', '')}"
                for item in exploit.get("results", [])
            )
            or exploit.get("proof_goal", exploit.get("reason", "Exploit validation was not requested.")),
        },
        {
            "phase": "Command execution proof",
            "status": "success" if exploit.get("verified") else ("skipped" if not exploit else "failed"),
            "evidence": "; ".join(
                f"{item.get('selected_exploit_id')}: {item.get('proof_output') or item.get('reason', 'no proof')}"
                for item in exploit.get("results", [])
            )
            or exploit.get("proof_output")
            or exploit.get("verification_note")
            or "No proof output collected.",
        },
        {
            "phase": "Cleanup",
            "status": "success" if exploit.get("cleanup_verified") else ("skipped" if not exploit else "failed"),
            "evidence": "Temporary proof file removed from the lab target."
            if exploit.get("cleanup_verified")
            else "Cleanup was not verified.",
        },
    ]
    return chain


def build_lab_report_prompt(state: LabState) -> str:
    tcp = json.dumps(state.get("tcp", {}), indent=2)
    services = json.dumps(state.get("services", []), indent=2)
    http = json.dumps(state.get("http", {}), indent=2)
    safe_scripts = summarize_tool_result(state["safe_script_result"]) if state.get("safe_script_result") else "Not run."
    exploit_validation = json.dumps(state.get("exploit_validation", {"status": "Not run."}), indent=2)
    exploit_selection = json.dumps(state.get("exploit_selection", {"status": "Not run."}), indent=2)
    kill_chain = json.dumps(state.get("kill_chain", []), indent=2)
    steps = "\n".join(f"- {step}" for step in state.get("steps", []))
    safety = state.get("safety_review", "")
    sources = state.get("sources", [])
    source_lines = []
    for idx, hit in enumerate(sources[:4], 1):
        meta = hit.get("metadata") or {}
        source_lines.append(
            f"[{idx}] {hit.get('collection')} {meta.get('mitre_id', '')} {meta.get('name', '')} "
            f"score={hit.get('score', '')}\n{hit.get('document', '')[:300]}"
        )

    return f"""
You are the reporting agent for an authorized MedFlow red-team lab.

Safety constraints:
- Target is a local isolated Metasploitable3 Docker lab.
- Keep the report at validation, telemetry, detection, and remediation level.
- Do not provide exploit code, credential theft instructions, persistence, evasion, or destructive steps.
- Do not recommend exploitation as a next step; recommend safe control validation, tabletop tests, logging checks, and defensive hardening.
- Clearly separate observed lab evidence from inferred follow-up ideas.

Actual graph steps completed:
{steps}

TCP connect check:
{tcp}

Nmap service discovery:
{services}

HTTP probe:
{http}

Nmap default/safe script validation:
{safe_scripts}

Exploit tool selection:
{exploit_selection}

Controlled exploitation validation:
{exploit_validation}

Kill-chain summary:
{kill_chain}

Safety review:
{safety}

Retrieved MedFlow/ATT&CK evidence:
{chr(10).join(source_lines)}

Write a red-team lab report with:
1. Executive summary
2. Agent workflow executed, using only the actual graph steps completed above
3. Observed attack surface
4. Safe validation actions performed, excluding any step marked skipped or not run
5. Exploit tool selection and rationale
6. Controlled exploitation evidence, only if exploit validation ran
7. Kill-chain outcome
8. ATT&CK mapping from retrieved evidence only
9. Defensive findings and recommended controls
10. Limitations and next steps
"""


def build_redteam_lab_graph(settings: Settings, provider: str = "llama", n_results: int = 5):
    def recon_connectivity(state: LabState) -> LabState:
        tcp = tcp_connect_check(state["target"], ports=state["ports"])
        return {
            "tcp": tcp,
            "steps": append_step(state, "ran TCP connectivity checks against lab target"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("tcp_connect_check", state["target"], json.dumps(tcp, indent=2)),
            ],
        }

    def recon_nmap(state: LabState) -> LabState:
        result = nmap_service_scan(state["target"], ports=state["ports"])
        services = parse_nmap_open_services(result.stdout)
        return {
            "nmap_result": result,
            "services": services,
            "steps": append_step(state, f"ran nmap service discovery and parsed {len(services)} open services"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("nmap_service_scan", " ".join(result.command or []), summarize_tool_result(result)),
            ],
        }

    def validate_safe_scripts(state: LabState) -> LabState:
        if not state.get("run_safe_scripts", True):
            return {"steps": append_step(state, "skipped nmap default/safe script validation")}
        open_ports = [int(service["port"]) for service in state.get("services", []) if service.get("port", "").isdigit()]
        result = nmap_safe_scripts(state["target"], ports=open_ports or state["ports"])
        return {
            "safe_script_result": result,
            "steps": append_step(state, f"ran nmap default,safe scripts against {len(open_ports) or len(state['ports'])} lab ports"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("nmap_safe_scripts", " ".join(result.command or []), summarize_tool_result(result)),
            ],
        }

    def probe_http(state: LabState) -> LabState:
        http = http_probe(state["target"])
        return {
            "http": http,
            "steps": append_step(state, "probed HTTP services for status, headers, and page title"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("http_probe", state["target"], json.dumps(http, indent=2)),
            ],
        }

    def select_exploit_tool(state: LabState) -> LabState:
        selection = select_exploit_candidate(
            state["target"],
            state.get("services", []),
            limit=state.get("max_exploit_candidates", 1),
        )
        selected = selection.get("selected") or {}
        step = (
            f"selected {len(selection.get('selected_candidates', []))} exploit/tool candidate(s) from observed services"
            if selected
            else "found no matching exploit tool for observed services"
        )
        return {
            "exploit_selection": selection,
            "steps": append_step(state, step),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("select_exploit_candidate", state["target"], json.dumps(selection, indent=2)),
            ],
        }

    def controlled_exploitation(state: LabState) -> LabState:
        if not state.get("run_exploit_validation", False):
            return {"steps": append_step(state, "skipped controlled exploitation validation")}
        result = run_selected_exploit(
            state["target"],
            state.get("exploit_selection", {}),
            use_sudo=state.get("use_sudo", False),
            execution_mode=state.get("execution_mode", "safe"),
        )
        return {
            "exploit_validation": result,
            "steps": append_step(state, "executed selected controlled exploitation tool against the isolated lab target"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("run_selected_exploit", state["target"], json.dumps(result, indent=2)),
            ],
        }

    def summarize_kill_chain(state: LabState) -> LabState:
        chain = build_kill_chain_summary(state)
        return {
            "kill_chain": chain,
            "steps": append_step(state, "summarized lab kill-chain outcome"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("build_kill_chain_summary", state["target"], json.dumps(chain, indent=2)),
            ],
        }

    def retrieve_attack_context(state: LabState) -> LabState:
        queries = build_evidence_queries(state["target"], state.get("services", []), state.get("http", {}))
        sources = retrieve_many(queries, settings=settings, n_results=n_results)
        return {
            "evidence_queries": queries,
            "sources": sources,
            "steps": append_step(state, f"retrieved {len(sources)} MedFlow/ATT&CK context items"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("retrieve_many", "\n".join(queries), f"{len(sources)} unique sources"),
            ],
        }

    def safety_gate(state: LabState) -> LabState:
        draft = json.dumps(
            {
                "target": state["target"],
                "services": state.get("services", []),
                "intent": "authorized local lab service discovery and safe validation",
            },
            indent=2,
        )
        review = safety_review_tool(draft)
        return {
            "safety_review": review,
            "steps": append_step(state, "checked lab findings against safety boundary"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("safety_review_tool", draft, review),
            ],
        }

    def report(state: LabState) -> LabState:
        prompt = build_lab_report_prompt(state)
        try:
            output = call_redteam_llm(prompt, settings=settings, provider=provider)
        except Exception as exc:
            output = build_fallback_report(state, str(exc))
        return {
            "report": output,
            "steps": append_step(state, "generated LangGraph red-team lab report"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("call_redteam_llm:lab_report", state["target"], output),
            ],
        }

    graph = StateGraph(LabState)
    graph.add_node("recon_connectivity", recon_connectivity)
    graph.add_node("recon_nmap", recon_nmap)
    graph.add_node("validate_safe_scripts", validate_safe_scripts)
    graph.add_node("probe_http", probe_http)
    graph.add_node("select_exploit_tool", select_exploit_tool)
    graph.add_node("controlled_exploitation", controlled_exploitation)
    graph.add_node("summarize_kill_chain", summarize_kill_chain)
    graph.add_node("retrieve_attack_context", retrieve_attack_context)
    graph.add_node("safety_gate", safety_gate)
    graph.add_node("report", report)
    graph.set_entry_point("recon_connectivity")
    graph.add_edge("recon_connectivity", "recon_nmap")
    graph.add_edge("recon_nmap", "validate_safe_scripts")
    graph.add_edge("validate_safe_scripts", "probe_http")
    graph.add_edge("probe_http", "select_exploit_tool")
    graph.add_edge("select_exploit_tool", "controlled_exploitation")
    graph.add_edge("controlled_exploitation", "summarize_kill_chain")
    graph.add_edge("summarize_kill_chain", "retrieve_attack_context")
    graph.add_edge("retrieve_attack_context", "safety_gate")
    graph.add_edge("safety_gate", "report")
    graph.add_edge("report", END)
    return graph.compile()


def build_fallback_report(state: LabState, error: str) -> str:
    services = state.get("services", [])
    selection = state.get("exploit_selection", {})
    exploit = state.get("exploit_validation", {})
    lines = [
        "# Red-Team Lab Report",
        "",
        "The LLM narrative report could not be generated, so this deterministic report was saved instead.",
        "",
        f"LLM error: {error}",
        "",
        "## Observed Services",
        *[
            f"- {item.get('port')}/{item.get('protocol')} {item.get('service')} {item.get('version')}"
            for item in services
        ],
        "",
        "## Selected Candidates",
        *[
            f"- {item.get('id')}: {', '.join(item.get('reasons', []))}"
            for item in selection.get("selected_candidates", [])
        ],
        "",
        "## Execution Results",
        *[
            f"- {item.get('selected_exploit_id')}: verified={item.get('verified')} proof={item.get('proof_output') or item.get('reason', '')}"
            for item in exploit.get("results", [])
        ],
    ]
    return "\n".join(lines)


def run_redteam_lab(
    target: str = DEFAULT_TARGET,
    ports: list[int] | None = None,
    provider: str = "llama",
    use_sudo: bool = False,
    run_safe_scripts: bool = True,
    run_exploit_validation: bool = False,
    max_exploit_candidates: int = 1,
    execution_mode: str = "safe",
    n_results: int = 5,
    settings: Settings | None = None,
) -> LabRun:
    settings = settings or load_settings()
    selected_ports = ports or default_ports_for_target(target)
    graph = build_redteam_lab_graph(settings, provider=provider, n_results=n_results)
    started = time.perf_counter()
    try:
        state = graph.invoke(
            {
                "target": target,
                "ports": selected_ports,
                "provider": provider,
                "use_sudo": use_sudo,
                "run_safe_scripts": run_safe_scripts,
                "run_exploit_validation": run_exploit_validation,
                "max_exploit_candidates": max_exploit_candidates,
                "execution_mode": execution_mode,
                "steps": [],
                "tool_traces": [],
            }
        )
        elapsed = time.perf_counter() - started
        nmap_result = state.get("nmap_result")
        safe_result = state.get("safe_script_result")
        return LabRun(
            target=target,
            provider=provider,
            report=state.get("report", ""),
            steps=state.get("steps", []),
            tool_traces=state.get("tool_traces", []),
            sources=state.get("sources", []),
            tcp=state.get("tcp", {}),
            services=state.get("services", []),
            http=state.get("http", {}),
            nmap=asdict(nmap_result) if nmap_result else {},
            safe_scripts=asdict(safe_result) if safe_result else None,
            exploit_selection=state.get("exploit_selection"),
            exploit_validation=state.get("exploit_validation"),
            kill_chain=state.get("kill_chain", []),
            elapsed_seconds=elapsed,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        return LabRun(
            target=target,
            provider=provider,
            report="",
            steps=[],
            tool_traces=[],
            sources=[],
            tcp={},
            services=[],
            http={},
            nmap={},
            exploit_selection=None,
            exploit_validation=None,
            kill_chain=[],
            elapsed_seconds=elapsed,
            error=str(exc),
        )


def save_lab_run(run: LabRun, output_dir: Path) -> dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    json_path = output_dir / f"redteam_lab_{stamp}.json"
    md_path = output_dir / f"redteam_lab_{stamp}.md"
    json_path.write_text(json.dumps(asdict(run), indent=2), encoding="utf-8")
    md_path.write_text(run.report or f"# Red-Team Lab Run\n\nError: {run.error}\n", encoding="utf-8")
    return {"json": json_path, "markdown": md_path}
