from __future__ import annotations

import time
from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from medflow_ti.config import Settings, load_settings

from .schemas import ComparisonRun, RedTeamScenario
from .shared_tools import (
    build_final_report_prompt,
    build_planning_prompt,
    build_redteam_queries,
    call_redteam_llm,
    load_scenario,
    make_trace,
    retrieve_many,
    safety_review_tool,
)


class RedTeamGraphState(TypedDict, total=False):
    scenario: RedTeamScenario
    provider: str
    retrieval_queries: list[str]
    hits: list[dict[str, Any]]
    campaign_plan: str
    safety_review: str
    report: str
    steps: list[str]
    tool_traces: list[Any]


def _append_step(state: RedTeamGraphState, step: str) -> list[str]:
    return [*state.get("steps", []), step]


def build_langgraph_app(settings: Settings, provider: str = "llama", n_results: int = 5):
    def prepare_queries(state: RedTeamGraphState) -> RedTeamGraphState:
        scenario = state["scenario"]
        queries = build_redteam_queries(scenario)
        return {
            "retrieval_queries": queries,
            "steps": _append_step(state, "prepared deterministic red-team retrieval queries"),
        }

    def retrieve_context(state: RedTeamGraphState) -> RedTeamGraphState:
        queries = state["retrieval_queries"]
        hits = retrieve_many(queries, settings=settings, n_results=n_results)
        return {
            "hits": hits,
            "steps": _append_step(state, f"retrieved {len(hits)} unique MedFlow KB evidence items"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("retrieve_many", "\n".join(queries), f"{len(hits)} unique hits"),
            ],
        }

    def draft_campaign_plan(state: RedTeamGraphState) -> RedTeamGraphState:
        prompt = build_planning_prompt(state["scenario"], state["hits"])
        plan = call_redteam_llm(prompt, settings=settings, provider=provider)
        return {
            "campaign_plan": plan,
            "steps": _append_step(state, "drafted safe red-team campaign plan with LLM"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("call_redteam_llm:planning", state["scenario"].objective, plan),
            ],
        }

    def safety_gate(state: RedTeamGraphState) -> RedTeamGraphState:
        review = safety_review_tool(state["campaign_plan"])
        return {
            "safety_review": review,
            "steps": _append_step(state, "checked campaign plan against safety boundary"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("safety_review_tool", state["campaign_plan"], review),
            ],
        }

    def final_report(state: RedTeamGraphState) -> RedTeamGraphState:
        prompt = build_final_report_prompt(
            state["scenario"],
            state["hits"],
            state["campaign_plan"],
            state["safety_review"],
        )
        report = call_redteam_llm(prompt, settings=settings, provider=provider)
        return {
            "report": report,
            "steps": _append_step(state, "generated final red-team exercise brief"),
            "tool_traces": [
                *state.get("tool_traces", []),
                make_trace("call_redteam_llm:report", state["campaign_plan"], report),
            ],
        }

    graph = StateGraph(RedTeamGraphState)
    graph.add_node("prepare_queries", prepare_queries)
    graph.add_node("retrieve_context", retrieve_context)
    graph.add_node("draft_campaign_plan", draft_campaign_plan)
    graph.add_node("safety_gate", safety_gate)
    graph.add_node("final_report", final_report)
    graph.set_entry_point("prepare_queries")
    graph.add_edge("prepare_queries", "retrieve_context")
    graph.add_edge("retrieve_context", "draft_campaign_plan")
    graph.add_edge("draft_campaign_plan", "safety_gate")
    graph.add_edge("safety_gate", "final_report")
    graph.add_edge("final_report", END)
    return graph.compile()


def run_langgraph_redteam(
    scenario_path: str | None = None,
    provider: str = "llama",
    n_results: int = 5,
    settings: Settings | None = None,
) -> ComparisonRun:
    settings = settings or load_settings()
    scenario = load_scenario(scenario_path, settings=settings)
    started = time.perf_counter()
    app = build_langgraph_app(settings, provider=provider, n_results=n_results)
    try:
        state = app.invoke({"scenario": scenario, "provider": provider, "steps": [], "tool_traces": []})
        elapsed = time.perf_counter() - started
        return ComparisonRun(
            framework="LangGraph",
            provider=provider,
            scenario_name=scenario.name,
            answer=state.get("report", ""),
            sources=state.get("hits", []),
            steps=state.get("steps", []),
            tool_traces=state.get("tool_traces", []),
            elapsed_seconds=elapsed,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        return ComparisonRun(
            framework="LangGraph",
            provider=provider,
            scenario_name=scenario.name,
            answer="",
            elapsed_seconds=elapsed,
            error=str(exc),
        )
