from __future__ import annotations

import asyncio
import time
from typing import Any

from llama_index.core.agent import FunctionAgent
from llama_index.core.tools import FunctionTool
from llama_index.llms.groq import Groq as LlamaIndexGroq

from medflow_ti.config import Settings, load_settings

from .schemas import ComparisonRun, ToolTrace
from .shared_tools import (
    SAFETY_BOUNDARY,
    build_redteam_queries,
    compact_hits,
    load_scenario,
    retrieve_redteam_context,
    safety_review_tool,
    scenario_to_text,
)


def _model_for_provider(settings: Settings, provider: str) -> tuple[str, dict[str, Any]]:
    if provider == "qwen":
        return settings.qwen_model, {}
    return settings.llama_model, {}


async def _run_agent(agent: FunctionAgent, prompt: str):
    try:
        handler = agent.run(user_msg=prompt)
    except TypeError:
        handler = agent.run(prompt)
    return await handler


def run_llamaindex_redteam(
    scenario_path: str | None = None,
    provider: str = "llama",
    n_results: int = 5,
    settings: Settings | None = None,
    verbose: bool = False,
) -> ComparisonRun:
    settings = settings or load_settings()
    scenario = load_scenario(scenario_path, settings=settings)
    traces: list[ToolTrace] = []
    collected_hits: dict[tuple[str, str], dict[str, Any]] = {}

    def search_medflow_redteam_knowledge(search_query: str) -> str:
        """Search MedFlow ATT&CK/red-team knowledge bases for safe validation evidence."""
        hits = retrieve_redteam_context(search_query, settings=settings, n_results=n_results)
        for hit in hits:
            collected_hits[(hit["collection"], hit["id"])] = hit
        output = compact_hits(hits, limit=n_results)
        traces.append(ToolTrace("search_medflow_redteam_knowledge", search_query, output[:500]))
        return output

    def review_redteam_safety(content: str) -> str:
        """Check a red-team plan for safe tabletop/purple-team boundaries."""
        output = safety_review_tool(content)
        traces.append(ToolTrace("review_redteam_safety", content[:500], output[:500]))
        return output

    tools = [
        FunctionTool.from_defaults(fn=search_medflow_redteam_knowledge),
        FunctionTool.from_defaults(fn=review_redteam_safety),
    ]

    model, extra_kwargs = _model_for_provider(settings, provider)
    llm = LlamaIndexGroq(
        model=model,
        api_key=settings.groq_api_key,
        temperature=0.2,
        max_tokens=1400,
        timeout=60,
        additional_kwargs=extra_kwargs,
    )
    agent = FunctionAgent(
        name="MedFlowRedTeamComparisonAgent",
        description="Safe red-team planning tool agent for comparing LlamaIndex against LangGraph.",
        system_prompt=f"""
You are a senior red-team lead evaluating LlamaIndex Agents for MedFlow.

{SAFETY_BOUNDARY}

Authorized scenario:
{scenario_to_text(scenario)}

Use the provided tools. Search the MedFlow knowledge base for ATT&CK and detection evidence, then safety-review your plan before finalizing.
Use "simulate", "validate", "observe", and "confirm control behavior" wording. Do not phrase steps as instructions to compromise a real system.
When naming ATT&CK IDs, analytics, or mitigations, use only tool-returned evidence. If you infer a likely mapping that was not retrieved, clearly label it as "candidate inference" and do not place it in the evidence section.
Return:
1. Executive summary
2. Agent workflow summary
3. Safe campaign plan
4. ATT&CK and detection evidence
5. Defensive validation checklist
6. Limitations and comparison notes
""",
        tools=tools,
        llm=llm,
        verbose=verbose,
        timeout=120,
    )

    prompt = f"""
Build a safe red-team validation brief for this authorized objective:
{scenario.objective}

Suggested retrieval queries:
{chr(10).join(f"- {item}" for item in build_redteam_queries(scenario))}

Use the KB search tool for at least one retrieval query and use the safety review tool before the final answer. Keep the final answer under 750 words.
The ATT&CK and detection evidence section must be based only on tool-returned sources.
Do not provide exploit code or real-world compromise instructions.
"""

    started = time.perf_counter()
    try:
        response = asyncio.run(_run_agent(agent, prompt))
        elapsed = time.perf_counter() - started
        sources = sorted(collected_hits.values(), key=lambda item: item.get("score", 0), reverse=True)
        return ComparisonRun(
            framework="LlamaIndex",
            provider=provider,
            scenario_name=scenario.name,
            answer=str(response),
            sources=sources,
            steps=[
                "created FunctionAgent with scenario, KB search, and safety tools",
                f"agent executed {len(traces)} captured tool calls",
                "returned final red-team exercise brief",
            ],
            tool_traces=traces,
            elapsed_seconds=elapsed,
        )
    except Exception as exc:
        elapsed = time.perf_counter() - started
        return ComparisonRun(
            framework="LlamaIndex",
            provider=provider,
            scenario_name=scenario.name,
            answer="",
            sources=sorted(collected_hits.values(), key=lambda item: item.get("score", 0), reverse=True),
            steps=[f"captured {len(traces)} tool calls before failure"],
            tool_traces=traces,
            elapsed_seconds=elapsed,
            error=str(exc),
        )
