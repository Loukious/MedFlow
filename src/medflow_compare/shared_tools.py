from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from medflow_ti.agents import format_context
from medflow_ti.config import Settings, load_settings
from medflow_ti.llm import make_llm
from medflow_ti.vector_store import query

from .schemas import RedTeamScenario, ToolTrace


REDTEAM_COLLECTIONS = ["redteam_db", "attack_db", "actor_db", "detection_db"]
DEFAULT_SCENARIO = "data/sample_alerts/redteam_hospital_portal.json"

SAFETY_BOUNDARY = """
Safety boundary:
- Treat this as an authorized tabletop or purple-team planning exercise.
- Use synthetic telemetry and control-validation checks; do not instruct the user to attempt live logins, send real MFA prompts, or touch real systems.
- Do not provide exploit code, credential theft instructions, evasion, persistence, destructive commands, or operational steps for compromising real systems.
- Keep offensive content at the level of validation objectives, assumptions, ATT&CK mapping, telemetry, detection tests, and response checks.
- Prefer "simulate", "validate", "observe", and "confirm controls" language over instructions to break into systems.
"""


def load_scenario(path: str | Path | None = None, settings: Settings | None = None) -> RedTeamScenario:
    settings = settings or load_settings()
    scenario_path = Path(path or settings.root / DEFAULT_SCENARIO)
    if not scenario_path.is_absolute():
        scenario_path = settings.root / scenario_path
    data = json.loads(scenario_path.read_text(encoding="utf-8"))
    return RedTeamScenario(**data)


def scenario_to_text(scenario: RedTeamScenario) -> str:
    return "\n".join(
        [
            f"Name: {scenario.name}",
            f"Environment: {scenario.environment}",
            f"Objective: {scenario.objective}",
            "Scope:",
            *[f"- {item}" for item in scenario.scope],
            "Out of scope:",
            *[f"- {item}" for item in scenario.out_of_scope],
            "Sample telemetry:",
            *[f"- {item}" for item in scenario.sample_telemetry],
            f"Deliverable: {scenario.deliverable}",
        ]
    )


def build_redteam_queries(scenario: RedTeamScenario) -> list[str]:
    telemetry = " ".join(scenario.sample_telemetry)
    return [
        f"{scenario.objective} ATT&CK red team validation",
        f"{telemetry} MFA fatigue password spraying device registration",
        "Multi-Factor Authentication Request Generation red team detection validation",
        "hospital portal identity provider session abuse detection response",
    ]


def retrieve_redteam_context(
    question: str,
    settings: Settings | None = None,
    n_results: int = 6,
    collections: list[str] | None = None,
) -> list[dict[str, Any]]:
    settings = settings or load_settings()
    return query(
        settings.chroma_dir,
        collections or REDTEAM_COLLECTIONS,
        question,
        settings.embedding_model,
        n_results=n_results,
    )


def retrieve_many(
    queries: list[str],
    settings: Settings | None = None,
    n_results: int = 5,
) -> list[dict[str, Any]]:
    settings = settings or load_settings()
    hits_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for search_query in queries:
        for hit in retrieve_redteam_context(search_query, settings=settings, n_results=n_results):
            key = (hit["collection"], hit["id"])
            existing = hits_by_key.get(key)
            if existing is None or hit.get("score", 0) > existing.get("score", 0):
                hit["source_query"] = search_query
                hits_by_key[key] = hit
    return sorted(hits_by_key.values(), key=lambda item: item.get("score", 0), reverse=True)


def compact_hits(hits: list[dict[str, Any]], limit: int = 8, max_chars: int = 900) -> str:
    rows = []
    for rank, hit in enumerate(hits[:limit], 1):
        meta = hit.get("metadata") or {}
        label = " ".join(x for x in [meta.get("mitre_id", ""), meta.get("name", "")] if x).strip()
        document = hit.get("document", "")
        if len(document) > max_chars:
            document = document[:max_chars].rstrip() + "..."
        rows.append(
            {
                "rank": rank,
                "collection": hit.get("collection"),
                "id": hit.get("id"),
                "label": label,
                "url": meta.get("url", ""),
                "score": round(float(hit.get("score") or 0), 3),
                "text": document,
            }
        )
    return json.dumps(rows, indent=2)


def medflow_kb_search_tool(search_query: str, n_results: int = 5) -> str:
    """Search MedFlow ATT&CK/red-team knowledge bases and return compact JSON evidence."""
    hits = retrieve_redteam_context(search_query, n_results=n_results)
    return compact_hits(hits, limit=n_results)


def safety_review_tool(content: str) -> str:
    """Review planned red-team content for the project safety boundary."""
    lowered = content.lower()
    negated_patterns = [
        "do not attempt real logins",
        "not attempt live logins",
        "do not send real mfa prompts",
        "not send real mfa prompts",
        "no real logins",
        "no real mfa prompts",
    ]
    normalized = lowered
    for phrase in negated_patterns:
        normalized = normalized.replace(phrase, "")
    blocked_patterns = [
        "steps to steal",
        "how to steal",
        "dump credentials",
        "attempt real logins",
        "send real mfa prompts",
        "disable logging",
        "turn off logging",
        "establish persistence",
        "evade detection by",
        "bypass detection by",
        "deploy ransomware",
        "encrypt files",
        "exploit code:",
        "payload code",
    ]
    findings = []
    for term in blocked_patterns:
        match = re.search(re.escape(term), normalized)
        if not match:
            continue
        nearby_prefix = normalized[max(0, match.start() - 90) : match.start()]
        if re.search(r"\b(no|not|never|without|avoid)\b", nearby_prefix):
            continue
        findings.append(term)
    verdict = "needs_revision" if findings else "approved_for_tabletop"
    return json.dumps(
        {
            "verdict": verdict,
            "findings": findings,
            "guidance": "Keep the output at validation, telemetry, detection, and response level.",
        },
        indent=2,
    )


def call_redteam_llm(prompt: str, settings: Settings, provider: str = "llama") -> str:
    llm = make_llm(
        provider=provider,
        groq_api_key=settings.groq_api_key,
        llama_model=settings.llama_model,
        qwen_model=settings.qwen_model,
        max_completion_tokens=1200,
    )
    return llm.generate(prompt)


def build_planning_prompt(scenario: RedTeamScenario, hits: list[dict[str, Any]]) -> str:
    return f"""
You are a senior red-team lead designing a safe, authorized healthcare validation exercise.

{SAFETY_BOUNDARY}

Scenario:
{scenario_to_text(scenario)}

Retrieved MedFlow context:
{format_context(hits[:6], max_doc_chars=500, max_total_chars=3600)}

Create a concise red-team validation plan. Keep the total response under 650 words.
When naming ATT&CK IDs, analytics, or mitigations, use only the retrieved context. If you infer a possible mapping that is not retrieved, label it as "candidate inference" rather than evidence.
Use these sections:
1. Campaign hypothesis
2. In-scope validation phases
3. ATT&CK mapping
4. Tools or telemetry to simulate
5. Expected detections
6. Safety guardrails
7. Report-ready success criteria
"""


def build_final_report_prompt(
    scenario: RedTeamScenario,
    hits: list[dict[str, Any]],
    campaign_plan: str,
    safety_review: str,
) -> str:
    return f"""
You are preparing a comparison-demo report for a red-team agent framework evaluation.

{SAFETY_BOUNDARY}

Scenario:
{scenario_to_text(scenario)}

Draft campaign plan:
{campaign_plan}

Safety review:
{safety_review}

Evidence:
{format_context(hits[:6], max_doc_chars=450, max_total_chars=3200)}

Return a polished red-team exercise brief under 750 words with:
Use only retrieved sources in the ATT&CK and detection evidence section. Put any non-retrieved ideas under limitations or candidate follow-up research.
1. Executive summary
2. Agent workflow summary
3. Safe campaign plan
4. ATT&CK and detection evidence
5. Defensive validation checklist
6. Limitations and next comparison criteria
"""


def make_trace(name: str, input_text: str, output_text: str, max_chars: int = 500) -> ToolTrace:
    preview = output_text if len(output_text) <= max_chars else output_text[:max_chars].rstrip() + "..."
    return ToolTrace(name=name, input=input_text, output_preview=preview)
