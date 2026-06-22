from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import Settings
from .llm import is_llm_api_error, make_llm
from .vector_store import query


AGENTS = {
    "redteam": {
        "collections": ["redteam_db", "attack_db", "actor_db"],
        "role": "authorized healthcare red-team advisor focused on ATT&CK-based adversary simulation",
    },
    "threat_intel": {
        "collections": ["attack_db", "actor_db", "detection_db", "redteam_db"],
        "role": (
            "healthcare threat intelligence analyst covering technique lookup, "
            "attribution, detection engineering, mitigation, and incident response"
        ),
    },
}

AGENT_ALIASES = {
    "cti": "threat_intel",
    "attribution": "threat_intel",
    "detection": "threat_intel",
    "threat-intel": "threat_intel",
    "threatintel": "threat_intel",
}


SAFETY = """
Safety rules:
- Support authorized defensive security, education, and validation.
- Do not provide exploit code, credential theft instructions, destructive commands, stealth persistence recipes, or operational steps to compromise real systems.
- For red-team questions, give high-level attack-chain structure, assumptions, validation goals, telemetry to collect, and defensive controls.
- If the user asks for an unknown MITRE ID such as T9999, say it was not found in retrieved ATT&CK context instead of inventing details.
"""


@dataclass
class AgentAnswer:
    answer: str
    sources: list[dict]


def format_context(hits: list[dict], max_doc_chars: int = 1400, max_total_chars: int = 12000) -> str:
    lines = []
    for i, hit in enumerate(hits, 1):
        meta = hit.get("metadata") or {}
        label = " ".join(x for x in [meta.get("mitre_id", ""), meta.get("name", "")] if x)
        document = hit["document"]
        if len(document) > max_doc_chars:
            document = document[:max_doc_chars].rstrip() + "..."
        lines.append(
            f"[{i}] collection={hit['collection']} id={hit['id']} label={label}\n"
            f"url={meta.get('url', '')}\n{document}"
        )
    context = "\n\n".join(lines)
    if len(context) > max_total_chars:
        return context[:max_total_chars].rstrip() + "\n\n[context truncated]"
    return context


def answer_question(settings: Settings, agent: str, question: str, n_results: int = 8, provider: str = "llama") -> AgentAnswer:
    agent = AGENT_ALIASES.get(agent, agent)
    if agent not in AGENTS:
        raise ValueError(f"Unknown agent '{agent}'. Choose one of: {', '.join(AGENTS)}")

    spec = AGENTS[agent]
    hits = query(settings.chroma_dir, spec["collections"], question, settings.embedding_model, n_results=n_results)
    max_doc_chars, max_total_chars = context_budget(provider)
    context = format_context(hits, max_doc_chars=max_doc_chars, max_total_chars=max_total_chars)
    prompt = f"""
You are a {spec["role"]} for a hospital security team.

{SAFETY}

Use only the retrieved context when naming MITRE techniques, actors, tools, analytics, mitigations, or URLs. Clearly separate evidence from inference.

Question:
{question}

Retrieved context:
{context}

Answer with concise sections:
1. Direct answer
2. MITRE evidence
3. Healthcare-specific detection/response guidance
4. Gaps or uncertainty
"""
    llm = make_llm(
        provider=provider,
        groq_api_key=settings.groq_api_key,
        llama_model=settings.llama_model,
        qwen_model=settings.qwen_model,
    )
    try:
        answer = llm.generate(prompt)
    except Exception as exc:
        if not is_llm_api_error(exc):
            raise
        answer = fallback_answer(question, hits, f"{provider_label(provider)} API unavailable: {exc}")
    return AgentAnswer(answer=answer, sources=hits)


def provider_label(provider: str) -> str:
    return {"llama": "Llama 3.1 8B", "qwen": "Qwen 3 32B", "groq": "Qwen 3 32B"}.get(provider, provider)


def context_budget(provider: str) -> tuple[int, int]:
    if provider in {"qwen", "groq"}:
        return 550, 4200
    return 1400, 12000


def fallback_answer(question: str, hits: list[dict], reason: str) -> str:
    source_lines = []
    found_exact = False
    question_upper = question.upper()
    for hit in hits:
        meta = hit.get("metadata") or {}
        mitre_id = meta.get("mitre_id", "")
        if mitre_id and mitre_id.upper() in question_upper:
            found_exact = True
        label = " ".join(x for x in [mitre_id, meta.get("name", "")] if x).strip()
        source_lines.append(f"- {hit['collection']}: {label or hit['id']} {meta.get('url', '')}".strip())

    direct = "The selected LLM could not generate a narrative answer right now."
    if any(token.startswith("T") and token[1:].replace(".", "").isdigit() for token in question_upper.split()):
        direct = "No exact matching MITRE technique ID was found in the retrieved context." if not found_exact else direct

    return "\n".join(
        [
            "1. Direct answer",
            direct,
            "",
            "2. Retrieved MITRE evidence",
            "\n".join(source_lines[:8]) if source_lines else "No sources retrieved.",
            "",
            "3. LLM status",
            reason,
        ]
    )
