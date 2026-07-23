from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from medflow_compare.shared_tools import SAFETY_BOUNDARY, call_redteam_llm
from medflow_graph.memory import GraphStore
from medflow_ti.config import Settings, load_settings

from .generated_tools import load_generated_tool_specs, save_generated_tool, tcp_banner_template


DEFAULT_GRAPH_PATH = Path("data/graph/medflow_graph.json")


@dataclass
class ToolsmithResult:
    action: str
    spec: dict[str, Any] | None = None
    paths: dict[str, Path] | None = None
    graph_node_id: str | None = None
    matches: list[dict[str, Any]] | None = None


class ToolsmithAgent:
    """Create and retrieve on-demand generated tools.

    Config-side generated tools are intentionally empty. Toolsmith writes new
    tools to data/generated_tools and indexes metadata in graph memory.
    """

    def __init__(
        self,
        *,
        graph_path: Path | str = DEFAULT_GRAPH_PATH,
        settings: Settings | None = None,
        provider: str = "gpt_oss",
    ) -> None:
        self.graph_path = Path(graph_path)
        self.settings = settings or load_settings()
        self.provider = provider

    def lookup(self, query: str, limit: int = 5) -> list[dict[str, Any]]:
        store = GraphStore.load(self.graph_path)
        graph_hits = store.search(query, limit=limit, node_types={"GeneratedTool"})
        spec_hits = self._spec_lookup(query, limit=limit)
        seen = {tool_identity(hit) for hit in graph_hits}
        for hit in spec_hits:
            identity = tool_identity(hit)
            if identity not in seen:
                graph_hits.append(hit)
                seen.add(identity)
        return sorted(graph_hits, key=lambda item: item.get("score", 0), reverse=True)[:limit]

    def create_from_template(
        self,
        *,
        tool_id: str,
        template: str,
        service: str,
        port: int,
        overwrite: bool = False,
    ) -> ToolsmithResult:
        if template != "tcp_banner":
            raise ValueError(f"Unsupported Toolsmith template: {template}")
        spec, code = tcp_banner_template(tool_id, service, port)
        return self.save(tool_id, spec, code, overwrite=overwrite)

    def create_from_prompt(self, *, tool_id: str, prompt: str, overwrite: bool = False) -> ToolsmithResult:
        spec, code = self.generate_with_llm(prompt)
        spec["id"] = spec.get("id") or f"generated:{tool_id}"
        return self.save(tool_id, spec, code, overwrite=overwrite)

    def save(self, tool_id: str, spec: dict[str, Any], code: str, *, overwrite: bool = False) -> ToolsmithResult:
        spec["id"] = spec.get("id") or f"generated:{tool_id}"
        if not spec["id"].startswith("generated:"):
            spec["id"] = f"generated:{spec['id']}"
        spec["provider"] = "generated_python"
        spec["runner"] = "generated_python_tool"
        paths = save_generated_tool(tool_id, spec, code, overwrite=overwrite)
        graph_node_id = self.index_tool(spec, paths)
        return ToolsmithResult(action="created", spec=spec, paths=paths, graph_node_id=graph_node_id)

    def index_tool(self, spec: dict[str, Any], paths: dict[str, Path]) -> str:
        store = GraphStore.load(self.graph_path)
        match = spec.get("match") or {}
        context = " ".join(
            [
                str(spec.get("id", "")),
                str(spec.get("name", "")),
                str(spec.get("description", "")),
                str(spec.get("proof_goal", "")),
                json.dumps(match, sort_keys=True),
            ]
        )
        result = store.upsert_node(
            "GeneratedTool",
            str(spec.get("id")),
            stable_key=str(spec.get("id")),
            attributes={
                "tool_id": spec.get("id"),
                "name": spec.get("name"),
                "description": spec.get("description"),
                "risk": spec.get("risk"),
                "safe_to_execute": spec.get("safe_to_execute"),
                "allowed_execution_modes": spec.get("allowed_execution_modes", []),
                "match": match,
                "proof_goal": spec.get("proof_goal"),
                "spec_path": str(paths.get("specs", "")),
                "code_path": str(paths.get("code", "")),
            },
            context=context,
            source_id=str(paths.get("specs", "")),
        )
        store.save()
        return result.node.id

    def generate_with_llm(self, prompt: str) -> tuple[dict[str, Any], str]:
        request = f"""
You are MedFlow Toolsmith, generating an on-demand Python validation tool for an authorized lab/purple-team system.

{SAFETY_BOUNDARY}

Generate only safe observation, parser, fingerprint, or evidence-normalization tools unless the request explicitly says this is for a local isolated lab.
Do not generate credential theft, brute force, persistence, evasion, destructive behavior, ransomware, or arbitrary shell execution.
The generated Python code must define:

def run(context: dict) -> dict:
    ...

Allowed imports: concurrent, ftplib, html, ipaddress, json, re, shutil, socket, subprocess, time, urllib, xml.
Return strict JSON with keys:
spec, code

The spec must include:
id, name, description, provider="generated_python", runner="generated_python_tool",
risk, safe_to_execute, allowed_execution_modes, match, proof_goal.

User tool request:
{prompt}
"""
        raw = call_redteam_llm(request, settings=self.settings, provider=self.provider)
        parsed = parse_json_object(raw)
        return parsed["spec"], parsed["code"]

    def _spec_lookup(self, query: str, limit: int) -> list[dict[str, Any]]:
        query_terms = {term for term in query.lower().replace("/", " ").replace(":", " ").split() if len(term) > 1}
        hits: list[dict[str, Any]] = []
        for spec in load_generated_tool_specs():
            text = " ".join(
                [
                    str(spec.get("id", "")),
                    str(spec.get("name", "")),
                    str(spec.get("description", "")),
                    str(spec.get("proof_goal", "")),
                    json.dumps(spec.get("match") or {}, sort_keys=True),
                ]
            ).lower()
            if not query_terms:
                score = 0.0
            else:
                score = len(query_terms & set(text.replace("/", " ").replace(":", " ").split())) / len(query_terms)
            if score > 0:
                hits.append(
                    {
                        "id": str(spec.get("id")),
                        "type": "GeneratedTool",
                        "name": str(spec.get("id")),
                        "score": round(score, 3),
                        "attributes": spec,
                        "context": text[:1200],
                        "source_ids": [str(spec.get("source", ""))],
                    }
                )
        return sorted(hits, key=lambda item: item["score"], reverse=True)[:limit]


def parse_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        stripped = stripped.removeprefix("json").strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("No JSON object found in generated response.")
    return json.loads(stripped[start : end + 1])


def tool_identity(hit: dict[str, Any]) -> str:
    attributes = hit.get("attributes") or {}
    return str(attributes.get("tool_id") or attributes.get("id") or hit.get("id"))
