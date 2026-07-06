from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any


RAW_SECTIONS = [
    "tcp",
    "services",
    "http",
    "web_fingerprint",
    "web_routes",
    "web_checks",
    "capability_selection",
    "capability_validation",
    "normalized_evidence",
    "graph_memory",
    "sources",
    "agents",
    "phases",
    "loop_summary",
    "safety_review",
]


def load_campaign_payload(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def build_campaign_debug(payload: dict[str, Any]) -> dict[str, Any]:
    validation = payload.get("capability_validation") or {}
    results = validation.get("results") or []
    raw_sections = {key: payload.get(key) for key in RAW_SECTIONS if key in payload}
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {
            "goal": payload.get("goal"),
            "target": payload.get("target"),
            "provider": payload.get("provider"),
            "elapsed_seconds": payload.get("elapsed_seconds"),
            "error": payload.get("error"),
            "service_count": len(payload.get("services") or []),
            "tool_timeline_count": len(payload.get("tool_timeline") or []),
            "tool_trace_count": len(payload.get("tool_traces") or []),
            "validation_attempted": validation.get("attempted", 0),
            "validation_successful": validation.get("successful", 0),
            "validation_status_counts": validation.get("status_counts", {}),
        },
        "tool_timeline": payload.get("tool_timeline") or [],
        "tool_traces": payload.get("tool_traces") or [],
        "validation_results": results,
        "raw_sections": raw_sections,
    }


def export_campaign_debug(report_path: str | Path, output_dir: str | Path | None = None) -> dict[str, Path]:
    report = Path(report_path)
    payload = load_campaign_payload(report)
    debug = build_campaign_debug(payload)
    base_dir = Path(output_dir) if output_dir else Path("reports") / "debug" / report.stem
    raw_dir = base_dir / "raw"
    validation_dir = base_dir / "validation_results"
    raw_dir.mkdir(parents=True, exist_ok=True)
    validation_dir.mkdir(parents=True, exist_ok=True)

    paths: dict[str, Path] = {}
    debug_path = base_dir / "debug.json"
    debug_path.write_text(json.dumps(debug, indent=2, default=str), encoding="utf-8")
    paths["debug_json"] = debug_path

    timeline_path = base_dir / "tool_timeline.json"
    timeline_path.write_text(json.dumps(debug["tool_timeline"], indent=2, default=str), encoding="utf-8")
    paths["tool_timeline"] = timeline_path

    traces_path = base_dir / "tool_traces.json"
    traces_path.write_text(json.dumps(debug["tool_traces"], indent=2, default=str), encoding="utf-8")
    paths["tool_traces"] = traces_path

    summary_path = base_dir / "summary.md"
    summary_path.write_text(render_debug_markdown(debug), encoding="utf-8")
    paths["summary"] = summary_path

    for key, value in debug["raw_sections"].items():
        section_path = raw_dir / f"{key}.json"
        section_path.write_text(json.dumps(value, indent=2, default=str), encoding="utf-8")
        paths[f"raw_{key}"] = section_path

    for index, result in enumerate(debug["validation_results"], start=1):
        result_id = safe_filename(str(result.get("selected_exploit_id") or f"result_{index}"))
        result_path = validation_dir / f"{index:02d}_{result_id}.json"
        result_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
        paths[f"validation_{index:02d}"] = result_path

    return paths


def render_debug_markdown(debug: dict[str, Any]) -> str:
    summary = debug["summary"]
    lines = [
        "# MedFlow Campaign Debug",
        "",
        f"- Goal: {summary.get('goal')}",
        f"- Target: {summary.get('target')}",
        f"- Provider: {summary.get('provider')}",
        f"- Elapsed seconds: {summary.get('elapsed_seconds')}",
        f"- Services observed: {summary.get('service_count')}",
        f"- Tool timeline entries: {summary.get('tool_timeline_count')}",
        f"- Tool trace entries: {summary.get('tool_trace_count')}",
        f"- Validation: {summary.get('validation_successful')}/{summary.get('validation_attempted')} successful",
        f"- Validation status counts: `{json.dumps(summary.get('validation_status_counts') or {})}`",
        "",
        "## Tool Timeline",
    ]
    for item in debug.get("tool_timeline") or []:
        lines.extend(
            [
                f"### {item.get('tool')} `{item.get('status')}`",
                "",
                f"- Input: `{item.get('input', '')}`",
                "",
                "```text",
                str(item.get("evidence", "")),
                "```",
                "",
            ]
        )

    lines.append("## Validation Results")
    for item in debug.get("validation_results") or []:
        lines.extend(
            [
                f"### {item.get('selected_exploit_id')}",
                "",
                f"- Status: `{item.get('status')}`",
                f"- Runner: `{item.get('runner')}`",
                f"- Verified: `{item.get('verified')}`",
                f"- Exploited: `{item.get('exploited')}`",
                "",
                "```text",
                str(item.get("proof_output") or item.get("reason") or ""),
                "```",
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def safe_filename(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in value)[:120] or "item"
