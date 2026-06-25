from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from medflow_compare.langgraph_workflow import run_langgraph_redteam
from medflow_compare.llamaindex_workflow import run_llamaindex_redteam
from medflow_compare.schemas import ComparisonRun


def source_label(hit: dict) -> str:
    meta = hit.get("metadata") or {}
    parts = [meta.get("mitre_id", ""), meta.get("name", "")]
    return " ".join(part for part in parts if part).strip() or hit.get("id", "")


def extract_ids(text: str) -> set[str]:
    return set(re.findall(r"\b(?:T|M|DET|AN)\d{4}(?:\.\d{3})?\b", text))


def source_ids(sources: list[dict]) -> set[str]:
    ids: set[str] = set()
    for hit in sources:
        meta = hit.get("metadata") or {}
        for value in [meta.get("mitre_id", ""), meta.get("name", ""), hit.get("document", "")[:500]]:
            ids.update(extract_ids(str(value)))
    return ids


def unsupported_answer_ids(run: ComparisonRun) -> list[str]:
    found = extract_ids(run.answer)
    supported = source_ids(run.sources)
    return sorted(found - supported)


def print_run(console: Console, run: ComparisonRun, show_sources: bool, show_traces: bool) -> None:
    status = "ERROR" if run.error else "OK"
    console.rule(f"{run.framework} [{status}]")
    console.print(f"Provider: [bold]{run.provider}[/bold]")
    console.print(f"Elapsed: [bold]{run.elapsed_seconds:.2f}s[/bold]")
    if run.error:
        console.print(f"[red]{run.error}[/red]")
    else:
        console.print(Panel(run.answer.strip() or "(empty answer)", title=f"{run.framework} Output"))

    unsupported = unsupported_answer_ids(run)
    if unsupported:
        console.print(
            "[yellow]Source audit:[/yellow] answer mentioned IDs not present in retrieved sources: "
            + ", ".join(unsupported)
        )

    steps = Table("Step")
    for step in run.steps:
        steps.add_row(step)
    console.print(steps)

    if show_traces and run.tool_traces:
        trace_table = Table("Tool", "Input", "Output Preview")
        for trace in run.tool_traces:
            trace_table.add_row(trace.name, trace.input[:180], trace.output_preview[:260])
        console.print(trace_table)

    if show_sources and run.sources:
        source_table = Table("Rank", "Collection", "Label", "Score")
        for rank, hit in enumerate(run.sources[:10], 1):
            source_table.add_row(
                str(rank),
                hit.get("collection", ""),
                source_label(hit),
                f"{float(hit.get('score') or 0):.3f}",
            )
        console.print(source_table)


def print_summary(console: Console, runs: list[ComparisonRun]) -> None:
    table = Table("Framework", "Status", "Elapsed", "Tool Calls", "Sources", "Unsupported IDs", "Notes")
    for run in runs:
        table.add_row(
            run.framework,
            "error" if run.error else "ok",
            f"{run.elapsed_seconds:.2f}s",
            str(len(run.tool_traces)),
            str(len(run.sources)),
            ", ".join(unsupported_answer_ids(run)) or "-",
            (run.error or "completed")[:80],
        )
    console.rule("Comparison Summary")
    console.print(table)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare LangGraph and LlamaIndex on the same safe MedFlow red-team planning scenario."
    )
    parser.add_argument("--framework", choices=["langgraph", "llamaindex", "both"], default="both")
    parser.add_argument("--provider", choices=["llama", "qwen"], default="llama")
    parser.add_argument("--scenario", default=None, help="Path to a scenario JSON file.")
    parser.add_argument("--results", type=int, default=5, help="Retrieved KB results per query/tool call.")
    parser.add_argument("--sources", action="store_true", help="Show retrieved sources.")
    parser.add_argument("--traces", action="store_true", help="Show tool traces.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of rich text.")
    parser.add_argument("--verbose-llamaindex", action="store_true", help="Show LlamaIndex ReAct trace output.")
    args = parser.parse_args()

    runs: list[ComparisonRun] = []
    if args.framework in {"langgraph", "both"}:
        runs.append(run_langgraph_redteam(args.scenario, provider=args.provider, n_results=args.results))
    if args.framework in {"llamaindex", "both"}:
        runs.append(
            run_llamaindex_redteam(
                args.scenario,
                provider=args.provider,
                n_results=args.results,
                verbose=args.verbose_llamaindex,
            )
        )

    if args.json:
        print(json.dumps([asdict(run) for run in runs], indent=2))
        return

    console = Console()
    print_summary(console, runs)
    for run in runs:
        print_run(console, run, show_sources=args.sources, show_traces=args.traces)


if __name__ == "__main__":
    main()
