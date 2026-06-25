from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from medflow_redteam.campaign import CampaignRun, run_campaign, save_campaign_run


def parse_ports(value: str | None) -> list[int] | None:
    if not value:
        return None
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def print_campaign(console: Console, run: CampaignRun, show_report: bool, show_traces: bool) -> None:
    status = "ERROR" if run.error else "OK"
    console.rule(f"MedFlow Red-Team Campaign [{status}]")
    console.print(f"Goal: [bold]{run.goal}[/bold]")
    console.print(f"Target: [bold]{run.target or 'tabletop / no live target'}[/bold]")
    console.print(f"Provider: [bold]{run.provider}[/bold]")
    console.print(f"Elapsed: [bold]{run.elapsed_seconds:.2f}s[/bold]")
    if run.error:
        console.print(f"[red]{run.error}[/red]")
        return

    summary = "\n".join(
        [
            f"Agents completed: {len(run.agents)}",
            f"Services observed: {len(run.services)}",
            f"Retrieved sources: {len(run.sources)}",
            f"Safety review: {run.safety_review[:180] if run.safety_review else 'not run'}",
        ]
    )
    console.print(Panel(summary, title="Campaign Summary"))

    agent_table = Table("Agent", "Tools", "Handoff")
    for agent in run.agents:
        agent_table.add_row(
            agent.role,
            ", ".join(agent.tools[:5]),
            agent.handoff[:220],
        )
    console.print(agent_table)

    if run.services:
        services = Table("Port", "Service", "Version")
        for service in run.services:
            services.add_row(service.get("port", ""), service.get("service", ""), service.get("version", ""))
        console.print(services)

    if show_traces:
        traces = Table("Tool/Agent", "Input", "Output Preview")
        for trace in run.tool_traces:
            traces.add_row(trace.name, trace.input[:160], trace.output_preview[:260])
        console.print(traces)

    if show_report:
        console.print(Panel(run.report.strip() or "(empty report)", title="Campaign Report"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MedFlow multi-agent red-team campaign planner.")
    parser.add_argument("goal", help="High-level campaign goal, for example: validate hospital portal identity attack paths.")
    parser.add_argument("--target", default=None, help="Optional allowlisted target for active reconnaissance.")
    parser.add_argument("--ports", default=None, help="Comma-separated ports for active reconnaissance.")
    parser.add_argument("--execute-recon", action="store_true", help="Let the Reconnaissance Agent run active allowlisted probes.")
    parser.add_argument("--no-llm", action="store_true", help="Use deterministic role handoffs for a fast offline demo.")
    parser.add_argument("--provider", choices=["llama", "qwen"], default="llama")
    parser.add_argument("--results", type=int, default=5, help="Retrieved context results per query.")
    parser.add_argument("--output-dir", default="reports/redteam_campaign", help="Directory for JSON and Markdown outputs.")
    parser.add_argument("--report", action="store_true", help="Print the generated campaign report.")
    parser.add_argument("--traces", action="store_true", help="Print role/tool traces.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of rich text.")
    args = parser.parse_args()

    run = run_campaign(
        goal=args.goal,
        target=args.target,
        ports=parse_ports(args.ports),
        provider=args.provider,
        execute_recon=args.execute_recon,
        use_llm=not args.no_llm,
        n_results=args.results,
    )
    saved = save_campaign_run(run, Path(args.output_dir))

    if args.json:
        data = asdict(run)
        data["saved"] = {name: str(path) for name, path in saved.items()}
        print(json.dumps(data, indent=2, default=str))
        return

    console = Console()
    print_campaign(console, run, show_report=args.report, show_traces=args.traces)
    console.print(f"Saved JSON: [bold]{saved['json']}[/bold]")
    console.print(f"Saved Markdown: [bold]{saved['markdown']}[/bold]")


if __name__ == "__main__":
    main()
