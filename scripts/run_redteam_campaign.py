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
    ports: set[int] = set()
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise ValueError(f"Invalid port range: {item}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError(f"Invalid TCP port(s): {invalid[:5]}")
    return sorted(ports)


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
            f"Web routes found: {web_route_label(run)}",
            f"Capability validation: {validation_label(run)}",
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

    if run.capability_validation and run.capability_validation.get("results"):
        validation_table = Table("Capability", "Status", "Evidence")
        for item in run.capability_validation["results"]:
            validation_table.add_row(
                item.get("selected_exploit_id", ""),
                "verified" if item.get("verified") else "not verified",
                (item.get("proof_output") or item.get("reason") or "")[:260],
            )
        console.print(validation_table)

    if run.web_routes and run.web_routes.get("web_routes"):
        routes_table = Table("URL", "Status", "Signal")
        interesting = [
            item for item in run.web_routes["web_routes"]
            if item.get("status") and (item.get("status") != 404 or item.get("artifact_signal"))
        ]
        for item in interesting[:12]:
            routes_table.add_row(
                item.get("url", ""),
                str(item.get("status", "")),
                item.get("artifact_signal") or item.get("title") or item.get("content_type", ""),
            )
        console.print(routes_table)

    if show_traces:
        traces = Table("Tool/Agent", "Input", "Output Preview")
        for trace in run.tool_traces:
            traces.add_row(trace.name, trace.input[:160], trace.output_preview[:260])
        console.print(traces)

    if show_report:
        console.print(Panel(run.report.strip() or "(empty report)", title="Campaign Report"))


def validation_label(run: CampaignRun) -> str:
    validation = run.capability_validation or {}
    if not validation:
        return "not requested"
    return f"{validation.get('successful', 0)}/{validation.get('attempted', 0)} verified"


def web_route_label(run: CampaignRun) -> str:
    routes = (run.web_routes or {}).get("web_routes", [])
    found = [item for item in routes if item.get("status") and item.get("status") != 404]
    artifact = [item for item in routes if item.get("artifact_signal")]
    return f"{len(found)} non-404, {len(artifact)} artifact signal(s)"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MedFlow multi-agent red-team campaign planner.")
    parser.add_argument("goal", help="High-level campaign goal, for example: validate hospital portal identity attack paths.")
    parser.add_argument("--target", default=None, help="Optional allowlisted target for active reconnaissance.")
    parser.add_argument("--ports", default=None, help="Comma-separated ports for active reconnaissance.")
    parser.add_argument("--execute-recon", action="store_true", help="Let the Reconnaissance Agent run active allowlisted probes.")
    parser.add_argument("--execute-validation", action="store_true", help="Select and run matching capability validation tools after recon.")
    parser.add_argument("--max-capabilities", type=int, default=5, help="Maximum matching validation capabilities to execute.")
    parser.add_argument(
        "--execution-mode",
        choices=["safe", "aggressive_lab"],
        default="safe",
        help="Execution policy for selected validation capabilities.",
    )
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
        execute_validation=args.execute_validation,
        max_capabilities=args.max_capabilities,
        execution_mode=args.execution_mode,
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
