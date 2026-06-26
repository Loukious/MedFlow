from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from medflow_redteam.docker_lab import CONTAINER_IP, setup_lab, stop_lab
from medflow_redteam.langgraph_lab import LabRun, run_redteam_lab, save_lab_run


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


def source_label(hit: dict) -> str:
    meta = hit.get("metadata") or {}
    label = " ".join(part for part in [meta.get("mitre_id", ""), meta.get("name", "")] if part).strip()
    return label or hit.get("id", "")


def exploit_status(run: LabRun) -> tuple[str, str]:
    exploit = run.exploit_validation or {}
    if not exploit:
        return "not requested", "Run with --exploit-validation to perform the lab exploit proof."
    if exploit.get("results"):
        lines = []
        for item in exploit["results"]:
            status = "success" if item.get("verified") else "failed"
            detail = item.get("proof_output") or item.get("reason") or "no proof output"
            lines.append(f"{item.get('selected_exploit_id')}: {status} - {detail}")
        return (
            f"{exploit.get('successful', 0)}/{exploit.get('attempted', len(exploit['results']))} successful",
            "\n".join(lines),
        )
    if exploit.get("verified"):
        proof = exploit.get("proof_output") or "proof output captured"
        return "successful", f"Remote command execution verified: {proof}"
    if exploit.get("exploited") and not exploit.get("verified"):
        return "unverified", exploit.get("verification_note") or "Exploit signal was sent, but verification failed."
    return "failed", exploit.get("reason") or exploit.get("error") or "Exploit validation did not succeed."


def selected_exploit_label(run: LabRun) -> str:
    selection = run.exploit_selection or {}
    selected_candidates = selection.get("selected_candidates") or ([selection.get("selected")] if selection.get("selected") else [])
    if not selected_candidates:
        return "none"
    labels = []
    for selected in selected_candidates:
        reasons = ", ".join(selected.get("reasons", []))
        labels.append(f"{selected.get('id')} ({reasons})")
    return "\n".join(labels)


def print_run(console: Console, run: LabRun, show_sources: bool, show_traces: bool, show_report: bool) -> None:
    status = "ERROR" if run.error else "OK"
    console.rule(f"LangGraph Red-Team Lab [{status}]")
    console.print(f"Target: [bold]{run.target}[/bold]")
    console.print(f"Provider: [bold]{run.provider}[/bold]")
    console.print(f"Elapsed: [bold]{run.elapsed_seconds:.2f}s[/bold]")
    if run.error:
        console.print(f"[red]{run.error}[/red]")
        return

    exploit_label, exploit_detail = exploit_status(run)
    open_services = ", ".join(
        f"{service.get('port')}/{service.get('service')}" for service in run.services
    ) or "none"
    summary = "\n".join(
        [
            f"Open services: {open_services}",
            f"Selected capabilities: {selected_exploit_label(run)}",
            f"Capability validation: {exploit_label}",
            f"Evidence: {exploit_detail}",
        ]
    )
    console.print(Panel(summary, title="Outcome Summary"))

    if run.kill_chain:
        chain_table = Table("Kill-Chain Phase", "Status", "Evidence")
        for item in run.kill_chain:
            chain_table.add_row(
                item.get("phase", ""),
                item.get("status", ""),
                str(item.get("evidence", ""))[:220],
            )
        console.print(chain_table)

    steps = Table("Step")
    for step in run.steps:
        steps.add_row(step)
    console.print(steps)

    services = Table("Port", "Proto", "Service", "Version")
    for service in run.services:
        services.add_row(
            service.get("port", ""),
            service.get("protocol", ""),
            service.get("service", ""),
            service.get("version", ""),
        )
    console.print(services)

    if show_traces:
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

    if show_report:
        console.print(Panel(run.report.strip() or "(empty report)", title="Narrative Report"))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the Milestone 2 LangGraph red-team lab workflow against local Metasploitable3."
    )
    parser.add_argument("--setup-lab", action="store_true", help="Create internal Docker network and start Metasploitable3.")
    parser.add_argument("--pull-image", action="store_true", help="Pull or refresh the Metasploitable3 image before starting.")
    parser.add_argument("--recreate-lab", action="store_true", help="Recreate the lab container before running.")
    parser.add_argument("--setup-only", action="store_true", help="Set up the Docker lab and exit without running the agent workflow.")
    parser.add_argument("--stop-lab", action="store_true", help="Stop the Metasploitable3 lab container and exit.")
    parser.add_argument("--use-sudo", action="store_true", help="Run Docker commands through sudo.")
    parser.add_argument("--target", default=CONTAINER_IP, help="Lab target. Defaults to the isolated Docker container IP.")
    parser.add_argument("--ports", default=None, help="Comma-separated target ports. Defaults depend on target.")
    parser.add_argument("--provider", choices=["llama", "qwen"], default="llama")
    parser.add_argument("--results", type=int, default=5, help="MedFlow/ATT&CK retrieval results per query.")
    parser.add_argument("--skip-safe-scripts", action="store_true", help="Skip nmap default,safe NSE scripts.")
    parser.add_argument(
        "--exploit-validation",
        action="store_true",
        help="Run selected controlled exploitation/validation capabilities against the isolated lab target.",
    )
    parser.add_argument("--max-exploits", type=int, default=1, help="Maximum matching exploit/tool candidates to execute.")
    parser.add_argument(
        "--execution-mode",
        choices=["safe", "aggressive_lab"],
        default="safe",
        help="Execution policy for selected capabilities.",
    )
    parser.add_argument("--sources", action="store_true", help="Show retrieved MedFlow/ATT&CK sources.")
    parser.add_argument("--traces", action="store_true", help="Show tool traces.")
    parser.add_argument("--report", action="store_true", help="Print the generated narrative report in the terminal.")
    parser.add_argument("--output-dir", default="reports/redteam_lab", help="Directory for JSON and Markdown reports.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of rich text.")
    args = parser.parse_args()

    console = Console()
    if args.stop_lab:
        result = stop_lab(use_sudo=args.use_sudo)
        if args.json:
            print(json.dumps(result.__dict__, indent=2))
        else:
            console.print(result.__dict__)
        return

    if args.setup_lab:
        lab = setup_lab(use_sudo=args.use_sudo, pull=args.pull_image, recreate=args.recreate_lab)
        if args.json:
            print(json.dumps(lab, indent=2))
        else:
            console.rule("Docker Lab Setup")
            console.print_json(json.dumps(lab))
        if args.setup_only:
            return

    run = run_redteam_lab(
        target=args.target,
        ports=parse_ports(args.ports),
        provider=args.provider,
        use_sudo=args.use_sudo,
        run_safe_scripts=not args.skip_safe_scripts,
        run_exploit_validation=args.exploit_validation,
        max_exploit_candidates=args.max_exploits,
        execution_mode=args.execution_mode,
        n_results=args.results,
    )
    saved = save_lab_run(run, Path(args.output_dir))

    if args.json:
        data = asdict(run)
        data["saved"] = {name: str(path) for name, path in saved.items()}
        print(json.dumps(data, indent=2))
        return

    print_run(console, run, show_sources=args.sources, show_traces=args.traces, show_report=args.report)
    console.print(f"Saved JSON: [bold]{saved['json']}[/bold]")
    console.print(f"Saved Markdown: [bold]{saved['markdown']}[/bold]")


if __name__ == "__main__":
    main()
