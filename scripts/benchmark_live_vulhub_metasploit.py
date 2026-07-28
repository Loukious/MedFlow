from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from medflow_redteam.campaign import run_campaign
from medflow_redteam.config_loader import ROOT


VULHUB_CONFIG = ROOT / "config" / "vulhub_labs.json"
SELECTION_MANIFEST = ROOT / "config" / "benchmarks" / "vulhub_metasploit_selection.json"
REPORT_DIR = ROOT / "reports" / "benchmarks"


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def docker_status(project: str) -> list[dict[str, Any]]:
    import subprocess

    proc = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={project}", "--format", "{{json .}}"],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    containers: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        container = json.loads(line)
        inspect = subprocess.run(
            ["docker", "inspect", container["ID"], "--format", "{{json .NetworkSettings.Networks}}"],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        ips: list[str] = []
        if inspect.returncode == 0 and inspect.stdout.strip():
            networks = json.loads(inspect.stdout)
            ips = [value.get("IPAddress") for value in networks.values() if value.get("IPAddress")]
        container["IPs"] = ips
        containers.append(container)
    return containers


def first_running_ip(project: str) -> str:
    for container in docker_status(project):
        if str(container.get("State", "")).lower() == "running":
            ips = container.get("IPs") or []
            if ips:
                return str(ips[0])
    return ""


def expected_ids(lab: dict[str, Any]) -> set[str]:
    return {f"metasploit:{item}" for item in lab.get("expected_metasploit_modules", [])}


def selected_metasploit_results(run_data: dict[str, Any]) -> list[dict[str, Any]]:
    results = ((run_data.get("capability_validation") or {}).get("results")) or []
    return [item for item in results if item.get("provider") == "metasploit" or item.get("runner") == "metasploit_module"]


def summarize_run(name: str, expected: set[str], run_data: dict[str, Any]) -> dict[str, Any]:
    metasploit_results = selected_metasploit_results(run_data)
    exploited = [item for item in metasploit_results if item.get("exploited")]
    verified = [item for item in metasploit_results if item.get("verified")]
    selected_ids = [str(item.get("selected_exploit_id")) for item in metasploit_results]
    expected_selected = bool(expected & set(selected_ids))
    expected_exploited = any(item.get("selected_exploit_id") in expected and item.get("exploited") for item in metasploit_results)
    proof = ""
    for item in exploited or verified:
        proof = str(item.get("proof_output") or item.get("reason") or "")
        if proof:
            break
    validation = run_data.get("capability_validation") or {}
    selection = run_data.get("capability_selection") or {}
    return {
        "name": name,
        "status": "exploited" if exploited else ("verified_only" if verified else "no_exploit_proof"),
        "expected_selected": expected_selected,
        "expected_exploited": expected_exploited,
        "selected_metasploit": selected_ids,
        "proof": proof,
        "validation_status_counts": validation.get("status_counts", {}),
        "attempted": validation.get("attempted", 0),
        "successful": validation.get("successful", 0),
        "top_candidates": [
            {
                "id": item.get("id"),
                "score": item.get("score"),
                "runner": item.get("runner"),
                "provider": item.get("provider"),
                "reasons": item.get("reasons", [])[:8],
            }
            for item in (selection.get("selected_candidates") or [])[:8]
        ],
    }


def run_live_lab(
    lab: dict[str, Any],
    lab_runtime: dict[str, Any],
    *,
    max_capabilities: int,
    provider: str,
    use_llm: bool,
    loop: bool,
    max_rounds: int,
    max_tools: int,
) -> dict[str, Any]:
    target = first_running_ip(lab_runtime["project"])
    if not target:
        return {
            "name": lab["name"],
            "vulhub_path": lab["vulhub_path"],
            "project": lab_runtime["project"],
            "status": "skipped_not_running",
            "target": "",
            "ports": lab_runtime.get("ports") or [int(lab["service"]["port"])],
            "expected_modules": lab.get("expected_metasploit_modules", []),
        }
    ports = [int(port) for port in (lab_runtime.get("ports") or [int(lab["service"]["port"])])]
    run = run_campaign(
        goal=lab_runtime.get("goal", f"Assess an authorized Vulhub lab target: {lab['name']}"),
        target=target,
        ports=ports,
        provider=provider,
        execute_recon=True,
        execute_validation=True,
        max_capabilities=max_capabilities,
        execution_mode="aggressive_lab",
        metasploit_action="exploit",
        use_llm=use_llm,
        loop=loop,
        max_rounds=max_rounds,
        max_tools=max_tools,
        stop_on_success=False if loop else True,
    )
    run_data = asdict(run)
    summary = summarize_run(lab["name"], expected_ids(lab), run_data)
    return {
        **summary,
        "vulhub_path": lab["vulhub_path"],
        "project": lab_runtime["project"],
        "target": target,
        "ports": ports,
        "expected_modules": lab.get("expected_metasploit_modules", []),
        "elapsed_seconds": run.elapsed_seconds,
        "error": run.error,
        "campaign": run_data,
    }


def print_results(results: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    console = Console()
    table = Table(title="Live Vulhub Metasploit Exploit Benchmark")
    table.add_column("Lab")
    table.add_column("Status")
    table.add_column("Expected")
    table.add_column("Selected Metasploit")
    table.add_column("Proof")
    for item in results:
        table.add_row(
            item["name"],
            item["status"],
            "yes" if item.get("expected_exploited") else ("selected" if item.get("expected_selected") else "no"),
            "\n".join(item.get("selected_metasploit") or [])[:180],
            str(item.get("proof") or item.get("error") or "")[:180],
        )
    console.print(table)
    console.print(json.dumps(summary, indent=2))


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    runnable = [item for item in results if item.get("status") != "skipped_not_running"]
    return {
        "total": len(results),
        "runnable": len(runnable),
        "skipped_not_running": sum(1 for item in results if item.get("status") == "skipped_not_running"),
        "exploited": sum(1 for item in runnable if item.get("status") == "exploited"),
        "solved": sum(1 for item in runnable if item.get("status") == "exploited"),
        "expected_selected": sum(1 for item in runnable if item.get("expected_selected")),
        "expected_exploited": sum(1 for item in runnable if item.get("expected_exploited")),
        "verified_only": sum(1 for item in runnable if item.get("status") == "verified_only"),
        "no_exploit_proof": [item["name"] for item in runnable if item.get("status") == "no_exploit_proof"],
        "skipped": [item["name"] for item in results if item.get("status") == "skipped_not_running"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run live Metasploit exploit validation across running Vulhub labs.")
    parser.add_argument("--labs", nargs="*", default=["all"], help="Manifest lab names to run, or all.")
    parser.add_argument("--max-labs", type=int, default=0, help="Limit number of labs after filtering.")
    parser.add_argument("--max-capabilities", type=int, default=6)
    parser.add_argument(
        "--provider",
        choices=["gpt_oss", "llama", "qwen", "local_qwen"],
        default="gpt_oss",
    )
    parser.add_argument("--llm", action="store_true", help="Use configured LLM for narrative report generation.")
    parser.add_argument("--loop", action="store_true", help="Keep trying additional selected capabilities after initial validation.")
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--max-tools", type=int, default=12)
    parser.add_argument("--save-report", action="store_true")
    args = parser.parse_args()

    runtime_labs = load_json(VULHUB_CONFIG)["labs"]
    manifest_labs = load_json(SELECTION_MANIFEST)["labs"]
    requested = set(args.labs)
    if requested and "all" not in requested:
        manifest_labs = [lab for lab in manifest_labs if lab["name"] in requested]
    if args.max_labs:
        manifest_labs = manifest_labs[: args.max_labs]

    results: list[dict[str, Any]] = []
    for lab in manifest_labs:
        runtime = runtime_labs.get(lab["name"])
        if not runtime:
            results.append({"name": lab["name"], "status": "skipped_missing_runtime_config"})
            continue
        results.append(
            run_live_lab(
                lab,
                runtime,
                max_capabilities=args.max_capabilities,
                provider=args.provider,
                use_llm=args.llm,
                loop=args.loop,
                max_rounds=args.max_rounds,
                max_tools=args.max_tools,
            )
        )

    summary = build_summary(results)
    print_results(results, summary)
    if args.save_report:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = REPORT_DIR / f"live_vulhub_metasploit_{stamp}.json"
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary": summary,
            "results": results,
        }
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        print(f"Saved report: {path}")


if __name__ == "__main__":
    main()
