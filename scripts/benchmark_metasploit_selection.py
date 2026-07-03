from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from medflow_redteam.capabilities import select_capabilities_for_services
from medflow_redteam.config_loader import ROOT


DEFAULT_MANIFEST = ROOT / "config" / "benchmarks" / "vulhub_metasploit_selection.json"
REPORT_DIR = ROOT / "reports" / "benchmarks"


def load_manifest(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def module_id(module_path: str) -> str:
    return f"metasploit:{module_path}"


def service_for_mode(lab: dict[str, Any], mode: str) -> dict[str, Any]:
    service = dict(lab["service"])
    if mode in {"cve", "both"}:
        service["cves"] = lab.get("cves", [])
    return service


def rank_for_expected(candidates: list[dict[str, Any]], expected_modules: list[str]) -> int | None:
    expected_ids = {module_id(path) for path in expected_modules}
    for index, candidate in enumerate(candidates, start=1):
        if candidate.get("id") in expected_ids:
            return index
    return None


def selected_modules(candidates: list[dict[str, Any]], limit: int = 5) -> list[str]:
    modules = []
    for candidate in candidates[:limit]:
        if candidate.get("provider") == "metasploit":
            modules.append(str(candidate.get("module_path") or candidate.get("id")))
        else:
            modules.append(str(candidate.get("id")))
    return modules


def run_one(lab: dict[str, Any], mode: str, top_k: int) -> dict[str, Any]:
    selection = select_capabilities_for_services(
        "benchmark.local",
        [service_for_mode(lab, mode)],
        limit=top_k,
    )
    candidates = [
        item
        for item in selection.get("candidates", [])
        if item.get("provider") == "metasploit"
    ]
    rank = rank_for_expected(candidates, lab.get("expected_metasploit_modules", []))
    return {
        "name": lab["name"],
        "vulhub_path": lab["vulhub_path"],
        "mode": mode,
        "expected_modules": lab.get("expected_metasploit_modules", []),
        "rank": rank,
        "hit_top_1": rank is not None and rank <= 1,
        "hit_top_3": rank is not None and rank <= 3,
        "hit_top_5": rank is not None and rank <= 5,
        "top_modules": selected_modules(candidates, limit=top_k),
        "top_reasons": [
            {
                "module": item.get("module_path"),
                "score": item.get("score"),
                "reasons": item.get("reasons", []),
            }
            for item in candidates[: min(top_k, 5)]
        ],
    }


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    return {
        "total": total,
        "top_1": sum(1 for item in results if item["hit_top_1"]),
        "top_3": sum(1 for item in results if item["hit_top_3"]),
        "top_5": sum(1 for item in results if item["hit_top_5"]),
        "misses": [item["name"] for item in results if not item["hit_top_5"]],
    }


def print_results(results: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    console = Console()
    table = Table(title="Metasploit Selection Benchmark")
    table.add_column("Lab")
    table.add_column("Mode")
    table.add_column("Rank")
    table.add_column("Expected")
    table.add_column("Top Modules")
    for item in results:
        table.add_row(
            item["name"],
            item["mode"],
            str(item["rank"] or "miss"),
            "\n".join(item["expected_modules"]),
            "\n".join(item["top_modules"][:3]),
        )
    console.print(table)
    console.print(
        json.dumps(
            {
                "total": summary["total"],
                "top_1": summary["top_1"],
                "top_3": summary["top_3"],
                "top_5": summary["top_5"],
                "misses": summary["misses"],
            },
            indent=2,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Vulhub-to-Metasploit module selection.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--mode", choices=["service", "cve", "both"], default="both")
    parser.add_argument("--top-k", type=int, default=10)
    parser.add_argument("--save-report", action="store_true")
    args = parser.parse_args()

    manifest = load_manifest(args.manifest)
    modes = ["service", "cve"] if args.mode == "both" else [args.mode]
    results = []
    for mode in modes:
        for lab in manifest["labs"]:
            results.append(run_one(lab, mode=mode, top_k=args.top_k))
    summary = summarize(results)
    print_results(results, summary)

    if args.save_report:
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = REPORT_DIR / f"metasploit_selection_{stamp}.json"
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "manifest": str(args.manifest),
            "mode": args.mode,
            "summary": summary,
            "results": results,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Saved report: {path}")


if __name__ == "__main__":
    main()
