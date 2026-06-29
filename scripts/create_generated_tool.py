from __future__ import annotations

import argparse
import json
from pathlib import Path

from medflow_compare.shared_tools import SAFETY_BOUNDARY, call_redteam_llm
from medflow_redteam.generated_tools import save_generated_tool, tcp_banner_template
from medflow_ti.config import load_settings


def parse_json_object(text: str) -> dict:
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.strip("`")
        stripped = stripped.removeprefix("json").strip()
    start = stripped.find("{")
    end = stripped.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("No JSON object found in generated response.")
    return json.loads(stripped[start : end + 1])


def llm_generate_tool(prompt: str, provider: str) -> tuple[dict, str]:
    settings = load_settings()
    request = f"""
You are MedFlow Toolsmith, generating a cached Python validation tool for an authorized lab/purple-team system.

{SAFETY_BOUNDARY}

Generate only safe observation, parser, fingerprint, or evidence-normalization tools unless the user explicitly says this is for the local isolated lab.
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
    raw = call_redteam_llm(request, settings=settings, provider=provider)
    parsed = parse_json_object(raw)
    return parsed["spec"], parsed["code"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Create and cache generated Python tools for MedFlow.")
    parser.add_argument("--id", required=True, help="Short tool id without the generated: prefix.")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--template", choices=["tcp_banner"], default=None)
    parser.add_argument("--service", default="")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--prompt", default="", help="LLM generation prompt for a generated tool.")
    parser.add_argument("--provider", choices=["llama", "qwen"], default="llama")
    parser.add_argument("--spec", type=Path, default=None, help="Read spec JSON from file.")
    parser.add_argument("--code", type=Path, default=None, help="Read Python code from file.")
    args = parser.parse_args()

    if args.template == "tcp_banner":
        if not args.service or not args.port:
            raise SystemExit("--template tcp_banner requires --service and --port.")
        spec, code = tcp_banner_template(args.id, args.service, args.port)
    elif args.spec and args.code:
        spec = json.loads(args.spec.read_text(encoding="utf-8"))
        code = args.code.read_text(encoding="utf-8")
    elif args.prompt:
        spec, code = llm_generate_tool(args.prompt, args.provider)
    else:
        raise SystemExit("Provide --template, --spec/--code, or --prompt.")

    spec["id"] = spec.get("id") or f"generated:{args.id}"
    if not spec["id"].startswith("generated:"):
        spec["id"] = f"generated:{spec['id']}"
    spec["provider"] = "generated_python"
    spec["runner"] = "generated_python_tool"
    paths = save_generated_tool(args.id, spec, code, overwrite=args.overwrite)
    print(json.dumps({key: str(value) for key, value in paths.items()}, indent=2))


if __name__ == "__main__":
    main()
