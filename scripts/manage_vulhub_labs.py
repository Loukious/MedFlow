from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from medflow_redteam.config_loader import ROOT


CONFIG_PATH = ROOT / "config" / "vulhub_labs.json"


def load_config() -> dict[str, Any]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def selected_labs(config: dict[str, Any], names: list[str]) -> dict[str, dict[str, Any]]:
    labs = config["labs"]
    if not names or names == ["all"]:
        return labs
    missing = [name for name in names if name not in labs]
    if missing:
        raise SystemExit(f"Unknown lab(s): {', '.join(missing)}. Known labs: {', '.join(sorted(labs))}")
    return {name: labs[name] for name in names}


def run_command(command: list[str], cwd: Path | None = None, use_sudo: bool = False, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    full_command = ["sudo", *command] if use_sudo else command
    return subprocess.run(full_command, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)


def compose_command(lab: dict[str, Any], override_path: Path, *args: str) -> list[str]:
    return [
        "docker-compose",
        "-p",
        lab["project"],
        "-f",
        "docker-compose.yml",
        "-f",
        str(override_path),
        *args,
    ]


def write_override(lab_name: str, lab: dict[str, Any]) -> Path:
    services = lab.get("services") or ["web"]
    lines = ["services:"]
    for service in services:
        lines.extend(
            [
                f"  {service}:",
                "    ports: []",
                "    restart: unless-stopped",
                "    networks:",
                "      - medflow_vulhub_internal",
            ]
        )
    lines.extend(
        [
            "networks:",
            "  medflow_vulhub_internal:",
            f"    name: {lab['project']}_internal",
            "    internal: true",
        ]
    )
    path = Path(tempfile.gettempdir()) / f"{lab['project']}.override.yml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def lab_path(lab: dict[str, Any]) -> Path:
    return ROOT / lab["path"]


def up_labs(labs: dict[str, dict[str, Any]], use_sudo: bool, pull: bool) -> None:
    for name, lab in labs.items():
        override = write_override(name, lab)
        cwd = lab_path(lab)
        if pull:
            pull_result = run_command(compose_command(lab, override, "pull"), cwd=cwd, use_sudo=use_sudo)
            print_result(name, "pull", pull_result)
            if pull_result.returncode != 0:
                continue
        result = run_command(compose_command(lab, override, "up", "-d", "--remove-orphans"), cwd=cwd, use_sudo=use_sudo)
        print_result(name, "up", result)


def down_labs(labs: dict[str, dict[str, Any]], use_sudo: bool) -> None:
    for name, lab in labs.items():
        override = write_override(name, lab)
        result = run_command(compose_command(lab, override, "down"), cwd=lab_path(lab), use_sudo=use_sudo)
        print_result(name, "down", result)


def status_labs(labs: dict[str, dict[str, Any]], use_sudo: bool) -> dict[str, list[dict[str, Any]]]:
    status: dict[str, list[dict[str, Any]]] = {}
    for name, lab in labs.items():
        result = run_command(["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={lab['project']}", "--format", "{{json .}}"], use_sudo=use_sudo)
        containers = []
        for line in result.stdout.splitlines():
            if line.strip():
                containers.append(json.loads(line))
        for container in containers:
            inspect = run_command(["docker", "inspect", container["ID"], "--format", "{{json .NetworkSettings.Networks}}"], use_sudo=use_sudo)
            if inspect.returncode == 0 and inspect.stdout.strip():
                networks = json.loads(inspect.stdout)
                container["IPs"] = [value.get("IPAddress") for value in networks.values() if value.get("IPAddress")]
        status[name] = containers
    return status


def print_status(status: dict[str, list[dict[str, Any]]]) -> None:
    for name, containers in status.items():
        print(f"\n{name}")
        if not containers:
            print("  not running")
            continue
        for container in containers:
            ips = ", ".join(container.get("IPs") or [])
            print(f"  {container.get('Names')} {container.get('State')} {container.get('Status')} ip={ips}")


def test_labs(labs: dict[str, dict[str, Any]], use_sudo: bool, no_llm: bool, max_capabilities: int) -> None:
    status = status_labs(labs, use_sudo=use_sudo)
    for name, containers in status.items():
        ips = [ip for container in containers for ip in container.get("IPs", [])]
        if not ips:
            print(f"\n{name}: no running container IP found; skipping")
            continue
        target = ips[0]
        lab = labs[name]
        ports = ",".join(str(port) for port in lab.get("ports", []))
        command = [
            str(ROOT / ".venv" / "bin" / "python"),
            str(ROOT / "scripts" / "run_redteam_campaign.py"),
            lab.get("goal", f"Assess authorized Vulhub lab {name}"),
            "--target",
            target,
            "--ports",
            ports,
            "--execute-validation",
            "--max-capabilities",
            str(max_capabilities),
            "--execution-mode",
            "safe",
            "--report",
        ]
        if no_llm:
            command.append("--no-llm")
        print(f"\n{name}: running campaign against {target}:{ports}")
        result = run_command(command, cwd=ROOT, use_sudo=False, timeout=1200)
        print(result.stdout)
        if result.stderr.strip():
            print(result.stderr)


def print_result(name: str, action: str, result: subprocess.CompletedProcess[str]) -> None:
    status = "ok" if result.returncode == 0 else f"failed:{result.returncode}"
    print(f"\n{name} {action}: {status}")
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage selected Vulhub labs for MedFlow testing.")
    parser.add_argument("action", choices=["up", "down", "status", "test"])
    parser.add_argument("labs", nargs="*", default=["all"], help="Lab names from config/vulhub_labs.json, or all.")
    parser.add_argument("--pull", action="store_true", help="Pull images before starting labs.")
    parser.add_argument("--use-sudo", action="store_true", help="Run Docker/Docker Compose commands through sudo.")
    parser.add_argument("--llm", action="store_true", help="Use configured LLM during campaign tests.")
    parser.add_argument("--max-capabilities", type=int, default=5)
    args = parser.parse_args()

    config = load_config()
    labs = selected_labs(config, args.labs)
    if args.action == "up":
        up_labs(labs, use_sudo=args.use_sudo, pull=args.pull)
    elif args.action == "down":
        down_labs(labs, use_sudo=args.use_sudo)
    elif args.action == "status":
        print_status(status_labs(labs, use_sudo=args.use_sudo))
    elif args.action == "test":
        test_labs(labs, use_sudo=args.use_sudo, no_llm=not args.llm, max_capabilities=args.max_capabilities)


if __name__ == "__main__":
    main()
