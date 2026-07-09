from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from typing import Any

from medflow_redteam.config_loader import ROOT


CONFIG_PATH = ROOT / "config" / "web_training_labs.json"


def load_config() -> dict[str, Any]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def run(command: list[str], *, use_sudo: bool = False, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        (["sudo", *command] if use_sudo else command),
        text=True,
        capture_output=True,
        check=False,
        cwd=cwd,
        timeout=1800,
    )


def selected_labs(config: dict[str, Any], names: list[str]) -> dict[str, dict[str, Any]]:
    labs = config["labs"]
    if not names or names == ["all"]:
        return labs
    missing = [name for name in names if name not in labs]
    if missing:
        raise SystemExit(f"Unknown lab(s): {', '.join(missing)}")
    return {name: labs[name] for name in names}


def ensure_network(network: str, use_sudo: bool) -> None:
    inspect = run(["docker", "network", "inspect", network], use_sudo=use_sudo)
    if inspect.returncode == 0:
        return
    created = run(["docker", "network", "create", "--internal", network], use_sudo=use_sudo)
    if created.returncode != 0:
        raise SystemExit(created.stderr or created.stdout)


def up_container(name: str, lab: dict[str, Any], network: str, use_sudo: bool, pull: bool) -> dict[str, Any]:
    if pull:
        pull_result = run(["docker", "pull", lab["image"]], use_sudo=use_sudo)
        if pull_result.returncode != 0:
            return {"name": name, "status": "pull_failed", "detail": pull_result.stderr[-500:]}
    existing = run(["docker", "ps", "-a", "--filter", f"name=^{lab['container']}$", "--format", "{{.ID}}"], use_sudo=use_sudo)
    if existing.stdout.strip():
        run(["docker", "rm", "-f", lab["container"]], use_sudo=use_sudo)
    result = run(
        [
            "docker", "run", "-d", "--rm",
            "--name", lab["container"],
            "--network", network,
            "--restart", "no",
            lab["image"],
        ],
        use_sudo=use_sudo,
    )
    return {"name": name, "status": "started" if result.returncode == 0 else "start_failed", "detail": (result.stdout or result.stderr).strip()[-500:]}


def status_container(name: str, lab: dict[str, Any], use_sudo: bool) -> dict[str, Any]:
    result = run(
        ["docker", "ps", "-a", "--filter", f"name=^{lab['container']}$", "--format", "{{json .}}"],
        use_sudo=use_sudo,
    )
    if not result.stdout.strip():
        return {"name": name, "status": "not_running"}
    container = json.loads(result.stdout.strip().splitlines()[0])
    inspect = run(["docker", "inspect", container["ID"], "--format", "{{json .NetworkSettings.Networks}}"], use_sudo=use_sudo)
    ips: list[str] = []
    if inspect.returncode == 0 and inspect.stdout.strip():
        networks = json.loads(inspect.stdout)
        ips = [value.get("IPAddress") for value in networks.values() if value.get("IPAddress")]
    return {
        "name": name,
        "status": container.get("State", "unknown"),
        "container": container.get("Names", lab["container"]),
        "ips": ips,
        "agent_target": ips[0] if ips else "",
        "port": lab.get("internal_port"),
        "coverage": lab.get("coverage", []),
    }


def prepare_crapi(lab: dict[str, Any], use_sudo: bool) -> dict[str, Any]:
    destination = ROOT / lab["local_path"]
    if destination.exists() and (destination / ".git").exists():
        result = run(["git", "pull", "--ff-only"], cwd=destination, use_sudo=use_sudo)
        status = "updated" if result.returncode == 0 else "update_failed"
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        result = run(["git", "clone", "--depth", "1", lab["repository"], str(destination)], use_sudo=use_sudo)
        status = "cloned" if result.returncode == 0 else "clone_failed"
    return {
        "name": "crapi",
        "status": status,
        "path": str(destination),
        "compose_command": f"docker compose -f {destination / lab['compose_path']} --compatibility up -d",
        "detail": (result.stdout or result.stderr).strip()[-500:],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage isolated web training labs for MedFlow.")
    parser.add_argument("action", choices=["up", "down", "status", "prepare-crapi"])
    parser.add_argument("labs", nargs="*", default=["all"])
    parser.add_argument("--pull", action="store_true")
    parser.add_argument("--use-sudo", action="store_true")
    args = parser.parse_args()

    config = load_config()
    labs = selected_labs(config, args.labs)
    results: list[dict[str, Any]] = []
    if args.action == "prepare-crapi":
        if "crapi" not in labs:
            raise SystemExit("prepare-crapi requires the crapi lab.")
        results.append(prepare_crapi(labs["crapi"], args.use_sudo))
    else:
        network = str(config["network"])
        if args.action == "up":
            ensure_network(network, args.use_sudo)
        for name, lab in labs.items():
            if lab.get("kind") != "container":
                results.append({"name": name, "status": "external_compose", "detail": "Run prepare-crapi, then its generated compose command."})
                continue
            if args.action == "up":
                results.append(up_container(name, lab, network, args.use_sudo, args.pull))
            elif args.action == "down":
                result = run(["docker", "rm", "-f", lab["container"]], use_sudo=args.use_sudo)
                results.append({"name": name, "status": "stopped" if result.returncode == 0 else "not_running"})
            else:
                results.append(status_container(name, lab, args.use_sudo))
    print(json.dumps({"results": results}, indent=2))


if __name__ == "__main__":
    main()
