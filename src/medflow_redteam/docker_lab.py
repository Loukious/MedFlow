from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .config_loader import load_lab_config


_LAB_CONFIG = load_lab_config()
_DOCKER_CONFIG = _LAB_CONFIG["docker_lab"]

IMAGE = _DOCKER_CONFIG["image"]
NETWORK = _DOCKER_CONFIG["network"]
CONTAINER = _DOCKER_CONFIG["container"]
SUBNET = _DOCKER_CONFIG["subnet"]
CONTAINER_IP = _DOCKER_CONFIG["container_ip"]
HOSTNAME = _DOCKER_CONFIG.get("hostname", "metasploitable3")
PORTS = {int(container_port): int(host_port) for container_port, host_port in _DOCKER_CONFIG["published_ports"].items()}
START_COMMAND = "; ".join(_DOCKER_CONFIG["startup_commands"])


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def run_command(command: list[str], timeout: int = 120, use_sudo: bool = False) -> CommandResult:
    full_command = ["sudo", *command] if use_sudo else command
    proc = subprocess.run(
        full_command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return CommandResult(full_command, proc.returncode, proc.stdout.strip(), proc.stderr.strip())


def docker_ok(use_sudo: bool = False) -> bool:
    result = run_command(["docker", "ps"], timeout=15, use_sudo=use_sudo)
    return result.returncode == 0


def ensure_image(use_sudo: bool = False, pull: bool = False) -> CommandResult:
    inspect = run_command(["docker", "image", "inspect", IMAGE], timeout=30, use_sudo=use_sudo)
    if inspect.returncode == 0 and not pull:
        return inspect
    return run_command(["docker", "pull", IMAGE], timeout=1800, use_sudo=use_sudo)


def ensure_network(use_sudo: bool = False) -> CommandResult:
    inspect = run_command(["docker", "network", "inspect", NETWORK], timeout=30, use_sudo=use_sudo)
    if inspect.returncode == 0:
        return inspect
    return run_command(
        ["docker", "network", "create", "--internal", "--subnet", SUBNET, NETWORK],
        timeout=60,
        use_sudo=use_sudo,
    )


def container_exists(use_sudo: bool = False) -> bool:
    result = run_command(["docker", "container", "inspect", CONTAINER], timeout=30, use_sudo=use_sudo)
    return result.returncode == 0


def container_running(use_sudo: bool = False) -> bool:
    result = run_command(
        ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
        timeout=30,
        use_sudo=use_sudo,
    )
    return result.returncode == 0 and result.stdout == "true"


def _expected_port_bindings() -> set[str]:
    return {f"{port}/tcp" for port in PORTS}


def container_has_expected_ports(use_sudo: bool = False) -> bool:
    result = run_command(
        ["docker", "inspect", "-f", "{{json .HostConfig.PortBindings}}", CONTAINER],
        timeout=30,
        use_sudo=use_sudo,
    )
    if result.returncode != 0 or not result.stdout:
        return False
    try:
        bindings = json.loads(result.stdout)
    except json.JSONDecodeError:
        return False
    return _expected_port_bindings().issubset(set(bindings))


def remove_container(use_sudo: bool = False) -> CommandResult:
    return run_command(["docker", "rm", "-f", CONTAINER], timeout=120, use_sudo=use_sudo)


def run_container(use_sudo: bool = False) -> CommandResult:
    if container_running(use_sudo=use_sudo):
        if not container_has_expected_ports(use_sudo=use_sudo):
            remove_container(use_sudo=use_sudo)
        else:
            return CommandResult(["docker", "start", CONTAINER], 0, "already running", "")
    if container_exists(use_sudo=use_sudo):
        if not container_has_expected_ports(use_sudo=use_sudo):
            remove_container(use_sudo=use_sudo)
        else:
            return run_command(["docker", "start", CONTAINER], timeout=120, use_sudo=use_sudo)
    if container_running(use_sudo=use_sudo):
        return CommandResult(["docker", "start", CONTAINER], 0, "already running", "")

    port_args: list[str] = []
    for container_port, host_port in PORTS.items():
        port_args.extend(["-p", f"127.0.0.1:{host_port}:{container_port}"])
    return run_command(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            CONTAINER,
            "--hostname",
            HOSTNAME,
            "--network",
            NETWORK,
            "--ip",
            CONTAINER_IP,
            "--restart",
            "unless-stopped",
            *port_args,
            IMAGE,
            "/bin/bash",
            "-lc",
            START_COMMAND,
        ],
        timeout=180,
        use_sudo=use_sudo,
    )


def lab_status(use_sudo: bool = False) -> dict:
    network = run_command(["docker", "network", "inspect", NETWORK], timeout=30, use_sudo=use_sudo)
    container = run_command(["docker", "container", "inspect", CONTAINER], timeout=30, use_sudo=use_sudo)
    ps = run_command(["docker", "ps", "--filter", f"name={CONTAINER}", "--format", "{{json .}}"], timeout=30, use_sudo=use_sudo)
    network_data = json.loads(network.stdout)[0] if network.returncode == 0 and network.stdout else {}
    container_data = json.loads(container.stdout)[0] if container.returncode == 0 and container.stdout else {}
    docker_error = ""
    if network.returncode != 0:
        docker_error = network.stderr
    elif container.returncode != 0:
        docker_error = container.stderr
    return {
        "image": IMAGE,
        "network": NETWORK,
        "network_internal": network_data.get("Internal"),
        "subnet": SUBNET,
        "container": CONTAINER,
        "container_ip": CONTAINER_IP,
        "running": container_data.get("State", {}).get("Running", False),
        "published_ports": {str(k): f"127.0.0.1:{v}" for k, v in PORTS.items()},
        "docker_ps": ps.stdout,
        "docker_status_available": network.returncode == 0 and container.returncode == 0,
        "docker_error": docker_error,
    }


def setup_lab(use_sudo: bool = False, pull: bool = False, recreate: bool = False) -> dict:
    recreate_result = None
    if recreate and container_exists(use_sudo=use_sudo):
        recreate_result = remove_container(use_sudo=use_sudo).__dict__
    steps = {
        "image": ensure_image(use_sudo=use_sudo, pull=pull).__dict__,
        "network": ensure_network(use_sudo=use_sudo).__dict__,
        "container": run_container(use_sudo=use_sudo).__dict__,
    }
    if recreate_result:
        steps["recreate"] = recreate_result
    return {"steps": steps, "status": lab_status(use_sudo=use_sudo)}


def stop_lab(use_sudo: bool = False) -> CommandResult:
    return run_command(["docker", "stop", CONTAINER], timeout=120, use_sudo=use_sudo)


def write_status(path: Path, use_sudo: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(lab_status(use_sudo=use_sudo), indent=2), encoding="utf-8")
