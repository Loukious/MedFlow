from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx

from medflow_redteam.config_loader import ROOT
from medflow_redteam.lab_http import load_wordlist
from medflow_redteam.password_spray_agent import (
    DEFAULT_PASSWORD_WORDLISTS,
    DEFAULT_USERNAME_WORDLISTS,
)


LAB_CONFIG = ROOT / "config" / "web_training_labs.json"
RUNTIME_ROOT = ROOT / "data" / "labs" / "runtime" / "identity_training_lab"
STATE_PATH = RUNTIME_ROOT / "state.json"
SOCKET_PATH = RUNTIME_ROOT / "juice_shop.sock"
LOG_PATH = RUNTIME_ROOT / "relay.log"
DEFAULT_HOST_PORT = 3000
SYNTHETIC_DOMAIN = "medflow-agent.test"


def run(command: list[str], *, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def require_root_and_tools() -> None:
    if os.geteuid() != 0:
        raise SystemExit(
            "Run this helper with sudo; Docker and network-namespace access are required."
        )
    missing = [
        command
        for command in ("docker", "nsenter", "socat")
        if not shutil.which(command)
    ]
    if missing:
        raise SystemExit(
            "Missing required command(s): "
            + ", ".join(missing)
            + ". Install them before starting the lab."
        )


def load_lab_config() -> tuple[str, dict[str, Any]]:
    payload = json.loads(LAB_CONFIG.read_text(encoding="utf-8"))
    return str(payload["network"]), dict(payload["labs"]["juice_shop"])


def ensure_internal_network(network: str) -> None:
    inspected = run(
        ["docker", "network", "inspect", network, "--format", "{{.Internal}}"]
    )
    if inspected.returncode == 0:
        if inspected.stdout.strip().lower() != "true":
            raise RuntimeError(
                f"Docker network {network} exists but is not internal."
            )
        return
    created = run(["docker", "network", "create", "--internal", network])
    if created.returncode != 0:
        raise RuntimeError(created.stderr.strip() or created.stdout.strip())


def port_is_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def start_container(network: str, lab: dict[str, Any]) -> tuple[int, str]:
    container = str(lab["container"])
    existing = run(
        [
            "docker",
            "inspect",
            container,
            "--format",
            "{{.Id}}",
        ]
    )
    if existing.returncode == 0:
        removed = run(["docker", "rm", "-f", container])
        if removed.returncode != 0:
            raise RuntimeError(
                removed.stderr.strip() or removed.stdout.strip()
            )
    started = run(
        [
            "docker",
            "run",
            "-d",
            "--rm",
            "--name",
            container,
            "--network",
            network,
            "--restart",
            "no",
            str(lab["image"]),
        ],
        timeout=300,
    )
    if started.returncode != 0:
        raise RuntimeError(started.stderr.strip() or started.stdout.strip())
    inspected = run(
        [
            "docker",
            "inspect",
            container,
            "--format",
            "{{.State.Pid}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
        ]
    )
    if inspected.returncode != 0:
        raise RuntimeError(inspected.stderr.strip() or inspected.stdout.strip())
    pid_text, ip = inspected.stdout.strip().split(maxsplit=1)
    return int(pid_text), ip


def start_relay(
    *,
    namespace_pid: int,
    container_ip: str,
    internal_port: int,
    host_port: int,
) -> tuple[int, int]:
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        SOCKET_PATH.unlink()
    with LOG_PATH.open("a", encoding="utf-8") as log:
        namespace_relay = subprocess.Popen(
            [
                "nsenter",
                "-t",
                str(namespace_pid),
                "-n",
                "socat",
                f"UNIX-LISTEN:{SOCKET_PATH},fork,mode=660",
                f"TCP:{container_ip}:{internal_port}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
    wait_for_socket(SOCKET_PATH, namespace_relay, timeout=10)
    with LOG_PATH.open("a", encoding="utf-8") as log:
        host_relay = subprocess.Popen(
            [
                "socat",
                (
                    f"TCP-LISTEN:{host_port},bind=127.0.0.1,"
                    "reuseaddr,fork"
                ),
                f"UNIX-CONNECT:{SOCKET_PATH}",
            ],
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
    time.sleep(0.2)
    if host_relay.poll() is not None:
        stop_managed_process(namespace_relay.pid)
        raise RuntimeError(
            f"Loopback relay exited early; inspect {LOG_PATH}."
        )
    return namespace_relay.pid, host_relay.pid


def wait_for_socket(
    path: Path,
    process: subprocess.Popen[Any],
    *,
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            break
        time.sleep(0.1)
    stop_managed_process(process.pid)
    raise RuntimeError(f"Namespace relay did not create {path}.")


def wait_for_http(url: str, *, timeout: float = 90) -> None:
    deadline = time.monotonic() + timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            response = httpx.get(url, timeout=2, follow_redirects=False)
            if response.status_code < 500:
                return
            last_error = f"HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(1)
    raise RuntimeError(f"Juice Shop did not become ready: {last_error}")


def seed_synthetic_accounts(url: str) -> list[dict[str, Any]]:
    username_paths = [ROOT / path for path in DEFAULT_USERNAME_WORDLISTS]
    password_paths = [ROOT / path for path in DEFAULT_PASSWORD_WORDLISTS]
    usernames, _ = load_wordlist(
        username_paths,
        limit=4,
        allowed_roots=[ROOT / "data" / "wordlists"],
    )
    passwords, _ = load_wordlist(
        password_paths,
        limit=2,
        allowed_roots=[ROOT / "data" / "wordlists"],
    )
    if len(usernames) < 4 or len(passwords) < 2:
        raise RuntimeError(
            "The SecLists subset is incomplete. Run "
            "scripts/download_redteam_wordlists.py first."
        )
    fixture_password = passwords[1]
    registration_url = url.rstrip("/") + "/api/Users"
    login_url = url.rstrip("/") + "/rest/user/login"
    results = []
    with httpx.Client(timeout=5, follow_redirects=False) as client:
        # Skip SecLists' OS-oriented "root" entry for this web-login fixture.
        for username in usernames[1:4]:
            identity = f"{username}@{SYNTHETIC_DOMAIN}"
            registration = client.post(
                registration_url,
                json={
                    "email": identity,
                    "password": fixture_password,
                    "passwordRepeat": fixture_password,
                },
            )
            if registration.status_code == 201:
                status = "created"
            else:
                status = "existing_verified"
            login = client.post(
                login_url,
                json={
                    "email": identity,
                    "password": fixture_password,
                },
            )
            if login.status_code != 200:
                raise RuntimeError(
                    f"Could not create or verify {identity}: "
                    f"registration={registration.status_code}, "
                    f"login={login.status_code}"
                )
            results.append(
                {
                    "identity": identity,
                    "status": status,
                    "registration_status": registration.status_code,
                    "login_status": login.status_code,
                }
            )
    return results


def write_state(state: dict[str, Any]) -> None:
    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    temporary = STATE_PATH.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(state, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    temporary.replace(STATE_PATH)


def read_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return {}
    try:
        payload = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def managed_process_matches(pid: int) -> bool:
    command_path = Path(f"/proc/{pid}/cmdline")
    try:
        command = command_path.read_bytes().replace(b"\0", b" ").decode(
            "utf-8",
            errors="replace",
        )
    except OSError:
        return False
    return "socat" in command and str(SOCKET_PATH) in command


def stop_managed_process(pid: int) -> None:
    if pid <= 1 or not managed_process_matches(pid):
        return
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if not Path(f"/proc/{pid}").exists():
            return
        time.sleep(0.1)
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def container_running(container: str) -> bool:
    inspected = run(
        [
            "docker",
            "inspect",
            container,
            "--format",
            "{{.State.Running}}",
        ]
    )
    return (
        inspected.returncode == 0
        and inspected.stdout.strip().lower() == "true"
    )


def up(host_port: int) -> dict[str, Any]:
    require_root_and_tools()
    network, lab = load_lab_config()
    container = str(lab["container"])
    current = read_state()
    if (
        current
        and container_running(container)
        and managed_process_matches(int(current.get("namespace_relay_pid") or 0))
        and managed_process_matches(int(current.get("host_relay_pid") or 0))
    ):
        return {
            "status": "already_running",
            "url": current.get("url"),
            "container": container,
            "network": network,
            "network_internal": True,
        }
    down(quiet=True)
    if not port_is_available(host_port):
        raise RuntimeError(
            f"127.0.0.1:{host_port} is already in use."
        )
    ensure_internal_network(network)
    namespace_relay_pid = 0
    host_relay_pid = 0
    try:
        namespace_pid, container_ip = start_container(network, lab)
        namespace_relay_pid, host_relay_pid = start_relay(
            namespace_pid=namespace_pid,
            container_ip=container_ip,
            internal_port=int(lab["internal_port"]),
            host_port=host_port,
        )
        url = f"http://127.0.0.1:{host_port}/"
        wait_for_http(url)
        accounts = seed_synthetic_accounts(url)
        state = {
            "container": container,
            "container_ip": container_ip,
            "container_namespace_pid": namespace_pid,
            "host_port": host_port,
            "host_relay_pid": host_relay_pid,
            "namespace_relay_pid": namespace_relay_pid,
            "network": network,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "url": url,
        }
        write_state(state)
        return {
            "status": "started",
            "url": url,
            "container": container,
            "network": network,
            "network_internal": True,
            "internet_access": False,
            "synthetic_accounts": accounts,
        }
    except Exception:
        stop_managed_process(host_relay_pid)
        stop_managed_process(namespace_relay_pid)
        run(["docker", "stop", container])
        if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
            SOCKET_PATH.unlink()
        raise


def down(*, quiet: bool = False) -> dict[str, Any]:
    require_root_and_tools()
    _, lab = load_lab_config()
    container = str(lab["container"])
    state = read_state()
    stop_managed_process(int(state.get("host_relay_pid") or 0))
    stop_managed_process(int(state.get("namespace_relay_pid") or 0))
    stopped = run(["docker", "stop", container])
    if SOCKET_PATH.exists() or SOCKET_PATH.is_symlink():
        SOCKET_PATH.unlink()
    if STATE_PATH.exists():
        STATE_PATH.unlink()
    result = {
        "status": (
            "stopped"
            if stopped.returncode == 0 or state
            else "not_running"
        ),
        "container": container,
        "loopback_relay_stopped": True,
    }
    if not quiet:
        return result
    return result


def status() -> dict[str, Any]:
    require_root_and_tools()
    _, lab = load_lab_config()
    state = read_state()
    container = str(lab["container"])
    url = str(state.get("url") or "")
    reachable = False
    if url:
        try:
            reachable = httpx.get(url, timeout=2).status_code < 500
        except httpx.HTTPError:
            reachable = False
    return {
        "status": "running" if container_running(container) else "stopped",
        "url": url,
        "reachable": reachable,
        "host_relay_running": managed_process_matches(
            int(state.get("host_relay_pid") or 0)
        ),
        "namespace_relay_running": managed_process_matches(
            int(state.get("namespace_relay_pid") or 0)
        ),
        "network_internal": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Manage an isolated Juice Shop identity fixture exposed only on "
            "the host loopback interface."
        )
    )
    parser.add_argument("action", choices=["up", "down", "status"])
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_HOST_PORT,
        help="Host loopback port used by the campaign (default: 3000).",
    )
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535.")
    try:
        if args.action == "up":
            result = up(args.port)
        elif args.action == "down":
            result = down()
        else:
            result = status()
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                indent=2,
            )
        )
        raise SystemExit(1) from exc
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
