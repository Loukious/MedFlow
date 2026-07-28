from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx

from medflow_redteam.config_loader import ROOT


RUNTIME_ROOT = ROOT / "reports" / "identity_training_lab_runtime"
STATE_PATH = RUNTIME_ROOT / "state.json"
LOG_PATH = RUNTIME_ROOT / "server.log"
SERVER_PATH = ROOT / "scripts" / "identity_training_lab_server.py"
DEFAULT_HOST_PORT = 3000


def port_is_available(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


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
    if pid <= 1:
        return False
    command_path = Path(f"/proc/{pid}/cmdline")
    try:
        command = command_path.read_bytes().replace(b"\0", b" ").decode(
            "utf-8",
            errors="replace",
        )
    except OSError:
        return False
    return str(SERVER_PATH) in command


def stop_managed_process(pid: int) -> None:
    if not managed_process_matches(pid):
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


def fetch_health(url: str, *, timeout: float = 10) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error = ""
    health_url = url.rstrip("/") + "/health"
    while time.monotonic() < deadline:
        try:
            response = httpx.get(
                health_url,
                timeout=2,
                follow_redirects=False,
            )
            if response.status_code == 200:
                payload = response.json()
                return payload if isinstance(payload, dict) else {}
            last_error = f"HTTP {response.status_code}"
        except (httpx.HTTPError, ValueError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
        time.sleep(0.2)
    raise RuntimeError(f"Identity fixture did not become ready: {last_error}")


def up(host_port: int) -> dict[str, Any]:
    current = read_state()
    current_pid = int(current.get("pid") or 0)
    current_url = str(current.get("url") or "")
    if managed_process_matches(current_pid) and current_url:
        health = fetch_health(current_url, timeout=2)
        return {
            "status": "already_running",
            "url": current_url,
            "loopback_only": True,
            "health": health.get("status"),
            "synthetic_accounts": health.get("synthetic_accounts", []),
        }

    down(quiet=True)
    if not port_is_available(host_port):
        raise RuntimeError(f"127.0.0.1:{host_port} is already in use.")

    RUNTIME_ROOT.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as log:
        process = subprocess.Popen(
            [
                sys.executable,
                str(SERVER_PATH),
                "--host",
                "127.0.0.1",
                "--port",
                str(host_port),
            ],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
    url = f"http://127.0.0.1:{host_port}/"
    try:
        health = fetch_health(url)
    except Exception:
        stop_managed_process(process.pid)
        raise
    write_state(
        {
            "pid": process.pid,
            "port": host_port,
            "started_at": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            ),
            "url": url,
        }
    )
    return {
        "status": "started",
        "url": url,
        "pid": process.pid,
        "loopback_only": True,
        "internet_access_required": False,
        "health": health.get("status"),
        "synthetic_accounts": health.get("synthetic_accounts", []),
    }


def down(*, quiet: bool = False) -> dict[str, Any]:
    state = read_state()
    pid = int(state.get("pid") or 0)
    was_running = managed_process_matches(pid)
    stop_managed_process(pid)
    if STATE_PATH.exists():
        STATE_PATH.unlink()
    result = {
        "status": "stopped" if was_running else "not_running",
        "server_stopped": True,
    }
    return result


def status() -> dict[str, Any]:
    state = read_state()
    pid = int(state.get("pid") or 0)
    url = str(state.get("url") or "")
    running = managed_process_matches(pid)
    health: dict[str, Any] = {}
    if running and url:
        try:
            health = fetch_health(url, timeout=2)
        except RuntimeError:
            running = False
    return {
        "status": "running" if running else "stopped",
        "url": url,
        "pid": pid if running else None,
        "loopback_only": True,
        "health": health.get("status"),
        "synthetic_accounts": health.get("synthetic_accounts", []),
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Manage a loopback-only username/password identity fixture loaded "
            "from the local SecLists checkout."
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
