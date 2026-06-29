import re
import subprocess
import time


def strip_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", value)


def run(context: dict) -> dict:
    target = context["target"]
    ports = [int(port) for port in context.get("ports", [])]
    args = context.get("args") or ["-sV", "-Pn", "--script", "default,safe"]
    timeout = int(context.get("timeout") or 240)
    started = time.perf_counter()
    command = ["nmap", *args, "-p", ",".join(str(port) for port in ports), target]
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        returncode = proc.returncode
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        stderr = (stderr.strip() + f"\nTimed out after {timeout} seconds").strip()
        returncode = 124
    return {
        "allowed": True,
        "verified": returncode == 0,
        "exploited": False,
        "cleanup_verified": True,
        "tool_result": {
            "tool": "nmap",
            "command": command,
            "returncode": returncode,
            "stdout": strip_ansi(stdout.strip()),
            "stderr": strip_ansi(stderr.strip()),
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        },
    }
