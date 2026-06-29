import socket
import time


def run(context: dict) -> dict:
    target = context["target"]
    capability = context["capability"]
    port = int((capability.get("match", {}).get("ports") or [3306])[0])
    started = time.perf_counter()
    result = {
        "allowed": True,
        "target": target,
        "service": "mysql",
        "port": port,
        "proof_goal": capability.get("proof_goal", "Probe MySQL handshake."),
        "verified": False,
        "exploited": False,
        "cleanup_verified": True,
    }
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            sock.settimeout(3)
            banner = sock.recv(128)
        result["banner_hex_preview"] = banner[:64].hex()
        result["proof_output"] = "MySQL handshake received before authentication."
        result["verified"] = bool(banner)
    except Exception as exc:
        result["reason"] = f"MySQL handshake probe failed: {exc}"
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result
