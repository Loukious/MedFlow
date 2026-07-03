import time
from urllib.parse import quote
from urllib.request import Request, urlopen


def run(context: dict) -> dict:
    target = context["target"]
    capability = context["capability"]
    matched = context.get("matched_service") or {}
    port = int(matched.get("port") or (capability.get("match", {}).get("ports") or [8000])[0])
    started = time.perf_counter()
    expression = "{{233*233}}"
    expected = "54289"
    url = f"http://{target}:{port}/?name={quote(expression)}"
    result = {
        "allowed": True,
        "target": target,
        "service": "http",
        "port": port,
        "proof_goal": capability.get("proof_goal", "Validate benign SSTI arithmetic rendering."),
        "verified": False,
        "exploited": False,
        "cleanup_verified": True,
        "url": url,
    }
    try:
        request = Request(url, headers={"User-Agent": "MedFlow-Generated-Tool/0.1"})
        with urlopen(request, timeout=5) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
        result["status"] = response.status
        result["body_preview"] = body[:300]
        result["verified"] = expected in body
        if result["verified"]:
            result["proof_output"] = f"Benign SSTI expression {expression} rendered to {expected}."
        else:
            result["reason"] = "Benign SSTI arithmetic result was not observed in the response."
    except Exception as exc:
        result["reason"] = f"SSTI arithmetic probe failed: {exc}"
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result
