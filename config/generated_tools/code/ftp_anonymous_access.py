from ftplib import FTP
import time


def run(context: dict) -> dict:
    target = context["target"]
    capability = context["capability"]
    port = int((capability.get("match", {}).get("ports") or [21])[0])
    started = time.perf_counter()
    result = {
        "allowed": True,
        "target": target,
        "service": "ftp",
        "port": port,
        "proof_goal": capability.get("proof_goal", "Attempt anonymous FTP login."),
        "verified": False,
        "exploited": False,
        "cleanup_verified": True,
    }
    try:
        ftp = FTP()
        ftp.connect(target, port, timeout=5)
        result["banner_preview"] = ftp.getwelcome()
        login_response = ftp.login("anonymous", "anonymous@example.com")
        result["login_response"] = login_response
        result["proof_output"] = f"Anonymous FTP login succeeded: {login_response}"
        result["verified"] = True
        ftp.quit()
    except Exception as exc:
        result["proof_output"] = ""
        result["reason"] = f"Anonymous FTP login did not succeed: {exc}"
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result
