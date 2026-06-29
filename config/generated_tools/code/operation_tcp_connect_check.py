import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def run(context: dict) -> dict:
    target = context["target"]
    ports = [int(port) for port in context.get("ports", [])]
    timeout = float(context.get("timeout") or 1.0)

    def check_one(port: int) -> tuple[str, dict]:
        started = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((target, port))
        return str(port), {"open": code == 0, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}

    results = {}
    workers = min(128, max(1, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check_one, port) for port in ports]
        for future in as_completed(futures):
            port, result = future.result()
            results[port] = result
    return {"allowed": True, "verified": True, "exploited": False, "tcp": results}
