import time
import re
from urllib.error import URLError
from urllib.request import Request, urlopen


def title_from_html(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def run(context: dict) -> dict:
    target = context["target"]
    ports = [int(port) for port in context.get("ports", [])]
    output = []
    for port in ports:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{target}:{port}/"
        started = time.perf_counter()
        try:
            request = Request(url, headers={"User-Agent": "MedFlow-Generated-Tool/0.1"})
            with urlopen(request, timeout=4) as response:
                body = response.read(4096).decode("utf-8", errors="replace")
                output.append(
                    {
                        "url": url,
                        "status": response.status,
                        "server": response.headers.get("Server", ""),
                        "title": title_from_html(body),
                        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                    }
                )
        except URLError as exc:
            output.append({"url": url, "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
        except Exception as exc:
            output.append({"url": url, "error": repr(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
    return {"allowed": True, "verified": True, "exploited": False, "http_probe": output}
