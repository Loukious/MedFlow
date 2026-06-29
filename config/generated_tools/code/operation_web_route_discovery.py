import time
import re
from urllib.request import Request, urlopen


def title_from_html(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", match.group(1)).strip() if match else ""


def links_from_html(body: str) -> list[str]:
    return re.findall(r"<a[^>]+href=[\"']([^\"']+)[\"']", body, flags=re.IGNORECASE)


def artifact_signal(url: str, content_type: str, body: bytes) -> str:
    lowered_url = url.lower()
    lowered_type = content_type.lower()
    pcap_magic = [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"]
    if any(body.startswith(magic) for magic in pcap_magic) or "pcap" in lowered_url:
        return "possible packet capture exposure"
    if "download" in lowered_url and ("octet-stream" in lowered_type or not lowered_type.startswith("text/html")):
        return "downloadable artifact"
    if any(term in lowered_url for term in ["backup", "config", "dump", "capture"]):
        return "sensitive path keyword"
    return ""


def run(context: dict) -> dict:
    target = context["target"]
    ports = [int(port) for port in context.get("ports", [])]
    paths = context.get("paths") or ["/", "/login", "/logout", "/admin", "/dashboard", "/data", "/data/0", "/data/1", "/download", "/download/0", "/download/1", "/capture", "/captures", "/pcap", "/api", "/api/v1", "/robots.txt"]
    output = []
    seen = set()
    for port in ports:
        scheme = "https" if port in {443, 8443} else "http"
        for path in paths:
            normalized_path = path if str(path).startswith("/") else f"/{path}"
            key = (port, normalized_path)
            if key in seen:
                continue
            seen.add(key)
            url = f"{scheme}://{target}:{port}{normalized_path}"
            started = time.perf_counter()
            try:
                request = Request(url, headers={"User-Agent": "MedFlow-Generated-Tool/0.1"})
                with urlopen(request, timeout=4) as response:
                    body = response.read(8192)
                    text = body.decode("utf-8", errors="replace")
                    links = []
                    if "text/html" in response.headers.get("Content-Type", ""):
                        links = links_from_html(text)
                    output.append(
                        {
                            "url": url,
                            "status": response.status,
                            "content_type": response.headers.get("Content-Type", ""),
                            "content_length": response.headers.get("Content-Length", ""),
                            "title": title_from_html(text),
                            "links": sorted(set(links))[:20],
                            "artifact_signal": artifact_signal(url, response.headers.get("Content-Type", ""), body),
                            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                        }
                    )
            except Exception as exc:
                output.append({"url": url, "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
    return {"allowed": True, "verified": True, "exploited": False, "web_routes": output}
