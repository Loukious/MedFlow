import time
import re
from urllib.error import HTTPError
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


def technology_signals(url: str, title: str, links: list[str], body: str, status: int | None = None) -> list[str]:
    lowered_url = url.lower()
    text = " ".join([title, " ".join(links), body[:2000]]).lower()
    signals = set()
    if "struts" in text or re.search(r"\bs2-\d{3}\b", text) or (status in {200, 500} and ".action" in lowered_url):
        signals.add("struts")
        signals.add("ognl")
    if "rocketmq" in text:
        signals.add("rocketmq")
    if "activemq" in text or "openwire" in text:
        signals.add("activemq")
        signals.add("openwire")
    if "couchdb" in text or '"couchdb"' in text:
        signals.add("couchdb")
    if "thinkphp" in text:
        signals.add("thinkphp")
        signals.add("php")
    if "spring" in text or "whitelabel error page" in text or (status in {200, 500} and "functionrouter" in lowered_url):
        signals.add("spring")
        signals.add("spring cloud")
        signals.add("functionrouter")
    return sorted(signals)


def run(context: dict) -> dict:
    target = context["target"]
    ports = [int(port) for port in context.get("ports", [])]
    paths = context.get("paths") or [
        "/",
        "/index.action",
        "/login.action",
        "/hello.action",
        "/showcase.action",
        "/functionRouter",
        "/login",
        "/logout",
        "/admin",
        "/dashboard",
        "/data",
        "/data/0",
        "/data/1",
        "/download",
        "/download/0",
        "/download/1",
        "/capture",
        "/captures",
        "/pcap",
        "/api",
        "/api/v1",
        "/robots.txt",
    ]
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
                    title = title_from_html(text)
                    output.append(
                        {
                            "url": url,
                            "status": response.status,
                            "content_type": response.headers.get("Content-Type", ""),
                            "content_length": response.headers.get("Content-Length", ""),
                            "title": title,
                            "links": sorted(set(links))[:20],
                            "technology_signals": technology_signals(url, title, links, text, response.status),
                            "artifact_signal": artifact_signal(url, response.headers.get("Content-Type", ""), body),
                            "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                        }
                    )
            except HTTPError as exc:
                body = exc.read(8192)
                text = body.decode("utf-8", errors="replace")
                links = []
                if "text/html" in exc.headers.get("Content-Type", ""):
                    links = links_from_html(text)
                title = title_from_html(text)
                output.append(
                    {
                        "url": url,
                        "status": exc.code,
                        "content_type": exc.headers.get("Content-Type", ""),
                        "content_length": exc.headers.get("Content-Length", ""),
                        "title": title,
                        "links": sorted(set(links))[:20],
                        "technology_signals": technology_signals(url, title, links, text, exc.code),
                        "artifact_signal": artifact_signal(url, exc.headers.get("Content-Type", ""), body),
                        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                        "http_error": True,
                    }
                )
            except Exception as exc:
                output.append({"url": url, "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
    return {"allowed": True, "verified": True, "exploited": False, "web_routes": output}
