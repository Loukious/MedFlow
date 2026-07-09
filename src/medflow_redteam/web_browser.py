from __future__ import annotations

import shutil
from typing import Any
from urllib.parse import urlparse


def collect_browser_observations(urls: list[str], max_pages: int = 8) -> dict[str, Any]:
    """Render same-origin pages and collect DOM controls plus network metadata."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"available": False, "error": "Playwright is not installed.", "pages": [], "requests": []}
    if not urls:
        return {"available": True, "pages": [], "requests": []}
    origin = origin_of(urls[0])
    executable = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    pages: list[dict[str, Any]] = []
    requests: list[dict[str, str]] = []
    seen_requests: set[tuple[str, str]] = set()
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, executable_path=executable)
            context = browser.new_context()

            def route_handler(route: Any) -> None:
                if origin_of(route.request.url) == origin:
                    route.continue_()
                else:
                    route.abort()

            context.route("**/*", route_handler)
            page = context.new_page()

            def capture(request: Any) -> None:
                if origin_of(request.url) != origin:
                    return
                key = (request.method, request.url)
                if key not in seen_requests:
                    seen_requests.add(key)
                    requests.append({"url": request.url, "method": request.method, "resource_type": request.resource_type})

            page.on("request", capture)
            for url in urls[:max_pages]:
                try:
                    page.goto(url, wait_until="networkidle", timeout=8000)
                    controls = page.locator("input, textarea, select").evaluate_all(
                        "els => els.map(e => ({name:e.name || e.id || '', type:e.type || e.tagName.toLowerCase()})).filter(x => x.name)"
                    )
                    forms = page.locator("form").evaluate_all(
                        "forms => forms.map(f => ({action:f.action || location.href, method:(f.method || 'GET').toUpperCase()}))"
                    )
                    pages.append({"url": page.url, "title": page.title(), "controls": controls[:30], "forms": forms[:10]})
                except Exception as exc:
                    pages.append({"url": url, "error": str(exc)[:180], "controls": [], "forms": []})
            browser.close()
    except Exception as exc:
        return {"available": False, "error": str(exc)[:220], "pages": pages, "requests": requests}
    return {"available": True, "pages": pages, "requests": requests[:80]}


def validate_dom_xss(url: str, sentinel: str) -> dict[str, Any]:
    """Open one same-origin GET URL and verify the harmless title sentinel only."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {"verified": False, "error": "Playwright is not installed."}
    if not sentinel or len(sentinel) > 80:
        return {"verified": False, "error": "Invalid browser validation sentinel."}
    executable = shutil.which("chromium") or shutil.which("chromium-browser") or shutil.which("google-chrome")
    origin = origin_of(url)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True, executable_path=executable)
            context = browser.new_context()
            context.route("**/*", lambda route: route.continue_() if origin_of(route.request.url) == origin else route.abort())
            page = context.new_page()
            page.goto(url, wait_until="networkidle", timeout=8000)
            title = page.title()
            browser.close()
        return {"verified": sentinel in title, "title": title[:160]}
    except Exception as exc:
        return {"verified": False, "error": str(exc)[:220]}


def origin_of(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"
