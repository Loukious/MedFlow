import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def web_technology_signals(headers: dict, body: str) -> list[str]:
    text = f"{headers.get('server', '')} {headers.get('x-powered-by', '')} {body[:4000]}".lower()
    checks = {
        "gunicorn": "gunicorn",
        "flask": "flask",
        "django": "django",
        "express": "express",
        "php": "php",
        "thinkphp": "thinkphp",
        "spring": "spring",
        "spring cloud": "spring cloud",
        "functionrouter": "functionrouter",
        "whitelabel": "whitelabel error page",
        "activemq": "activemq",
        "openwire": "openwire",
        "wordpress": "wp-content",
        "jquery": "jquery",
        "bootstrap": "bootstrap",
    }
    return sorted({name for name, marker in checks.items() if marker in text})


def shiro_cookie_signal(url: str) -> bool:
    try:
        request = Request(
            url,
            headers={
                "User-Agent": "MedFlow-Generated-Tool/0.1",
                "Cookie": "rememberMe=medflow_probe",
            },
        )
        with urlopen(request, timeout=4) as response:
            return "rememberme=deleteme" in response.headers.get("Set-Cookie", "").lower()
    except Exception:
        return False


def run(context: dict) -> dict:
    target = context["target"]
    ports = [int(port) for port in context.get("ports", [])]
    fingerprints = []
    for port in ports:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{target}:{port}/"
        started = time.perf_counter()
        try:
            request = Request(url, headers={"User-Agent": "MedFlow-Generated-Tool/0.1"})
            with urlopen(request, timeout=4) as response:
                body = response.read(8192).decode("utf-8", errors="replace")
                headers = {key.lower(): value for key, value in response.headers.items()}
                technology_signals = web_technology_signals(headers, body)
                if shiro_cookie_signal(url):
                    technology_signals = sorted({*technology_signals, "shiro"})
                fingerprints.append(
                    {
                        "url": url,
                        "status": response.status,
                        "server": headers.get("server", ""),
                        "powered_by": headers.get("x-powered-by", ""),
                        "set_cookie_present": bool(headers.get("set-cookie")),
                        "security_headers": {
                            "content_security_policy": bool(headers.get("content-security-policy")),
                            "strict_transport_security": bool(headers.get("strict-transport-security")),
                            "x_frame_options": bool(headers.get("x-frame-options")),
                            "x_content_type_options": bool(headers.get("x-content-type-options")),
                        },
                        "technology_signals": technology_signals,
                        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                    }
                )
        except HTTPError as exc:
            body = exc.read(8192).decode("utf-8", errors="replace")
            headers = {key.lower(): value for key, value in exc.headers.items()}
            technology_signals = web_technology_signals(headers, body)
            if shiro_cookie_signal(url):
                technology_signals = sorted({*technology_signals, "shiro"})
            fingerprints.append(
                {
                    "url": url,
                    "status": exc.code,
                    "server": headers.get("server", ""),
                    "powered_by": headers.get("x-powered-by", ""),
                    "set_cookie_present": bool(headers.get("set-cookie")),
                    "security_headers": {
                        "content_security_policy": bool(headers.get("content-security-policy")),
                        "strict_transport_security": bool(headers.get("strict-transport-security")),
                        "x_frame_options": bool(headers.get("x-frame-options")),
                        "x_content_type_options": bool(headers.get("x-content-type-options")),
                    },
                    "technology_signals": technology_signals,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                    "http_error": True,
                }
            )
        except Exception as exc:
            error_text = str(exc)
            technology_signals = web_technology_signals({}, error_text)
            fingerprints.append(
                {
                    "url": url,
                    "error": error_text,
                    "technology_signals": technology_signals,
                    "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                }
            )
    return {"allowed": True, "verified": True, "exploited": False, "web_fingerprints": fingerprints}
