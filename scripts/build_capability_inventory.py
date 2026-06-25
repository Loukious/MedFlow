from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "data" / "capability_sources"
OUTPUT_DIR = ROOT / "data" / "capabilities"
OUTPUT_PATH = OUTPUT_DIR / "capability_inventory.json"

METASPLOIT_REPO = "https://github.com/rapid7/metasploit-framework.git"
NUCLEI_TEMPLATES_REPO = "https://github.com/projectdiscovery/nuclei-templates.git"
NMAP_SCRIPTS_DIR = Path("/usr/share/nmap/scripts")


def run(command: list[str], cwd: Path | None = None, timeout: int = 900) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, text=True, capture_output=True, timeout=timeout, check=False)


def ensure_repo(url: str, path: Path, refresh: bool = False) -> dict[str, Any]:
    if path.exists() and refresh:
        proc = run(["git", "-C", str(path), "pull", "--ff-only"], timeout=900)
        return {"path": str(path), "updated": proc.returncode == 0, "stdout": proc.stdout[-1000:], "stderr": proc.stderr[-1000:]}
    if path.exists():
        return {"path": str(path), "updated": False, "reason": "already exists"}
    path.parent.mkdir(parents=True, exist_ok=True)
    proc = run(["git", "clone", "--depth", "1", url, str(path)], timeout=1800)
    return {"path": str(path), "cloned": proc.returncode == 0, "stdout": proc.stdout[-1000:], "stderr": proc.stderr[-1000:]}


def extract_ruby_string(text: str, key: str) -> str:
    pattern = rf"['\"]{re.escape(key)}['\"]\s*=>\s*['\"]([^'\"]+)['\"]"
    match = re.search(pattern, text)
    return match.group(1).strip() if match else ""


def extract_ruby_array(text: str, key: str) -> list[str]:
    pattern = rf"['\"]{re.escape(key)}['\"]\s*=>\s*\[(.*?)\]"
    match = re.search(pattern, text, flags=re.DOTALL)
    if not match:
        return []
    return sorted(set(re.findall(r"['\"]([^'\"]+)['\"]", match.group(1))))


def service_from_path_or_text(path: Path, text: str) -> str:
    lowered = f"{path.as_posix()} {text[:2000]}".lower()
    for service in ["ftp", "ssh", "smb", "mysql", "irc", "http", "smtp", "telnet", "postgres"]:
        if service in lowered:
            return "netbios-ssn" if service == "smb" else service
    return ""


DEFAULT_PORTS_BY_SERVICE = {
    "ftp": ["21"],
    "ssh": ["22"],
    "http": ["80", "8080", "8180"],
    "https": ["443", "8443"],
    "mysql": ["3306"],
    "irc": ["6667"],
    "netbios-ssn": ["139", "445"],
    "smb": ["139", "445"],
}


def ports_from_text(text: str) -> list[str]:
    ports = set()
    for match in re.finditer(r"(?:RPORT|DefaultOptions.*?RPORT)['\"]?\s*(?:=>|=)\s*['\"]?(\d+)", text, flags=re.DOTALL):
        ports.add(match.group(1))
    return sorted(ports)


def metasploit_capabilities(repo: Path, limit: int | None = None) -> list[dict[str, Any]]:
    modules_dir = repo / "modules"
    capabilities = []
    files = list(modules_dir.glob("**/*.rb")) if modules_dir.exists() else []
    for path in files[: limit or None]:
        rel = path.relative_to(repo)
        text = path.read_text(encoding="utf-8", errors="ignore")
        cves = extract_ruby_array(text, "References")
        cves = [item for item in cves if item.upper().startswith("CVE-")]
        name = extract_ruby_string(text, "Name") or path.stem.replace("_", " ")
        description = extract_ruby_string(text, "Description")
        service = service_from_path_or_text(path, text)
        ports = ports_from_text(text)
        module_dir = rel.parts[1] if len(rel.parts) > 1 else "module"
        module_type = {"exploits": "exploit", "auxiliary": "auxiliary"}.get(module_dir, module_dir.rstrip("s"))
        module_parts = list(rel.with_suffix("").parts)
        if module_parts and module_parts[0] == "modules":
            module_parts = module_parts[1:]
        if module_parts:
            module_parts[0] = {"exploits": "exploit"}.get(module_parts[0], module_parts[0])
        module_path = "/".join(module_parts)
        unsafe_terms = {
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
        lowered_path = module_path.lower()
        safe_to_execute = (
            module_type == "auxiliary"
            and any(word in lowered_path for word in ["scanner", "version", "enum"])
            and not any(term in lowered_path for term in unsafe_terms)
        )
        if not ports and service in DEFAULT_PORTS_BY_SERVICE:
            ports = DEFAULT_PORTS_BY_SERVICE[service]
        capabilities.append(
            {
                "id": f"metasploit:{module_path}",
                "name": name,
                "provider": "metasploit",
                "runner": "metasploit_module",
                "execution": "metadata_only" if not safe_to_execute else "external_tool_optional",
                "safe_to_execute": safe_to_execute,
                "module_path": module_path,
                "module_type": module_type,
                "risk": "external framework module metadata",
                "description": description[:500],
                "cves": cves,
                "match": {
                    "service": service,
                    "ports": ports,
                    "product_keywords": [word for word in [service, path.stem.split("_")[0]] if word],
                },
            }
        )
    return capabilities


def parse_yaml_scalar(text: str, key: str) -> str:
    match = re.search(rf"^\s*{re.escape(key)}:\s*(.+?)\s*$", text, flags=re.MULTILINE)
    if not match:
        return ""
    return match.group(1).strip().strip("'\"")


def parse_yaml_list(text: str, key: str) -> list[str]:
    block = re.search(rf"^\s*{re.escape(key)}:\s*\n((?:\s+-\s+.+\n)+)", text, flags=re.MULTILINE)
    if not block:
        inline = re.search(rf"^\s*{re.escape(key)}:\s*\[(.*?)\]", text, flags=re.MULTILINE)
        if inline:
            return [item.strip().strip("'\"") for item in inline.group(1).split(",") if item.strip()]
        scalar = parse_yaml_scalar(text, key)
        if scalar:
            return [item.strip().strip("'\"") for item in scalar.split(",") if item.strip()]
        return []
    return [item.strip().removeprefix("-").strip().strip("'\"") for item in block.group(1).splitlines()]


def nuclei_capabilities(repo: Path, limit: int | None = None) -> list[dict[str, Any]]:
    capabilities = []
    files = list(repo.glob("**/*.yaml")) + list(repo.glob("**/*.yml")) if repo.exists() else []
    for path in files[: limit or None]:
        rel = path.relative_to(repo)
        if rel.parts and rel.parts[0] == "code":
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        template_id = parse_yaml_scalar(text, "id") or rel.with_suffix("").as_posix()
        name = parse_yaml_scalar(text, "name") or template_id
        severity = parse_yaml_scalar(text, "severity")
        tags = parse_yaml_list(text, "tags")
        cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)))
        service = "http" if "/http/" in f"/{rel.as_posix()}" or "http:" in text else service_from_path_or_text(path, text)
        ports = ["80", "443", "8080", "8443", "8180"] if service == "http" else DEFAULT_PORTS_BY_SERVICE.get(service, [])
        unsafe_terms = {
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
        lowered = f"{rel.as_posix()} {name} {' '.join(tags)}".lower()
        capabilities.append(
            {
                "id": f"nuclei:{template_id}",
                "name": name,
                "provider": "nuclei",
                "runner": "nuclei_template",
                "execution": "external_tool_optional",
                "safe_to_execute": severity.lower() not in {"critical"} and not any(term in lowered for term in unsafe_terms),
                "template_path": rel.as_posix(),
                "risk": f"nuclei template severity={severity or 'unknown'}",
                "cves": cves,
                "tags": tags,
                "match": {
                    "service": service,
                    "ports": ports,
                    "product_keywords": tags[:8],
                },
            }
        )
    return capabilities


def nmap_capabilities(scripts_dir: Path = NMAP_SCRIPTS_DIR) -> list[dict[str, Any]]:
    capabilities = []
    for path in sorted(scripts_dir.glob("*.nse")) if scripts_dir.exists() else []:
        text = path.read_text(encoding="utf-8", errors="ignore")
        categories_match = re.search(r"categories\s*=\s*\{(.*?)\}", text, flags=re.DOTALL)
        categories = re.findall(r"['\"]([^'\"]+)['\"]", categories_match.group(1)) if categories_match else []
        portrule_text = " ".join(re.findall(r"shortport\.port_or_service\((.*?)\)", text, flags=re.DOTALL))
        services = re.findall(r"['\"]([a-zA-Z0-9_-]+)['\"]", portrule_text)
        inferred_service = services[0] if len(services) == 1 else service_from_path_or_text(path, text)
        if inferred_service == "smb":
            inferred_service = "netbios-ssn"
        ports = re.findall(r"\b(\d{2,5})\b", portrule_text)
        if not ports and inferred_service in DEFAULT_PORTS_BY_SERVICE:
            ports = DEFAULT_PORTS_BY_SERVICE[inferred_service]
        unsafe_name_terms = {"brute", "dump", "hash", "pass", "passwd", "password", "dos"}
        unsafe_by_name = any(term in path.stem.lower() for term in unsafe_name_terms)
        unsafe_by_category = bool({"brute", "dos", "exploit", "intrusive"} & {item.lower() for item in categories})
        safe_to_execute = ("safe" in categories or "default" in categories) and not unsafe_by_name and not unsafe_by_category
        capabilities.append(
            {
                "id": f"nmap_nse:{path.stem}",
                "name": path.stem,
                "provider": "nmap_nse",
                "runner": "nmap_nse_script",
                "execution": "external_tool_optional",
                "safe_to_execute": safe_to_execute,
                "script_name": path.name,
                "risk": f"nmap categories={','.join(categories)}",
                "categories": categories,
                "match": {
                    "service": inferred_service,
                    "ports": sorted(set(ports)),
                    "product_keywords": sorted(set([*services[:8], inferred_service, *path.stem.split("-")]))[:12],
                },
            }
        )
    return capabilities


def main() -> None:
    parser = argparse.ArgumentParser(description="Build MedFlow red-team capability inventory.")
    parser.add_argument("--refresh", action="store_true", help="Pull existing repos or clone missing repos.")
    parser.add_argument("--skip-network", action="store_true", help="Only use already available local sources.")
    parser.add_argument("--limit", type=int, default=None, help="Limit modules/templates per external provider for quick tests.")
    args = parser.parse_args()

    SOURCE_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    source_status: dict[str, Any] = {}
    metasploit_dir = SOURCE_DIR / "metasploit-framework"
    nuclei_dir = SOURCE_DIR / "nuclei-templates"
    if not args.skip_network:
        source_status["metasploit"] = ensure_repo(METASPLOIT_REPO, metasploit_dir, refresh=args.refresh)
        source_status["nuclei"] = ensure_repo(NUCLEI_TEMPLATES_REPO, nuclei_dir, refresh=args.refresh)
    else:
        source_status["metasploit"] = {"path": str(metasploit_dir), "available": metasploit_dir.exists()}
        source_status["nuclei"] = {"path": str(nuclei_dir), "available": nuclei_dir.exists()}

    capabilities = []
    capabilities.extend(metasploit_capabilities(metasploit_dir, limit=args.limit))
    capabilities.extend(nuclei_capabilities(nuclei_dir, limit=args.limit))
    capabilities.extend(nmap_capabilities())

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "sources": source_status,
        "counts": {
            "total": len(capabilities),
            "metasploit": sum(1 for item in capabilities if item.get("provider") == "metasploit"),
            "nuclei": sum(1 for item in capabilities if item.get("provider") == "nuclei"),
            "nmap_nse": sum(1 for item in capabilities if item.get("provider") == "nmap_nse"),
        },
        "capabilities": capabilities,
    }
    OUTPUT_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps({"output": str(OUTPUT_PATH), "counts": payload["counts"], "sources": source_status}, indent=2))


if __name__ == "__main__":
    main()
