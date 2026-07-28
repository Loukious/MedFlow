from __future__ import annotations

import argparse
import json
import time
from dataclasses import asdict
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from medflow_graph.memory import GraphStore, ingest_campaign_report
from medflow_redteam.campaign import CampaignRun, run_campaign, save_campaign_run
from medflow_redteam.credential_reporting import collect_revealed_credentials
from medflow_redteam.password_spray_agent import (
    DEFAULT_PASSWORD_WORDLISTS as DEFAULT_SPRAY_PASSWORD_WORDLISTS,
    DEFAULT_USERNAME_WORDLISTS,
    PasswordSprayConfig,
)
from medflow_redteam.web_app import WebAuthContext
from medflow_redteam.wordlist_attack_agent import (
    DEFAULT_PASSWORD_WORDLISTS as DEFAULT_WORDLIST_PASSWORD_WORDLISTS,
    WordlistAttackConfig,
)


def parse_ports(value: str | None) -> list[int] | None:
    if not value:
        return None
    ports: set[int] = set()
    for raw_item in value.split(","):
        item = raw_item.strip()
        if not item:
            continue
        if "-" in item:
            start_text, end_text = item.split("-", 1)
            start = int(start_text)
            end = int(end_text)
            if start > end:
                raise ValueError(f"Invalid port range: {item}")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))
    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError(f"Invalid TCP port(s): {invalid[:5]}")
    return sorted(ports)


def load_auth_contexts(path: str | None) -> list[WebAuthContext]:
    if not path:
        return []
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    items = payload.get("contexts", payload) if isinstance(payload, dict) else payload
    if not isinstance(items, list):
        raise ValueError("Auth context JSON must be a list or an object with a contexts list.")
    contexts: list[WebAuthContext] = []
    for item in items:
        if not isinstance(item, dict) or not item.get("name"):
            raise ValueError("Each auth context requires a name.")
        contexts.append(
            WebAuthContext(
                name=str(item["name"]),
                headers={str(key): str(value) for key, value in (item.get("headers") or {}).items()},
                cookies={str(key): str(value) for key, value in (item.get("cookies") or {}).items()},
                owned_object_ids=[str(value) for value in (item.get("owned_object_ids") or [])],
            )
        )
    return contexts


def parse_json_object(value: str) -> dict:
    payload = json.loads(value)
    if not isinstance(payload, dict):
        raise argparse.ArgumentTypeError("Expected a JSON object.")
    return payload


def print_campaign(console: Console, run: CampaignRun, show_report: bool, show_traces: bool) -> None:
    status = "ERROR" if run.error else "OK"
    console.rule(f"MedFlow Red-Team Campaign [{status}]")
    console.print(f"Goal: [bold]{run.goal}[/bold]")
    console.print(
        f"Target: [bold]{run.target_url or run.target or 'tabletop / no live target'}[/bold]"
    )
    console.print(f"Provider: [bold]{run.provider}[/bold]")
    console.print(f"Elapsed: [bold]{run.elapsed_seconds:.2f}s[/bold]")
    if run.error:
        console.print(f"[red]{run.error}[/red]")
        return

    summary = "\n".join(
        [
            f"Agents completed: {len(run.agents)}",
            f"Services observed: {len(run.services)}",
            f"Web routes found: {web_route_label(run)}",
            f"Authorization assessment: {authorization_label(run)}",
            f"Authentication discovery: {authentication_discovery_label(run)}",
            f"Password wordlist: {wordlist_label(run)}",
            f"Password spray: {password_spray_label(run)}",
            f"Graph memory hits: {len((run.graph_memory or {}).get('hits', []))}",
            f"Normalized evidence: {len(run.normalized_evidence)}",
            f"Loop stop: {(run.loop_summary or {}).get('stop_reason', 'not enabled')}",
            f"Capability validation: {validation_label(run)}",
            f"Retrieved sources: {len(run.sources)}",
            f"Safety review: {run.safety_review[:180] if run.safety_review else 'not run'}",
        ]
    )
    console.print(Panel(summary, title="Campaign Summary"))

    credentials = collect_revealed_credentials(
        run.wordlist_attack,
        run.password_spray,
    )
    if credentials:
        console.print(
            "[bold red]Sensitive lab output:[/bold red] accepted plaintext "
            "credentials were retained by explicit request."
        )
        credential_table = Table(
            "Attack",
            "Identity",
            "Password",
            "Endpoint",
        )
        for credential in credentials:
            credential_table.add_row(
                credential["attack"],
                Text(credential["username"]),
                Text(credential["password"], style="bold yellow"),
                Text(credential["endpoint"]),
            )
        console.print(credential_table)

    agent_table = Table("Agent", "Tools", "Handoff")
    for agent in run.agents:
        agent_table.add_row(
            agent.role,
            ", ".join(agent.tools[:5]),
            agent.handoff[:220],
        )
    console.print(agent_table)

    if run.phases:
        phases = Table("Phase", "Status", "Evidence")
        for phase in run.phases:
            phases.add_row(phase.get("phase", ""), phase.get("status", ""), phase.get("evidence", "")[:220])
        console.print(phases)

    if run.services:
        services = Table("Port", "Service", "Version")
        for service in run.services:
            services.add_row(service.get("port", ""), service.get("service", ""), service.get("version", ""))
        console.print(services)

    if run.capability_validation and run.capability_validation.get("results"):
        validation_table = Table("Capability", "Status", "Evidence")
        for item in run.capability_validation["results"]:
            validation_table.add_row(
                item.get("selected_exploit_id", ""),
                item.get("status") or ("verified" if item.get("verified") else "not verified"),
                (item.get("proof_output") or item.get("reason") or "")[:260],
            )
        console.print(validation_table)

    if run.tool_timeline:
        timeline = Table("Tool", "Status", "Evidence")
        for item in run.tool_timeline[:18]:
            timeline.add_row(item.get("tool", ""), item.get("status", ""), item.get("evidence", "")[:260])
        console.print(timeline)

    if run.normalized_evidence:
        evidence_table = Table("Severity", "Status", "Asset", "Finding")
        for item in run.normalized_evidence[:18]:
            evidence_table.add_row(
                item.get("severity", ""),
                item.get("status", ""),
                item.get("asset", ""),
                item.get("title", "")[:120],
            )
        console.print(evidence_table)

    if run.web_routes and run.web_routes.get("web_routes"):
        routes_table = Table("URL", "Status", "Signal")
        interesting = [
            item for item in run.web_routes["web_routes"]
            if item.get("status") and (item.get("status") != 404 or item.get("artifact_signal"))
        ]
        for item in interesting[:12]:
            routes_table.add_row(
                item.get("url", ""),
                str(item.get("status", "")),
                item.get("artifact_signal") or item.get("title") or item.get("content_type", ""),
            )
        console.print(routes_table)

    if run.web_assessment and run.web_assessment.get("findings"):
        web_table = Table("Type", "Confidence", "Parameter", "Evidence")
        for item in run.web_assessment.get("findings", [])[:12]:
            web_table.add_row(
                item.get("type", ""),
                item.get("confidence", ""),
                item.get("parameter", ""),
                (item.get("evidence") or item.get("proof") or "")[:160],
            )
        console.print(web_table)

    if show_traces:
        traces = Table("Tool/Agent", "Input", "Output Preview")
        for trace in run.tool_traces:
            traces.add_row(trace.name, trace.input[:160], trace.output_preview[:260])
        console.print(traces)

    if show_report:
        console.print(Panel(run.report.strip() or "(empty report)", title="Campaign Report"))


def validation_label(run: CampaignRun) -> str:
    validation = run.capability_validation or {}
    if not validation:
        return "not requested"
    return f"{validation.get('successful', 0)}/{validation.get('attempted', 0)} verified"


def web_route_label(run: CampaignRun) -> str:
    routes = (run.web_routes or {}).get("web_routes", [])
    found = [item for item in routes if item.get("status") and item.get("status") != 404]
    artifact = [item for item in routes if item.get("artifact_signal")]
    return f"{len(found)} non-404, {len(artifact)} artifact signal(s)"


def authorization_label(run: CampaignRun) -> str:
    assessment = run.authorization_assessment or {}
    status = assessment.get("status", "not selected")
    posture = assessment.get("overall_security_posture")
    requests = assessment.get("http_requests", 0)
    return f"{status}, posture={posture or 'n/a'}, requests={requests}"


def authentication_discovery_label(run: CampaignRun) -> str:
    discovery = run.authentication_discovery or {}
    if not discovery:
        return "not requested"
    contract = discovery.get("contract") or {}
    return (
        f"{discovery.get('status', 'unknown')}; "
        f"endpoint={contract.get('endpoint', 'not discovered')}"
    )


def wordlist_label(run: CampaignRun) -> str:
    result = run.wordlist_attack or {}
    if not result:
        return "not requested"
    return (
        f"{result.get('successful', 0)}/{result.get('attempted', 0)} accepted; "
        f"stop={result.get('stop_reason', 'unknown')}"
    )


def password_spray_label(run: CampaignRun) -> str:
    result = run.password_spray or {}
    if not result:
        return "not requested"
    return (
        f"{result.get('successful', 0)}/{result.get('attempted', 0)} accepted; "
        f"users={result.get('unique_identities_attempted', 0)}/"
        f"{result.get('username_candidates_loaded', 0)}; "
        f"passwords={result.get('password_candidates_attempted', 0)}; "
        f"stop={result.get('stop_reason', 'unknown')}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the MedFlow multi-agent red-team campaign planner.")
    parser.add_argument("goal", help="High-level campaign goal, for example: validate hospital portal identity attack paths.")
    scope = parser.add_mutually_exclusive_group()
    scope.add_argument(
        "--target",
        default=None,
        help="Optional allowlisted IP target for network reconnaissance.",
    )
    scope.add_argument(
        "--url",
        dest="target_url",
        default=None,
        help=(
            "Explicitly authorized HTTP(S) target. The campaign orchestrator autonomously routes "
            "bounded web/API specialist work. In aggressive_lab mode, an LLM may discover a "
            "private-lab login contract when the goal explicitly requests credential testing."
        ),
    )
    parser.add_argument("--ports", default=None, help="Comma-separated ports for active reconnaissance.")
    parser.add_argument("--auth-contexts", default=None, help="JSON file containing pre-authenticated lab contexts for authorized IDOR comparison.")
    parser.add_argument(
        "--stateful-api",
        action="store_true",
        help="Run bounded OpenAPI workflow and cross-principal checks. Writes require aggressive_lab mode.",
    )
    parser.add_argument(
        "--stateful-max-requests",
        type=int,
        default=40,
        help="Maximum HTTP requests for the stateful API agent.",
    )
    parser.add_argument(
        "--stateful-max-workflows",
        type=int,
        default=8,
        help="Maximum API workflows per stateful assessment phase.",
    )
    parser.add_argument(
        "--wordlist-attack",
        action="store_true",
        help=(
            "Try a bounded SecLists password wordlist against one lab identity. "
            "Requires aggressive_lab mode."
        ),
    )
    parser.add_argument("--wordlist-username")
    parser.add_argument("--wordlist-max-passwords", type=int, default=100)
    parser.add_argument("--wordlist-max-attempts", type=int, default=100)
    parser.add_argument("--wordlist-delay", type=float, default=0.25)
    parser.add_argument(
        "--password-spray",
        action="store_true",
        help=(
            "Run bounded authentication validation against --url. Requires "
            "--execution-mode aggressive_lab and --login-endpoint."
        ),
    )
    parser.add_argument("--login-endpoint")
    parser.add_argument("--login-username-field", default="username")
    parser.add_argument("--login-password-field", default="password")
    parser.add_argument("--login-format", choices=["json", "form"], default="json")
    parser.add_argument("--login-static-fields", type=parse_json_object, default={})
    parser.add_argument("--login-header", action="append", default=[])
    parser.add_argument("--login-success-status", action="append", type=int, default=[])
    parser.add_argument("--login-failure-status", action="append", type=int, default=[])
    parser.add_argument("--username-template", default="{username}")
    parser.add_argument("--username-wordlist", action="append", type=Path)
    parser.add_argument("--password-wordlist", action="append", type=Path)
    parser.add_argument("--login-success-json-path", action="append", default=[])
    parser.add_argument("--spray-max-users", type=int, default=10)
    parser.add_argument("--spray-max-passwords", type=int, default=3)
    parser.add_argument("--spray-max-attempts", type=int, default=30)
    parser.add_argument("--spray-delay", type=float, default=0.5)
    parser.add_argument(
        "--reveal-credentials",
        action="store_true",
        help=(
            "Print accepted synthetic lab credentials and retain them in owner-only "
            "campaign JSON/Markdown artifacts. Requires a private --url and "
            "--execution-mode aggressive_lab."
        ),
    )
    parser.add_argument("--execute-recon", action="store_true", help="Let the Reconnaissance Agent run active allowlisted probes.")
    parser.add_argument("--execute-validation", action="store_true", help="Select and run matching capability validation tools after recon.")
    parser.add_argument("--max-capabilities", type=int, default=5, help="Maximum matching validation capabilities to execute.")
    parser.add_argument(
        "--execution-mode",
        choices=["safe", "aggressive_lab"],
        default="safe",
        help="Execution policy for selected validation capabilities.",
    )
    parser.add_argument(
        "--metasploit-action",
        choices=["plan", "check", "exploit"],
        default="check",
        help="Metasploit action for selected modules. exploit requires --execution-mode aggressive_lab.",
    )
    parser.add_argument("--no-llm", action="store_true", help="Use deterministic role handoffs for a fast offline demo.")
    parser.add_argument(
        "--provider",
        choices=["gpt_oss", "llama", "qwen", "local_qwen"],
        default="gpt_oss",
    )
    parser.add_argument("--results", type=int, default=5, help="Retrieved context results per query.")
    parser.add_argument("--graph-memory", default="data/graph/medflow_graph.json", help="Optional graph-memory JSON path.")
    parser.add_argument("--update-graph", action="store_true", help="Ingest the saved campaign JSON into graph memory after the run.")
    parser.add_argument("--graph-dedup", action="store_true", help="Run graph-memory dedup cleanup after --update-graph.")
    parser.add_argument("--loop", action="store_true", help="Run bounded closed-loop validation rounds after the initial pass.")
    parser.add_argument("--max-rounds", type=int, default=3, help="Maximum total validation rounds when --loop is enabled.")
    parser.add_argument("--max-tools", type=int, default=12, help="Maximum total validation tools when --loop is enabled.")
    parser.add_argument("--max-failed-rounds", type=int, default=2, help="Stop loop after this many non-finding rounds.")
    parser.add_argument("--no-stop-on-success", action="store_true", help="Continue loop even after a positive validation result.")
    parser.add_argument("--output-dir", default="reports/redteam_campaign", help="Directory for JSON and Markdown outputs.")
    parser.add_argument("--report", action="store_true", help="Print the generated campaign report.")
    parser.add_argument("--traces", action="store_true", help="Print role/tool traces.")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of rich text.")
    args = parser.parse_args()

    if (args.wordlist_attack or args.password_spray) and not args.target_url:
        parser.error("The wordlist and password-spray agents require --url.")
    if (args.wordlist_attack or args.password_spray) and not args.login_endpoint:
        parser.error(
            "--wordlist-attack and --password-spray require --login-endpoint."
        )
    if args.wordlist_attack and not args.wordlist_username:
        parser.error("--wordlist-attack requires --wordlist-username.")
    if (
        args.wordlist_attack or args.password_spray
    ) and args.execution_mode != "aggressive_lab":
        parser.error(
            "Active credential agents require --execution-mode aggressive_lab."
        )
    if args.reveal_credentials and not args.target_url:
        parser.error("--reveal-credentials requires --url.")
    if args.reveal_credentials and args.execution_mode != "aggressive_lab":
        parser.error(
            "--reveal-credentials requires --execution-mode aggressive_lab."
        )
    login_headers = {}
    for item in args.login_header:
        if ":" not in item:
            parser.error("--login-header values must use NAME:VALUE.")
        name, value = item.split(":", 1)
        login_headers[name.strip()] = value.strip()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    identity_trace_dir = Path(args.output_dir) / "identity_agents"
    wordlist_config = (
        WordlistAttackConfig(
            target_url=args.target_url,
            endpoint=args.login_endpoint,
            username=args.wordlist_username,
            password_wordlist_paths=(
                args.password_wordlist
                or list(DEFAULT_WORDLIST_PASSWORD_WORDLISTS)
            ),
            username_field=args.login_username_field,
            password_field=args.login_password_field,
            request_format=args.login_format,
            static_fields=args.login_static_fields,
            headers=login_headers,
            success_statuses=tuple(args.login_success_status or [200]),
            failure_statuses=tuple(
                args.login_failure_status or [400, 401, 403]
            ),
            success_json_paths=tuple(args.login_success_json_path),
            max_passwords=args.wordlist_max_passwords,
            max_attempts=args.wordlist_max_attempts,
            delay_seconds=args.wordlist_delay,
            execution_mode=args.execution_mode,
            execute=True,
            reveal_credentials=args.reveal_credentials,
            trace_path=identity_trace_dir / f"wordlist_attempts_{stamp}.jsonl",
        )
        if args.wordlist_attack
        else None
    )
    password_spray_config = (
        PasswordSprayConfig(
            target_url=args.target_url,
            endpoint=args.login_endpoint,
            username_wordlist_paths=(
                args.username_wordlist or list(DEFAULT_USERNAME_WORDLISTS)
            ),
            password_wordlist_paths=(
                args.password_wordlist
                or list(DEFAULT_SPRAY_PASSWORD_WORDLISTS)
            ),
            username_template=args.username_template,
            username_field=args.login_username_field,
            password_field=args.login_password_field,
            request_format=args.login_format,
            static_fields=args.login_static_fields,
            headers=login_headers,
            success_statuses=tuple(args.login_success_status or [200]),
            failure_statuses=tuple(
                args.login_failure_status or [400, 401, 403]
            ),
            success_json_paths=tuple(args.login_success_json_path),
            max_users=args.spray_max_users,
            max_passwords=args.spray_max_passwords,
            max_attempts=args.spray_max_attempts,
            delay_seconds=args.spray_delay,
            execution_mode=args.execution_mode,
            execute=True,
            reveal_credentials=args.reveal_credentials,
            trace_path=identity_trace_dir
            / f"password_spray_attempts_{stamp}.jsonl",
        )
        if args.password_spray
        else None
    )

    run = run_campaign(
        goal=args.goal,
        target=args.target,
        target_url=args.target_url,
        ports=parse_ports(args.ports),
        provider=args.provider,
        execute_recon=args.execute_recon,
        execute_validation=args.execute_validation or args.loop,
        max_capabilities=args.max_capabilities,
        execution_mode=args.execution_mode,
        metasploit_action=args.metasploit_action,
        use_llm=not args.no_llm,
        n_results=args.results,
        graph_memory_path=Path(args.graph_memory) if args.graph_memory else None,
        loop=args.loop,
        max_rounds=args.max_rounds,
        max_tools=args.max_tools,
        max_failed_rounds=args.max_failed_rounds,
        stop_on_success=not args.no_stop_on_success,
        web_auth_contexts=load_auth_contexts(args.auth_contexts),
        stateful_api=args.stateful_api,
        stateful_max_requests=args.stateful_max_requests,
        stateful_max_workflows=args.stateful_max_workflows,
        authorization_output_root=Path(args.output_dir) / "authorization",
        identity_output_root=identity_trace_dir,
        wordlist_attack_config=wordlist_config,
        password_spray_config=password_spray_config,
        reveal_credentials=args.reveal_credentials,
    )
    saved = save_campaign_run(run, Path(args.output_dir))
    graph_update = None
    if args.update_graph:
        graph_path = Path(args.graph_memory)
        store = GraphStore.load(graph_path)
        ingest_stats = ingest_campaign_report(store, saved["json"])
        dedup_stats = store.dream_dedup() if args.graph_dedup else {"merged": 0, "reviews_added": 0}
        store.save()
        graph_update = {
            "path": str(graph_path),
            "ingest": ingest_stats,
            "dedup": dedup_stats,
            "summary": store.summary(),
        }

    if args.json:
        data = asdict(run)
        data["saved"] = {name: str(path) for name, path in saved.items()}
        if graph_update:
            data["graph_update"] = graph_update
        print(json.dumps(data, indent=2, default=str))
        return

    console = Console()
    print_campaign(console, run, show_report=args.report, show_traces=args.traces)
    console.print(f"Saved JSON: [bold]{saved['json']}[/bold]")
    console.print(f"Saved Markdown: [bold]{saved['markdown']}[/bold]")
    if graph_update:
        console.print(f"Updated graph: [bold]{graph_update['path']}[/bold]")
        console.print(f"Graph ingest: {graph_update['ingest']}")
        console.print(f"Graph dedup: {graph_update['dedup']}")


if __name__ == "__main__":
    main()
