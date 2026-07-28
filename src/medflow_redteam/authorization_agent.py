from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from groq import APIStatusError, BadRequestError, Groq, RateLimitError
from openai import (
    APIStatusError as OpenAIAPIStatusError,
    BadRequestError as OpenAIBadRequestError,
    OpenAI,
    RateLimitError as OpenAIRateLimitError,
)
from pypdf import PdfReader

from medflow_ti.config import ROOT, load_settings
from medflow_ti.llm import strip_thinking


DEFAULT_OUTPUT_ROOT = ROOT / "reports" / "authorization_agent"
MAX_RESPONSE_BYTES = 32 * 1024
MODEL_RESPONSE_BODY_CHARS = 8_000
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
FORBIDDEN_REQUEST_HEADERS = {"host", "content-length", "transfer-encoding", "connection"}
SENSITIVE_HEADER_MARKERS = {"authorization", "cookie", "api-key", "apikey", "token", "secret"}
WRITE_MARKER_PATTERN = re.compile(
    r"(?i)(?:autonomous|automated|authorization|security)[ _-]?test|test[ _-]?only"
)
AUDIT_CHECKPOINT_VERSION = 6


class AuthorizationAgentError(RuntimeError):
    pass


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self,
        request: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


@dataclass(frozen=True)
class PromptDocument:
    source: Path
    text: str
    sha256: str
    allowed_origins: tuple[str, ...]
    primary_sha256: str = ""
    supplemental_sources: tuple[Path, ...] = ()
    discovery_mode: bool = False
    allowed_methods: tuple[str, ...] = ()


@dataclass
class AuthorizationRun:
    run_id: str
    run_dir: Path
    report_path: Path
    assessment_path: Path
    evidence_path: Path
    execution_log_path: Path
    console_log_path: Path
    submission_note_path: Path
    assessment: dict[str, Any]
    observations: list[dict[str, Any]]


class EventLogger:
    def __init__(self, run_dir: Path) -> None:
        self.execution_path = run_dir / "execution_log.jsonl"
        self.console_path = run_dir / "console_output.log"
        self.events: list[dict[str, Any]] = []

    def event(self, kind: str, **payload: Any) -> None:
        item = {"timestamp": utc_now(), "event": kind, **payload}
        self.events.append(item)
        with self.execution_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(item, ensure_ascii=True, default=str) + "\n")

    def status(self, message: str) -> None:
        line = f"[{datetime.now().strftime('%H:%M:%S')}] {message}"
        print(line, flush=True)
        with self.console_path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


class GenericHttpPlanTool:
    """Execute a prompt-derived HTTP plan without knowing its application semantics."""

    def __init__(
        self,
        document: PromptDocument,
        logger: EventLogger,
        *,
        request_budget: int,
    ) -> None:
        self.document = document
        self.logger = logger
        self.request_budget = max(1, min(int(request_budget), 50))
        self.target_origin = ""
        self.baseline_headers: dict[str, str] = {}
        self.mutable_headers: set[str] = set()
        self.declared_tests: dict[str, dict[str, Any]] = {}
        self.action_ids: set[str] = set()
        self.observations: list[dict[str, Any]] = []
        self.plan_batches: list[dict[str, Any]] = []

    def execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        plan = self.validate_plan(arguments)
        remaining = self.request_budget - len(self.observations)
        if len(plan["requests"]) > remaining:
            raise AuthorizationAgentError(
                f"Plan requests {len(plan['requests'])} calls but only {remaining} remain."
            )

        self.plan_batches.append(
            {
                "target_origin": plan["target_origin"],
                "baseline_header_names": sorted(plan["baseline_headers"]),
                "mutable_headers": sorted(plan["mutable_headers"]),
                "tests": plan["tests"],
                "request_action_ids": [item["action_id"] for item in plan["requests"]],
            }
        )
        results: list[dict[str, Any]] = []
        for request_plan in plan["requests"]:
            self.action_ids.add(request_plan["action_id"])
            self.logger.status(
                f"HTTP {request_plan['method']} {request_plan['path']} "
                f"({request_plan['action_id']} / {request_plan['test_id']})"
            )
            observation = self.send(request_plan)
            self.observations.append(observation)
            write_json_atomic(
                self.logger.execution_path.parent / "raw_http_evidence.json",
                self.observations,
            )
            results.append(compact_observation(observation, body_chars=600))
            status = observation["response"].get("status")
            self.logger.status(
                f"Response {status if status is not None else 'transport_error'} "
                f"after {observation['response']['elapsed_ms']} ms"
            )
            self.logger.event(
                "http_tool_result",
                action_id=observation["action_id"],
                test_id=observation["test_id"],
                objective=observation["objective"],
                request=observation["request"],
                response=observation["response"],
            )
        return {
            "accepted": True,
            "scope": {
                "target_origin": self.target_origin,
                "baseline_header_names": sorted(self.baseline_headers),
                "mutable_headers": sorted(self.mutable_headers),
            },
            "declared_tests": list(self.declared_tests.values()),
            "new_observations": results,
            "request_budget": {
                "maximum": self.request_budget,
                "used": len(self.observations),
                "remaining": self.request_budget - len(self.observations),
            },
            "instruction": (
                "Interpret every response. Compare the executed evidence against every requirement "
                "in the original prompt before deciding whether follow-up requests are needed."
            ),
        }

    def validate_plan(self, arguments: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(arguments, dict):
            raise ValueError("HTTP plan arguments must be an object.")
        target_origin = normalize_origin(str(arguments.get("target_origin") or ""))
        if target_origin not in self.document.allowed_origins:
            raise ValueError("Target origin must be an exact URL origin present in the supplied prompt.")

        baseline_headers = normalize_headers(arguments.get("baseline_headers"))
        mutable_headers = {
            str(item).strip().lower()
            for item in arguments.get("mutable_headers") or []
            if str(item).strip()
        }
        validate_prompt_headers(
            self.document.text,
            baseline_headers,
            mutable_headers,
            allow_empty=self.document.discovery_mode,
            evidence_text=self.scope_evidence_text(),
        )
        if self.target_origin:
            if target_origin != self.target_origin:
                raise ValueError("Follow-up plans cannot change target origin.")
            if self.document.discovery_mode:
                for name, value in self.baseline_headers.items():
                    if baseline_headers.get(name) != value:
                        raise ValueError(
                            "Follow-up plans cannot remove or change an established baseline header."
                        )
                if not self.mutable_headers.issubset(mutable_headers):
                    raise ValueError(
                        "Follow-up plans cannot remove established mutable headers."
                    )
            else:
                if baseline_headers != self.baseline_headers:
                    raise ValueError(
                        "Follow-up plans cannot change the supplied baseline identity."
                    )
                if mutable_headers != self.mutable_headers:
                    raise ValueError("Follow-up plans cannot change mutable headers.")

        tests = validate_declared_tests(arguments.get("tests"))
        candidate_tests = dict(self.declared_tests)
        for test in tests:
            existing = candidate_tests.get(test["test_id"])
            if existing and existing != test:
                raise ValueError(f"Follow-up plan changed declared test '{test['test_id']}'.")
            candidate_tests[test["test_id"]] = test

        requests = arguments.get("requests")
        if not isinstance(requests, list) or not requests:
            raise ValueError("The model must provide at least one HTTP request.")
        if len(requests) > 30:
            raise ValueError("One HTTP plan may contain at most 30 requests.")
        validated_requests: list[dict[str, Any]] = []
        batch_action_ids: set[str] = set()
        for item in requests:
            validated = self.validate_request(
                item,
                tests={*candidate_tests, "recon"},
                mutable_headers=mutable_headers,
            )
            if validated["action_id"] in batch_action_ids:
                raise ValueError(f"Duplicate action_id '{validated['action_id']}'.")
            batch_action_ids.add(validated["action_id"])
            validated_requests.append(validated)

        # Commit scope and test state only after the entire batch has passed validation.
        if not self.target_origin:
            self.target_origin = target_origin
        self.baseline_headers = baseline_headers
        self.mutable_headers = mutable_headers
        self.declared_tests = candidate_tests
        return {
            "target_origin": target_origin,
            "baseline_headers": baseline_headers,
            "mutable_headers": mutable_headers,
            "tests": tests,
            "requests": validated_requests,
        }

    def validate_request(
        self,
        item: Any,
        *,
        tests: set[str],
        mutable_headers: set[str],
    ) -> dict[str, Any]:
        if not isinstance(item, dict):
            raise ValueError("Each request plan must be an object.")
        action_id = str(item.get("action_id") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,100}", action_id):
            raise ValueError("Each action_id must be a safe unique label.")
        if action_id in self.action_ids:
            raise ValueError(f"Duplicate action_id '{action_id}'.")
        test_id = str(item.get("test_id") or "").strip()
        if test_id not in tests:
            raise ValueError(f"Request references undeclared test_id '{test_id}'.")
        method = str(item.get("method") or "").upper().strip()
        if method not in SAFE_METHODS | MUTATING_METHODS:
            raise ValueError(f"Unsupported HTTP method '{method}'.")
        if (
            method not in self.document.allowed_methods
            and not prompt_mentions_method(self.document.text, method)
        ):
            raise ValueError(f"HTTP method {method} is not explicitly present in the prompt.")
        path = str(item.get("path") or "").strip()
        parsed_path = urlsplit(path)
        if (
            not path.startswith("/")
            or parsed_path.scheme
            or parsed_path.netloc
            or parsed_path.fragment
            or any(part == ".." for part in parsed_path.path.split("/"))
        ):
            raise ValueError("Request path must remain relative to the prompt-derived origin.")

        overrides = normalize_headers(item.get("header_overrides") or {})
        if not set(overrides).issubset(mutable_headers):
            raise ValueError("A request may override only model-declared mutable supplied headers.")
        allowed_value_text = self.scope_evidence_text().lower()
        for value in overrides.values():
            if value.lower() not in allowed_value_text:
                raise ValueError(
                    "Header override values must be present in the prompt or prior target evidence."
                )

        body = item.get("body") or {}
        if not isinstance(body, dict):
            raise ValueError("Request body must be a JSON object.")
        if len(json.dumps(body, default=str)) > 4_096:
            raise ValueError("Request body exceeds 4 KiB.")
        if method in SAFE_METHODS and body:
            raise ValueError(f"{method} requests cannot carry a body.")
        if method in MUTATING_METHODS:
            validate_generic_test_write(body)

        return {
            "action_id": action_id,
            "test_id": test_id,
            "objective": str(item.get("objective") or "").strip()[:1_000],
            "method": method,
            "path": path,
            "header_overrides": overrides,
            "body": body,
        }

    def scope_evidence_text(self) -> str:
        parts = [self.document.text]
        if self.document.discovery_mode:
            for observation in self.observations:
                response = observation.get("response") or {}
                parts.append(str(response.get("body") or ""))
                parts.append(json.dumps(response.get("headers") or {}, default=str))
        return "\n".join(parts)

    def send(self, plan: dict[str, Any]) -> dict[str, Any]:
        url = self.target_origin.rstrip("/") + plan["path"]
        headers = {
            **self.baseline_headers,
            **plan["header_overrides"],
            "accept": "application/json",
            "user-agent": "MedFlow-GenericAuthorizationAgent/1.0",
        }
        data = None
        if plan["method"] in MUTATING_METHODS:
            headers["content-type"] = "application/json"
            data = json.dumps(plan["body"]).encode("utf-8")

        started = time.monotonic()
        status: int | None = None
        response_headers: dict[str, str] = {}
        body = ""
        transport_error = ""
        try:
            request = Request(url, data=data, headers=headers, method=plan["method"])
            with build_opener(NoRedirect()).open(request, timeout=15) as response:
                status = response.status
                response_headers = safe_response_headers(dict(response.headers.items()))
                body = response.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
        except HTTPError as exc:
            status = exc.code
            response_headers = safe_response_headers(dict(exc.headers.items()) if exc.headers else {})
            body = exc.read(MAX_RESPONSE_BYTES).decode("utf-8", errors="replace")
        except (URLError, TimeoutError, OSError) as exc:
            transport_error = f"{type(exc).__name__}: {exc}"[:500]

        return {
            "action_id": plan["action_id"],
            "test_id": plan["test_id"],
            "objective": plan["objective"],
            "request": {
                "method": plan["method"],
                "url": url,
                "path": plan["path"],
                "headers": redact_headers(headers),
                "header_overrides": redact_headers(plan["header_overrides"]),
                "body": plan["body"],
            },
            "response": {
                "status": status,
                "headers": response_headers,
                "body": body,
                "body_sha256": sha256_short(body),
                "body_bytes": len(body.encode("utf-8", errors="replace")),
                "elapsed_ms": round((time.monotonic() - started) * 1_000, 2),
                "transport_error": transport_error,
            },
        }


class GenericAuthorizationAgent:
    def __init__(
        self,
        document: PromptDocument,
        logger: EventLogger,
        *,
        request_budget: int = 30,
        max_tool_rounds: int = 3,
        provider: str = "gpt_oss",
    ) -> None:
        settings = load_settings()
        normalized_provider = provider.strip().lower().replace("-", "_")
        if normalized_provider != "local_qwen" and not settings.groq_api_key:
            raise AuthorizationAgentError("Missing GROQ_API_KEY/GroqAPIKey in .env.")
        if normalized_provider not in {"gpt_oss", "llama", "qwen", "local_qwen"}:
            raise AuthorizationAgentError(
                "Authorization agent provider must be `gpt_oss`, `llama`, `qwen`, "
                "or `local_qwen`."
            )
        self.document = document
        self.logger = logger
        self.provider = normalized_provider
        if normalized_provider == "gpt_oss":
            self.model = settings.gpt_oss_model
        elif normalized_provider == "llama":
            self.model = settings.llama_model
        elif normalized_provider == "qwen":
            self.model = settings.qwen_model
        else:
            self.model = settings.local_qwen_model
        self.supports_json_schema = normalized_provider in {"gpt_oss", "local_qwen"}
        if normalized_provider == "local_qwen":
            self.backend = "llama.cpp"
            self.api_endpoint = (
                f"{settings.local_qwen_base_url.rstrip('/')}/chat/completions"
            )
            self.client = OpenAI(
                api_key=settings.local_qwen_api_key or "local",
                base_url=settings.local_qwen_base_url,
                max_retries=0,
                timeout=300.0,
            )
        else:
            self.backend = "Groq"
            self.api_endpoint = "https://api.groq.com/openai/v1/chat/completions"
            self.client = Groq(api_key=settings.groq_api_key, max_retries=0)
        self.http_tool = GenericHttpPlanTool(
            document,
            logger,
            request_budget=request_budget,
        )
        self.max_tool_rounds = max(1, min(int(max_tool_rounds), 5))
        self.llm_calls = 0
        self.coverage_review: dict[str, Any] = {}

    def run(self) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        self.logger.status(f"Starting generic prompt-driven assessment with {self.model}")
        self.logger.event(
            "assessment_started",
            provider=self.backend,
            llm_profile=self.provider,
            model=self.model,
            prompt_source=str(self.document.source),
            prompt_sources=[
                str(self.document.source),
                *[str(path) for path in self.document.supplemental_sources],
            ],
            prompt_sha256=self.document.sha256,
            allowed_origins=self.document.allowed_origins,
            request_budget=self.http_tool.request_budget,
        )
        scenario_instruction = (
            "Treat the following as a high-level campaign objective plus an explicitly authorized "
            "target. Autonomously discover applicable routes and authorization boundaries. Do not "
            "invent credentials, identity headers, role values, or target behavior that is not in "
            "the prompt or returned by the target."
            if self.document.discovery_mode
            else (
                "Treat the following document as the complete scenario-specific prompt. Infer all "
                "targets, supplied identity headers, mutable headers, endpoints, tests, and request "
                "variants from it."
            )
        )
        messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": generic_planner_system_prompt(
                    discovery_mode=self.document.discovery_mode
                ),
            },
            {
                "role": "user",
                "content": f"{scenario_instruction}\n\n{self.document.text}",
            },
        ]
        tool_schema = execute_plan_tool_schema()
        for round_number in range(1, self.max_tool_rounds + 1):
            self.logger.status(f"LLM planning/tool round {round_number}")
            message = self.complete(
                messages,
                tools=[tool_schema],
                tool_choice="required",
                max_completion_tokens=3_500,
                purpose=f"http_plan_round_{round_number}",
            )
            assistant = message_to_dict(message)
            messages.append(assistant)
            tool_calls = assistant.get("tool_calls") or []
            if not tool_calls:
                raise AuthorizationAgentError("The model did not call the generic HTTP plan tool.")
            for tool_call in tool_calls:
                function = tool_call.get("function") or {}
                arguments: dict[str, Any] = {}
                if function.get("name") != "execute_http_plan":
                    result = {"accepted": False, "error": "Unknown tool requested."}
                else:
                    try:
                        arguments = json.loads(function.get("arguments") or "{}")
                        result = self.http_tool.execute(arguments)
                    except Exception as exc:
                        result = {
                            "accepted": False,
                            "error": f"{type(exc).__name__}: {exc}",
                        }
                        self.logger.event(
                            "http_plan_rejected",
                            error=result["error"],
                            arguments=safe_plan_for_log(arguments),
                        )
                        self.logger.status(f"HTTP plan rejected: {result['error']}")
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call["id"],
                        "name": "execute_http_plan",
                        "content": json.dumps(result, ensure_ascii=True),
                    }
                )
            if not self.http_tool.observations:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "No HTTP evidence was collected. Correct the scope/plan using only "
                            "facts from the supplied prompt and call execute_http_plan again."
                        ),
                    }
                )
                continue

            structural_gaps = self.structural_coverage_gaps()
            self.coverage_review = (
                {
                    "complete": False,
                    "covered_requirements": [],
                    "missing_requirements": structural_gaps,
                    "review_summary": (
                        "Every declared test must have at least one executed request/response "
                        "observation before semantic coverage review."
                    ),
                }
                if structural_gaps
                else self.review_coverage()
            )
            self.logger.event("coverage_review", **self.coverage_review)
            if self.coverage_review["complete"]:
                self.logger.status("Coverage reviewer found all prompt requirements represented")
                break
            self.logger.status(
                f"Coverage reviewer requested follow-up: "
                f"{'; '.join(self.coverage_review['missing_requirements'])}"
            )
            followup_scope = (
                "Preserve established baseline headers and mutable headers. You may add a header "
                "or value only when it appeared in the original prompt or prior target evidence."
                if self.document.discovery_mode
                else "Keep the same target, baseline headers, and mutable headers."
            )
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "A separate model coverage review found missing or inconclusive work. "
                        f"Call execute_http_plan with only the necessary follow-up requests. "
                        f"{followup_scope} Any previously "
                        "declared test that you re-declare must remain unchanged; add a test only "
                        "when it is required by the objective or supported target evidence.\n\n"
                        f"{json.dumps(self.coverage_review, indent=2)}"
                    ),
                }
            )
        else:
            raise AuthorizationAgentError("Maximum tool rounds reached before complete prompt coverage.")

        self.logger.status("The model is interpreting every response and generating the final report")
        assessment = self.generate_assessment()
        self.logger.event(
            "assessment_completed",
            provider=self.backend,
            model=self.model,
            llm_calls=self.llm_calls,
            http_requests=len(self.http_tool.observations),
            overall_security_posture=assessment["overall_security_posture"],
        )
        self.logger.status(
            f"Assessment complete: {assessment['overall_security_posture']} "
            f"({len(self.http_tool.observations)} HTTP requests, {self.llm_calls} LLM calls)"
        )
        return assessment, self.http_tool.observations

    def structural_coverage_gaps(self) -> list[str]:
        observed_test_ids = {
            str(item.get("test_id") or "")
            for item in self.http_tool.observations
            if item.get("test_id") != "recon"
        }
        return [
            f"Declared test '{test_id}' has no executed evidence."
            for test_id in self.http_tool.declared_tests
            if test_id != "recon" and test_id not in observed_test_ids
        ]

    def review_coverage(self) -> dict[str, Any]:
        evidence = compact_observations(
            self.http_tool.observations,
            total_body_chars=4_000,
            per_body_chars=500,
        )
        prompt = f"""
Act as an independent coverage reviewer. Compare the original assignment with the model-declared
tests and executed HTTP evidence. Decide whether every explicitly required reconnaissance step and
security test has enough request/response evidence for a final judgment. Do not judge whether the
application is vulnerable yet. Do not require tests that are absent from the assignment.
For a mutating test, an explicit server response that the write was accepted is enough to judge
acceptance; require a read-back only before claiming persistence or a particular stored field
change. Treat a schema/transport error without acceptance semantics as inconclusive coverage.

Original assignment:
{self.document.text}

Declared tests:
{json.dumps(list(self.http_tool.declared_tests.values()), indent=2)}

Executed evidence:
{json.dumps(evidence, indent=2)}
""".strip()
        message = self.complete(
            [
                {
                    "role": "system",
                    "content": (
                        "You are a strict black-box assessment coverage reviewer. Scenario-specific "
                        "requirements come only from the supplied assignment text."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            response_format=coverage_response_format(),
            max_completion_tokens=2_000,
            purpose="coverage_review",
        )
        payload = parse_json_object(strip_thinking(message.content or ""))
        if not isinstance(payload.get("complete"), bool):
            raise AuthorizationAgentError("Coverage reviewer returned an invalid complete flag.")
        return payload

    def generate_assessment(self) -> dict[str, Any]:
        declared_tests = [
            test
            for test_id, test in sorted(self.http_tool.declared_tests.items())
            if test_id != "recon"
        ]
        if not declared_tests:
            raise AuthorizationAgentError("The model did not declare any security tests.")

        baseline = [
            item for item in self.http_tool.observations if item["test_id"] == "recon"
        ]
        self.logger.status(
            f"The model is interpreting {len(baseline)} baseline responses"
        )
        interpretations = self.interpret_baseline(baseline)
        test_results: list[dict[str, Any]] = []
        for test in declared_tests:
            test_observations = [
                item
                for item in self.http_tool.observations
                if item["test_id"] == test["test_id"]
            ]
            if not test_observations:
                raise AuthorizationAgentError(
                    f"No evidence exists for declared test '{test['test_id']}'."
                )
            self.logger.status(
                f"The model is judging {test['test_id']} from "
                f"{len(test_observations)} responses"
            )
            judgment = self.judge_security_test(
                test,
                baseline=baseline,
                baseline_interpretations=interpretations,
                test_observations=test_observations,
            )
            test_results.append(judgment["test"])
            interpretations.extend(judgment["response_interpretations"])

        self.logger.status("An independent model critic is auditing all test verdicts")
        test_results, interpretations = self.audit_test_judgments(
            declared_tests=declared_tests,
            test_results=test_results,
            interpretations=interpretations,
        )
        self.logger.status("The model is synthesizing the final assessment")
        summary = self.apply_discovery_scope_guard(
            self.summarize_assessment(test_results)
        )
        assessment = {
            **summary,
            "tests": test_results,
            "response_interpretations": interpretations,
        }
        errors = validate_assessment(
            assessment,
            expected_test_ids={item["test_id"] for item in declared_tests},
            observations=self.http_tool.observations,
            allow_scope_inconclusive=bool(self.discovery_scope_limitation()),
        )
        if errors:
            raise AuthorizationAgentError(
                f"Staged model report failed consistency checks: {errors}"
            )
        return assessment

    def reaudit_assessment(
        self,
        assessment: dict[str, Any],
    ) -> dict[str, Any]:
        declared_tests = [
            test
            for test_id, test in sorted(self.http_tool.declared_tests.items())
            if test_id != "recon"
        ]
        expected_test_ids = {item["test_id"] for item in declared_tests}
        structural_errors = validate_assessment(
            assessment,
            expected_test_ids=expected_test_ids,
            observations=self.http_tool.observations,
            allow_scope_inconclusive=bool(self.discovery_scope_limitation()),
        )
        if structural_errors:
            raise AuthorizationAgentError(
                f"Existing assessment cannot be re-audited: {structural_errors}"
            )

        self.logger.status("An independent model critic is re-auditing the existing verdicts")
        test_results, interpretations = self.audit_test_judgments(
            declared_tests=declared_tests,
            test_results=assessment["tests"],
            interpretations=assessment["response_interpretations"],
        )
        self.logger.status("The model is re-synthesizing the audited assessment")
        updated = {
            **self.apply_discovery_scope_guard(
                self.summarize_assessment(test_results)
            ),
            "tests": test_results,
            "response_interpretations": interpretations,
        }
        errors = validate_assessment(
            updated,
            expected_test_ids=expected_test_ids,
            observations=self.http_tool.observations,
            allow_scope_inconclusive=bool(self.discovery_scope_limitation()),
        )
        if errors:
            raise AuthorizationAgentError(
                f"Re-audited report failed consistency checks: {errors}"
            )
        return updated

    def interpret_baseline(
        self,
        observations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not observations:
            return []
        action_ids = [item["action_id"] for item in observations]
        evidence = compact_observations(
            observations,
            total_body_chars=4_000,
            per_body_chars=1_000,
        )
        prompt = f"""
Interpret each baseline/reconnaissance HTTP response. Explain what behavior it establishes for the
supplied baseline subject. Do not assign a security-test PASS or FAIL in this stage.

Original scenario:
{self.document.text}

Baseline evidence:
{json.dumps(evidence, indent=2)}
""".strip()
        message = self.complete(
            [
                {
                    "role": "system",
                    "content": (
                        "You are a black-box authorization evidence analyst. Use only the supplied "
                        "scenario and evidence; interpret every listed action exactly once."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            response_format=interpretations_response_format(action_ids),
            max_completion_tokens=1_500,
            purpose="baseline_interpretation",
        )
        payload = parse_json_object(strip_thinking(message.content or ""))
        interpretations = payload.get("response_interpretations")
        validate_interpretation_ids(interpretations, action_ids)
        self.logger.event(
            "baseline_interpretation_result",
            response_interpretations=interpretations,
        )
        return interpretations

    def judge_security_test(
        self,
        test: dict[str, Any],
        *,
        baseline: list[dict[str, Any]],
        baseline_interpretations: list[dict[str, Any]],
        test_observations: list[dict[str, Any]],
    ) -> dict[str, Any]:
        action_ids = [item["action_id"] for item in test_observations]
        evidence = compact_observations(
            [*baseline, *test_observations],
            total_body_chars=6_000,
            per_body_chars=1_000,
        )
        prompt = f"""
Judge one model-declared authorization test and interpret each of its test actions.

Decision rules:
- The original scenario controls if planner metadata is ambiguous or conflicts with it.
- `baseline_headers` establish the supplied principal. Values under `header_overrides` are attack
  variations by that same principal, not new authentication.
- A client-controlled identity or role claim is not proof that the subject became that identity or
  role. Reference accounts, IDs, and role strings are context rather than credentials. Access
  obtained solely by changing such a claim is unauthorized unless the evidence shows distinct
  secrets, tokens, sessions, or another authentication ceremony were used.
- PASS means the authorization control resisted all unauthorized attempts in this test.
- FAIL means evidence demonstrates unauthorized disclosure, function access, write, or privileged
  access.
- INCONCLUSIVE means transport failure, invalid request shape, or ambiguous semantics prevent a
  defensible judgment.
- Planner conditions are reviewable metadata. If they invert these security meanings, judge the
  observed security behavior instead: denied unauthorized access is PASS, while a nonexistent
  route, testing mistake, or unmet functional expectation is INCONCLUSIVE rather than a
  vulnerability.
- A missing optional response header or an unavailable endpoint is not itself authorization impact.
- Route names, endpoint existence, generic errors, and public API inventory are reconnaissance
  metadata, not unauthorized disclosure by themselves. Security must not depend on hiding a route.
  FAIL only when evidence exposes protected content, secrets, private object data, restricted
  functionality, or privilege.
- Interpret response semantics, not status codes alone.
- Root-cause statements must distinguish directly observed behavior from black-box inference.
  Never claim knowledge of unseen authentication, code, storage, or validation internals; describe
  such explanations as behavior that is "consistent with" or "suggests" a likely flaw.
- A server response that explicitly says a write was accepted proves acceptance. Do not claim
  persistence or a particular field change unless response evidence or a read-back proves it.
- Use only the evidence below and provide concrete server-side remediation.

Original scenario:
{self.document.text}

Declared test metadata:
{json.dumps(test, indent=2)}

Baseline interpretations:
{json.dumps(baseline_interpretations, indent=2)}

Relevant baseline and test evidence:
{json.dumps(evidence, indent=2)}
""".strip()
        message = self.complete(
            [
                {
                    "role": "system",
                    "content": (
                        "You are a strict black-box authorization-test judge. Scenario-specific "
                        "facts come only from the supplied prompt and evidence. Endpoint names, "
                        "route existence, and public API inventory alone are reconnaissance "
                        "metadata, never proof of protected-data disclosure or authorization "
                        "failure."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            response_format=test_judgment_response_format(test["test_id"], action_ids),
            max_completion_tokens=2_000,
            purpose=f"test_judgment_{test['test_id']}",
            temperature=0.0,
        )
        payload = parse_json_object(strip_thinking(message.content or ""))
        if (payload.get("test") or {}).get("test_id") != test["test_id"]:
            raise AuthorizationAgentError(
                f"Judgment returned the wrong test ID for '{test['test_id']}'."
            )
        validate_interpretation_ids(payload.get("response_interpretations"), action_ids)
        self.logger.event(
            "test_judgment_result",
            test_id=test["test_id"],
            judgment=payload,
        )
        return payload

    def summarize_assessment(
        self,
        test_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        discovery_limitation = self.discovery_scope_limitation()
        prompt = f"""
Synthesize the final assessment summary from these model test judgments. Preserve their verdicts
and evidence references. If any test is FAIL, overall posture must be vulnerable. If no test fails
but any is INCONCLUSIVE, posture must be inconclusive; otherwise it is secure. Consolidate observed
and inferred root causes, prioritize server-side remediation, and create findings only for
evidence-supported failed tests. Describe unseen implementation causes as black-box inferences,
not established internal facts. Every claim about authentication, sessions, tokens, databases,
code, or server-side validation must explicitly say the observed behavior "is consistent with",
"suggests", or "may indicate" that cause. Do not state that an unseen control exists or is absent.
If the discovery limitation below is non-empty, the overall posture must be `inconclusive`, even
when every narrow executed test passed. A denied unauthenticated request proves only that tested
boundary; it does not prove the security of undiscovered authenticated routes or roles.

Discovery limitation:
{discovery_limitation or "none"}

Original scenario:
{self.document.text}

Coverage review:
{json.dumps(self.coverage_review, indent=2)}

Test judgments:
{json.dumps(test_results, indent=2)}
""".strip()
        message = self.complete(
            [
                {
                    "role": "system",
                    "content": (
                        "You are the final report synthesizer for a black-box authorization "
                        "assessment. Do not invent evidence or alter prior test verdicts."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            response_format=assessment_summary_response_format(
                [item["action_id"] for item in self.http_tool.observations]
            ),
            max_completion_tokens=2_000,
            purpose="assessment_summary",
        )
        summary = parse_json_object(strip_thinking(message.content or ""))
        self.logger.event("assessment_summary_result", summary=summary)
        return summary

    def discovery_scope_limitation(self) -> str:
        if not self.document.discovery_mode:
            return ""
        if self.http_tool.baseline_headers:
            return ""
        successful = [
            item
            for item in self.http_tool.observations
            if isinstance((item.get("response") or {}).get("status"), int)
            and 200 <= int(item["response"]["status"]) < 400
        ]
        if successful:
            return ""
        return (
            "No authenticated context was available and no request reached an application surface "
            "that returned a successful response. The evidence can judge the tested anonymous "
            "boundary only; authenticated routes, objects, roles, and functions remain unassessed."
        )

    def apply_discovery_scope_guard(
        self,
        summary: dict[str, Any],
    ) -> dict[str, Any]:
        limitation = self.discovery_scope_limitation()
        if not limitation:
            return summary
        guarded = {**summary}
        guarded["overall_security_posture"] = "inconclusive"
        limitations = [
            str(item)
            for item in guarded.get("limitations") or []
            if str(item).strip()
        ]
        if limitation not in limitations:
            limitations.insert(0, limitation)
        guarded["limitations"] = limitations
        scope_note = (
            "Overall scope is inconclusive because authenticated application surfaces could not "
            "be reached or evaluated. "
        )
        executive = str(guarded.get("executive_summary") or "")
        if not executive.startswith(scope_note):
            guarded["executive_summary"] = scope_note + executive
        return guarded

    def audit_test_judgments(
        self,
        *,
        declared_tests: list[dict[str, Any]],
        test_results: list[dict[str, Any]],
        interpretations: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        audited_tests = test_results
        audited_interpretations = interpretations
        completed_test_ids: set[str] = set()
        checkpoint_path = (
            self.logger.execution_path.parent / "verdict_audit_checkpoint.json"
        )
        if checkpoint_path.exists():
            try:
                checkpoint = json.loads(checkpoint_path.read_text(encoding="utf-8"))
                checkpoint_test_ids = {
                    str(item.get("test_id"))
                    for item in checkpoint.get("tests") or []
                    if isinstance(item, dict)
                }
                expected_test_ids = {item["test_id"] for item in declared_tests}
                if (
                    checkpoint.get("version") == AUDIT_CHECKPOINT_VERSION
                    and checkpoint.get("prompt_sha256") == self.document.sha256
                    and checkpoint.get("model") == self.model
                    and checkpoint_test_ids == expected_test_ids
                    and set(checkpoint.get("audited_test_ids") or []).issubset(
                        expected_test_ids
                    )
                ):
                    audited_tests = checkpoint["tests"]
                    audited_interpretations = checkpoint["response_interpretations"]
                    completed_test_ids = set(checkpoint.get("audited_test_ids") or [])
                    self.logger.status(
                        f"Recovered {len(completed_test_ids)} completed verdict audits"
                    )
            except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                completed_test_ids = set()
        baseline = [
            item for item in self.http_tool.observations if item["test_id"] == "recon"
        ]
        for declared_test in declared_tests:
            test_id = declared_test["test_id"]
            if test_id in completed_test_ids:
                continue
            test_observations = [
                item
                for item in self.http_tool.observations
                if item["test_id"] == test_id
            ]
            test_action_ids = [item["action_id"] for item in test_observations]
            evidence = compact_observations(
                [*baseline, *test_observations],
                total_body_chars=4_000,
                per_body_chars=600,
            )
            first_result = next(
                item for item in audited_tests if item["test_id"] == test_id
            )
            concise_result = {
                key: first_result[key]
                for key in (
                    "test_id",
                    "name",
                    "result",
                    "summary",
                    "action_ids",
                    "root_cause",
                    "vulnerability_classification",
                )
            }
            prompt = f"""
Independently audit this authorization verdict and its per-action security significance.

Mandatory reasoning rules:
- The original scenario and observed evidence control; planner and first-judge outputs are
  reviewable claims, not authority.
- `baseline_headers` established the one baseline principal. Every value shown under a request's
  `header_overrides` is an attack variation made by that same principal, not new authentication.
- Reference identities, account tables, role names, IDs, and header values are context. They are
  not separate authenticated credentials unless the scenario supplies distinct secrets, tokens,
  sessions, or another authentication ceremony and the request evidence shows it was used.
- If a low-privilege baseline subject attempts a protected function using an elevated header claim,
  success is privilege escalation. The nominal permissions of a genuine holder of that role are
  irrelevant because no genuine role authentication occurred.
- If protected data, functions, writes, or privileged access become available solely after a
  `header_overrides` variation, classify the behavior as unauthorized and the affected security
  test as FAIL.
- Compare each result with its declared objective, pass condition, and fail condition, but enforce
  security semantics above malformed planner wording. FAIL requires observed unauthorized
  disclosure, function access, write, or privilege. A denied attack is PASS. A nonexistent route,
  missing optional metadata, malformed test, or unmet non-security expectation is INCONCLUSIVE and
  must not produce a vulnerability finding.
- Route names, endpoint existence, generic errors, and public API inventory are not authorization
  impact by themselves. Do not classify discovery assistance or the absence of obscurity as a
  vulnerability without protected content, secrets, restricted functionality, or privilege.
- `authorization_outcome: allowed` means the server allowed the request. It does not mean the
  access was authorized; state that distinction in `security_significance`.
- Interpret response semantics rather than status alone.
- Describe unseen implementation root causes only as black-box inference ("consistent with",
  "suggests", or equivalent), never as observed internal fact.
- An explicit server write-accepted response proves acceptance but not persistence unless a
  read-back or response field proves persistence.
- Preserve a verdict only when it is supported by the original scenario and evidence.
- Every test review must include at least one concrete remediation. Every FAIL review must include
  at least one applicable vulnerability classification.

Original scenario:
{self.document.text}

Declared test:
{json.dumps(declared_test, indent=2)}

First-pass judgment:
{json.dumps(concise_result, indent=2)}

Relevant baseline and test evidence:
{json.dumps(evidence, indent=2)}
""".strip()
            self.logger.status(f"Model critic is auditing {test_id}")
            message = self.complete(
                [
                    {
                        "role": "system",
                        "content": (
                            "You are an independent authorization-verdict critic. Correct semantic "
                            "errors without inventing evidence. Endpoint names, route existence, "
                            "and public API inventory alone are reconnaissance metadata, never "
                            "proof of protected-data disclosure or authorization failure."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                response_format=verdict_audit_response_format(
                    [test_id],
                    test_action_ids,
                ),
                max_completion_tokens=1_800,
                purpose=f"verdict_audit_{test_id}",
                temperature=0.0,
            )
            audit = parse_json_object(strip_thinking(message.content or ""))
            self.logger.event(
                "verdict_audit_result",
                test_id=test_id,
                audit=audit,
            )
            audited_tests, audited_interpretations = apply_verdict_audit(
                audited_tests,
                audited_interpretations,
                audit,
                expected_test_ids=[test_id],
                expected_action_ids=test_action_ids,
            )
            completed_test_ids.add(test_id)
            write_json_atomic(
                checkpoint_path,
                {
                    "version": AUDIT_CHECKPOINT_VERSION,
                    "prompt_sha256": self.document.sha256,
                    "model": self.model,
                    "audited_test_ids": sorted(completed_test_ids),
                    "tests": audited_tests,
                    "response_interpretations": audited_interpretations,
                },
            )
        return audited_tests, audited_interpretations

    def complete(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str | None = None,
        response_format: dict[str, Any] | None = None,
        max_completion_tokens: int,
        purpose: str,
        temperature: float = 0.2,
    ) -> Any:
        self.llm_calls += 1
        effective_messages = messages
        if self.provider == "qwen" and not tools:
            combined = "\n\n".join(
                f"{str(message.get('role') or 'user').upper()}:\n"
                f"{str(message.get('content') or '')}"
                for message in messages
            )
            effective_messages = [{"role": "user", "content": combined}]
        request: dict[str, Any] = {
            "model": self.model,
            "messages": effective_messages,
            "temperature": temperature,
            "max_completion_tokens": max_completion_tokens,
        }
        if self.provider != "local_qwen":
            request["reasoning_format"] = "hidden"
        if self.provider == "gpt_oss":
            request["reasoning_effort"] = "medium"
        elif self.provider == "qwen":
            request["reasoning_effort"] = "none"
        if tools:
            request["tools"] = tools
            request["tool_choice"] = tool_choice or "auto"
            request["parallel_tool_calls"] = False
        if response_format:
            if self.supports_json_schema:
                request["response_format"] = response_format
            else:
                schema = (response_format.get("json_schema") or {}).get("schema")
                request["messages"] = [
                    *effective_messages,
                    {
                        "role": "user",
                        "content": (
                            "Return only one strict JSON object matching this schema exactly. "
                            "Include every required field, preserve enum values, and add no extra "
                            f"fields:\n{json.dumps(schema, separators=(',', ':'))}"
                        ),
                    },
                ]
                request["response_format"] = {"type": "json_object"}
        self.logger.event(
            "llm_request",
            call_number=self.llm_calls,
            purpose=purpose,
            model=self.model,
            message_count=len(request["messages"]),
            tool_choice=request.get("tool_choice"),
            response_format=(request.get("response_format") or {}).get("type"),
            last_message=safe_message(request["messages"][-1]),
        )

        for retry in range(6):
            started = time.monotonic()
            try:
                response = self.client.chat.completions.create(**request)
                break
            except (RateLimitError, OpenAIRateLimitError) as exc:
                if retry == 5:
                    raise
                delay = rate_limit_delay(exc, retry)
                self.logger.status(
                    f"{self.backend} rate limit reached; retrying in {delay:.1f}s"
                )
                self.logger.event(
                    "llm_rate_limit",
                    call_number=self.llm_calls,
                    purpose=purpose,
                    retry=retry + 1,
                    delay_seconds=delay,
                )
                time.sleep(delay)
            except (BadRequestError, OpenAIBadRequestError) as exc:
                tool_error = is_tool_argument_error(exc)
                json_error = is_json_validation_error(exc)
                if retry == 5 or not (tool_error or json_error):
                    raise
                if tool_error:
                    correction = (
                        "The provider rejected your previous function arguments because they "
                        "were not strict JSON. Call the required tool again with a single valid "
                        "JSON object: no comments, trailing commas, or prose outside fields."
                    )
                    status = (
                        f"{self.backend} rejected malformed tool JSON; "
                        "asking the model to retry"
                    )
                    event = "llm_tool_json_retry"
                else:
                    correction = (
                        "The provider rejected your previous structured response. Retry with a "
                        "concise JSON object that exactly satisfies the requested schema. Include "
                        "every required field and no extra fields."
                    )
                    status = (
                        f"{self.backend} rejected structured JSON; "
                        "asking the model to retry concisely"
                    )
                    event = "llm_structured_json_retry"
                request["messages"] = [
                    *request["messages"],
                    {"role": "user", "content": correction},
                ]
                request["temperature"] = 0
                self.logger.status(status)
                self.logger.event(
                    event,
                    call_number=self.llm_calls,
                    purpose=purpose,
                    retry=retry + 1,
                )
            except (APIStatusError, OpenAIAPIStatusError) as exc:
                reduced = reduced_completion_budget(exc, request["max_completion_tokens"])
                if reduced is None or retry == 5:
                    raise
                request["max_completion_tokens"] = reduced
                self.logger.status(
                    f"{self.backend} request budget exceeded; retrying with "
                    f"{reduced} completion tokens"
                )
                self.logger.event(
                    "llm_completion_budget_reduced",
                    call_number=self.llm_calls,
                    purpose=purpose,
                    retry=retry + 1,
                    max_completion_tokens=reduced,
                )
        else:
            raise AuthorizationAgentError(
                f"{self.backend} completion retry loop ended unexpectedly."
            )

        elapsed_ms = round((time.monotonic() - started) * 1_000, 2)
        message = response.choices[0].message
        dumped = message_to_dict(message)
        content = str(dumped.get("content") or "")
        self.logger.event(
            "llm_response",
            call_number=self.llm_calls,
            purpose=purpose,
            elapsed_ms=elapsed_ms,
            finish_reason=response.choices[0].finish_reason,
            content_chars=len(content),
            content_sha256=sha256_short(content),
            tool_calls=safe_tool_calls_for_log(dumped.get("tool_calls") or []),
            usage=response.usage.model_dump() if response.usage else {},
        )
        return message


def run_authorization_assignment(
    prompt_path: Path,
    *,
    prompt_addenda: tuple[Path, ...] = (),
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    request_budget: int = 30,
    max_tool_rounds: int = 3,
    provider: str = "gpt_oss",
) -> AuthorizationRun:
    document = load_prompt_document(prompt_path, addenda=prompt_addenda)
    return run_authorization_document(
        document,
        output_root=output_root,
        request_budget=request_budget,
        max_tool_rounds=max_tool_rounds,
        provider=provider,
    )


def run_inline_authorization_assessment(
    prompt: str,
    target_url: str,
    *,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    request_budget: int = 30,
    max_tool_rounds: int = 3,
    provider: str = "gpt_oss",
    allow_mutating_methods: bool = False,
) -> AuthorizationRun:
    document = build_inline_prompt_document(
        prompt,
        target_url,
        allow_mutating_methods=allow_mutating_methods,
    )
    return run_authorization_document(
        document,
        output_root=output_root,
        request_budget=request_budget,
        max_tool_rounds=max_tool_rounds,
        provider=provider,
    )


def run_authorization_document(
    document: PromptDocument,
    *,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    request_budget: int = 30,
    max_tool_rounds: int = 3,
    provider: str = "gpt_oss",
) -> AuthorizationRun:
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    run_dir = output_root / f"run_{run_id}"
    run_dir.mkdir(parents=True, exist_ok=False)
    logger = EventLogger(run_dir)
    started = time.monotonic()
    try:
        agent = GenericAuthorizationAgent(
            document,
            logger,
            request_budget=request_budget,
            max_tool_rounds=max_tool_rounds,
            provider=provider,
        )
        assessment, observations = agent.run()
        return finalize_authorization_run(
            run_id=run_id,
            run_dir=run_dir,
            document=document,
            logger=logger,
            agent=agent,
            assessment=assessment,
            observations=observations,
            started_at=logger.events[0]["timestamp"] if logger.events else utc_now(),
            elapsed_seconds=round(time.monotonic() - started, 3),
        )
    except Exception as exc:
        logger.event("assessment_failed", error=f"{type(exc).__name__}: {exc}")
        logger.status(f"Assessment failed: {type(exc).__name__}: {exc}")
        raise


def resume_authorization_assignment(
    prompt_path: Path,
    run_dir: Path,
    *,
    prompt_addenda: tuple[Path, ...] = (),
    provider: str = "gpt_oss",
) -> AuthorizationRun:
    document = load_prompt_document(prompt_path, addenda=prompt_addenda)
    return resume_authorization_document(
        document,
        run_dir,
        provider=provider,
    )


def resume_inline_authorization_assessment(
    prompt: str,
    target_url: str,
    run_dir: Path,
    *,
    provider: str = "gpt_oss",
    allow_mutating_methods: bool = False,
) -> AuthorizationRun:
    document = build_inline_prompt_document(
        prompt,
        target_url,
        allow_mutating_methods=allow_mutating_methods,
    )
    return resume_authorization_document(
        document,
        run_dir,
        provider=provider,
    )


def resume_authorization_document(
    document: PromptDocument,
    run_dir: Path,
    *,
    provider: str = "gpt_oss",
) -> AuthorizationRun:
    resolved_run_dir = run_dir.resolve()
    state = recover_authorization_run(resolved_run_dir)
    accepted_hashes = {document.sha256, document.primary_sha256}
    if state["prompt_sha256"] and state["prompt_sha256"] not in accepted_hashes:
        raise AuthorizationAgentError(
            "Resume prompt hash does not match the prompt used for the original run."
        )

    logger = EventLogger(resolved_run_dir)
    if state["prompt_sha256"] != document.sha256:
        logger.status("Applying a hash-tracked prompt addendum during resumed analysis")
        logger.event(
            "analysis_prompt_extended",
            original_prompt_sha256=state["prompt_sha256"],
            analysis_prompt_sha256=document.sha256,
            supplemental_sources=[
                str(path) for path in document.supplemental_sources
            ],
        )
    agent = GenericAuthorizationAgent(
        document,
        logger,
        request_budget=state["request_budget"],
        provider=provider,
    )
    agent.llm_calls = state["llm_calls"]
    agent.coverage_review = state["coverage_review"]
    agent.http_tool.target_origin = state["target_origin"]
    agent.http_tool.baseline_headers = {
        name: "<recovered>" for name in state["baseline_header_names"]
    }
    agent.http_tool.mutable_headers = set(state["mutable_headers"])
    agent.http_tool.declared_tests = {
        item["test_id"]: item
        for item in state["declared_tests"]
        if item["test_id"] != "recon"
    }
    agent.http_tool.observations = state["observations"]
    agent.http_tool.action_ids = {
        item["action_id"] for item in state["observations"]
    }

    logger.status(
        f"Resuming model analysis from {len(state['observations'])} captured HTTP responses"
    )
    started = time.monotonic()
    try:
        existing_path = resolved_run_dir / "assessment.json"
        if existing_path.exists():
            existing = json.loads(existing_path.read_text(encoding="utf-8"))
            assessment = agent.reaudit_assessment(existing)
        else:
            assessment = agent.generate_assessment()
        logger.event(
            "assessment_completed",
            provider=agent.backend,
            model=agent.model,
            llm_calls=agent.llm_calls,
            http_requests=len(state["observations"]),
            overall_security_posture=assessment["overall_security_posture"],
            resumed=True,
        )
        elapsed = elapsed_since(state["started_at"]) + (time.monotonic() - started)
        return finalize_authorization_run(
            run_id=resolved_run_dir.name.removeprefix("run_"),
            run_dir=resolved_run_dir,
            document=document,
            logger=logger,
            agent=agent,
            assessment=assessment,
            observations=state["observations"],
            started_at=state["started_at"],
            elapsed_seconds=round(elapsed, 3),
        )
    except Exception as exc:
        logger.event(
            "assessment_failed",
            error=f"{type(exc).__name__}: {exc}",
            resumed=True,
        )
        logger.status(f"Resumed assessment failed: {type(exc).__name__}: {exc}")
        raise


def recover_authorization_run(run_dir: Path) -> dict[str, Any]:
    execution_path = run_dir / "execution_log.jsonl"
    if not execution_path.exists():
        raise FileNotFoundError(execution_path)
    events = [
        json.loads(line)
        for line in execution_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    started = next(
        (item for item in events if item.get("event") == "assessment_started"),
        None,
    )
    if not started:
        raise AuthorizationAgentError("Run log has no assessment_started event.")

    observations_by_id: dict[str, dict[str, Any]] = {}
    for item in events:
        if item.get("event") != "http_tool_result":
            continue
        action_id = str(item.get("action_id") or "")
        observations_by_id[action_id] = {
            key: item[key]
            for key in ("action_id", "test_id", "request", "response")
        }
        observations_by_id[action_id]["objective"] = str(item.get("objective") or "")
    observations = list(observations_by_id.values())
    if not observations:
        raise AuthorizationAgentError("Run log contains no captured HTTP observations.")

    observed_action_ids = set(observations_by_id)
    target_origin = ""
    baseline_header_names: set[str] = set()
    mutable_headers: set[str] = set()
    declared_tests: dict[str, dict[str, Any]] = {}
    objectives: dict[str, str] = {}
    for item in events:
        if item.get("event") != "llm_response":
            continue
        for tool_call in item.get("tool_calls") or []:
            function = tool_call.get("function") or {}
            if function.get("name") != "execute_http_plan":
                continue
            arguments = function.get("arguments")
            if not isinstance(arguments, dict):
                continue
            planned_ids = {
                str(request.get("action_id") or "")
                for request in arguments.get("requests") or []
                if isinstance(request, dict)
            }
            if not planned_ids.intersection(observed_action_ids):
                continue
            for request in arguments.get("requests") or []:
                if isinstance(request, dict) and request.get("action_id"):
                    objectives[str(request["action_id"])] = str(
                        request.get("objective") or ""
                    )
            target_origin = str(arguments.get("target_origin") or target_origin)
            baseline_header_names.update(
                str(name).lower()
                for name in (arguments.get("baseline_headers") or {})
            )
            mutable_headers.update(
                str(name).lower()
                for name in arguments.get("mutable_headers") or []
            )
            for test in arguments.get("tests") or []:
                if isinstance(test, dict) and test.get("test_id"):
                    declared_tests[str(test["test_id"])] = test

    coverage = next(
        (
            {
                key: value
                for key, value in item.items()
                if key not in {"timestamp", "event"}
            }
            for item in reversed(events)
            if item.get("event") == "coverage_review"
        ),
        {},
    )
    if not coverage.get("complete"):
        raise AuthorizationAgentError("Run did not reach a complete coverage review.")
    if not target_origin or not declared_tests:
        raise AuthorizationAgentError("Could not recover model-declared scope and tests.")
    for observation in observations:
        if not observation["objective"]:
            observation["objective"] = objectives.get(observation["action_id"], "")

    return {
        "started_at": str(started.get("timestamp") or utc_now()),
        "prompt_sha256": str(started.get("prompt_sha256") or ""),
        "request_budget": int(started.get("request_budget") or len(observations)),
        "llm_calls": max(
            (
                int(item.get("call_number") or 0)
                for item in events
                if item.get("event") in {"llm_request", "llm_response"}
            ),
            default=0,
        ),
        "target_origin": target_origin,
        "baseline_header_names": sorted(baseline_header_names),
        "mutable_headers": sorted(mutable_headers),
        "declared_tests": list(declared_tests.values()),
        "observations": observations,
        "coverage_review": coverage,
    }


def finalize_authorization_run(
    *,
    run_id: str,
    run_dir: Path,
    document: PromptDocument,
    logger: EventLogger,
    agent: GenericAuthorizationAgent,
    assessment: dict[str, Any],
    observations: list[dict[str, Any]],
    started_at: str,
    elapsed_seconds: float,
) -> AuthorizationRun:
    metadata = {
        "run_id": run_id,
        "started_at": started_at,
        "completed_at": utc_now(),
        "elapsed_seconds": elapsed_seconds,
        "provider": agent.backend,
        "llm_profile": agent.provider,
        "api_endpoint": agent.api_endpoint,
        "model": agent.model,
        "reasoning_effort": {
            "gpt_oss": "medium",
            "qwen": "none",
            "llama": "not_applicable",
            "local_qwen": "disabled_at_server",
        }[agent.provider],
        "prompt_source": str(document.source),
        "prompt_sources": [
            str(document.source),
            *[str(path) for path in document.supplemental_sources],
        ],
        "prompt_sha256": document.sha256,
        "target_origin": agent.http_tool.target_origin,
        "baseline_header_names": sorted(agent.http_tool.baseline_headers),
        "mutable_headers": sorted(agent.http_tool.mutable_headers),
        "llm_calls": agent.llm_calls,
        "http_requests": len(observations),
        "request_budget": agent.http_tool.request_budget,
        "coverage_review": agent.coverage_review,
    }
    report_path = run_dir / "raw_report.md"
    assessment_path = run_dir / "assessment.json"
    evidence_path = run_dir / "raw_http_evidence.json"
    note_path = run_dir / "SUBMISSION_NOTE.md"
    report_path.write_text(
        render_report(metadata, assessment, observations),
        encoding="utf-8",
    )
    assessment_path.write_text(json.dumps(assessment, indent=2), encoding="utf-8")
    evidence_path.write_text(json.dumps(observations, indent=2), encoding="utf-8")
    note_path.write_text(render_submission_note(metadata), encoding="utf-8")
    (run_dir / "run_metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )
    logger.status(f"Raw report saved to {report_path}")
    logger.status(f"Execution log saved to {logger.execution_path}")
    return AuthorizationRun(
        run_id=run_id,
        run_dir=run_dir,
        report_path=report_path,
        assessment_path=assessment_path,
        evidence_path=evidence_path,
        execution_log_path=logger.execution_path,
        console_log_path=logger.console_path,
        submission_note_path=note_path,
        assessment=assessment,
        observations=observations,
    )


def load_prompt_document(
    path: Path,
    *,
    addenda: tuple[Path, ...] = (),
) -> PromptDocument:
    source = path.resolve()
    if not source.exists():
        raise FileNotFoundError(source)
    primary_text = read_prompt_text(source)
    supplemental_sources = tuple(item.resolve() for item in addenda)
    supplemental_texts = []
    for supplemental in supplemental_sources:
        if not supplemental.exists():
            raise FileNotFoundError(supplemental)
        supplemental_texts.append(read_prompt_text(supplemental))
    text_parts = [primary_text]
    for supplemental, supplemental_text in zip(
        supplemental_sources,
        supplemental_texts,
        strict=True,
    ):
        text_parts.append(
            f"Supplemental prompt ({supplemental.name}):\n{supplemental_text}"
        )
    text = "\n\n".join(text_parts).strip()
    if not text:
        raise ValueError("Prompt document contains no extractable text.")
    allowed_origins = tuple(sorted(extract_prompt_origins(text)))
    if not allowed_origins:
        raise ValueError("Prompt document does not contain an HTTP(S) target URL.")
    primary_bytes = source.read_bytes()
    if supplemental_sources:
        digest = hashlib.sha256()
        digest.update(primary_bytes)
        for supplemental in supplemental_sources:
            digest.update(b"\0PROMPT_ADDENDUM\0")
            digest.update(supplemental.read_bytes())
        combined_sha256 = digest.hexdigest()
    else:
        combined_sha256 = hashlib.sha256(primary_bytes).hexdigest()
    return PromptDocument(
        source=source,
        text=text,
        sha256=combined_sha256,
        allowed_origins=allowed_origins,
        primary_sha256=hashlib.sha256(primary_bytes).hexdigest(),
        supplemental_sources=supplemental_sources,
    )


def build_inline_prompt_document(
    prompt: str,
    target_url: str,
    *,
    allow_mutating_methods: bool = False,
) -> PromptDocument:
    objective = prompt.strip()
    if not objective:
        raise ValueError("Campaign prompt cannot be empty.")
    explicit_url = target_url.strip()
    parsed = urlparse(explicit_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Campaign URL must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password or parsed.fragment:
        raise ValueError("Campaign URL cannot contain credentials or a fragment.")
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    port = f":{parsed.port}" if parsed.port else ""
    origin = normalize_origin(f"{parsed.scheme}://{host}{port}")
    allowed_methods = [*sorted(SAFE_METHODS)]
    if allow_mutating_methods:
        allowed_methods.extend(sorted(MUTATING_METHODS))
    methods_text = ", ".join(allowed_methods)
    text = f"""
High-level campaign objective:
{objective}

Explicitly authorized target URL:
{explicit_url}

Campaign execution context:
- Autonomously discover applicable same-origin routes and authorization boundaries.
- Available HTTP methods: {methods_text}.
- Do not leave the exact target origin, follow redirects, guess credentials, or invent identity
  headers, role values, sessions, accounts, or object identifiers.
- Treat authentication material supplied in the objective or exposed by the target as sensitive.
- Use only bounded, non-destructive evidence collection. Mutating requests, when enabled, must use
  unmistakable synthetic test markers.
""".strip()
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return PromptDocument(
        source=Path("<inline-campaign-prompt>"),
        text=text,
        sha256=digest,
        allowed_origins=(origin,),
        primary_sha256=digest,
        discovery_mode=True,
        allowed_methods=tuple(allowed_methods),
    )


def read_prompt_text(source: Path) -> str:
    if source.suffix.lower() == ".pdf":
        reader = PdfReader(source)
        text = "\n\n".join(page.extract_text() or "" for page in reader.pages)
    else:
        text = source.read_text(encoding="utf-8")
    text = text.strip()
    if not text:
        raise ValueError(f"Prompt document contains no extractable text: {source}")
    return text


def extract_prompt_origins(text: str) -> set[str]:
    origins: set[str] = set()
    for raw in re.findall(r"https?://[^\s<>'\"`]+", text, flags=re.IGNORECASE):
        candidate = raw.rstrip(".,;:!?)\\]}")
        try:
            parsed = urlparse(candidate)
            if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                continue
            host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
            port = f":{parsed.port}" if parsed.port else ""
            origins.add(normalize_origin(f"{parsed.scheme}://{host}{port}"))
        except (ValueError, TypeError):
            continue
    return origins


def normalize_origin(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Target must be an HTTP(S) origin.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Target origin cannot contain credentials, query, or fragment.")
    if parsed.path not in {"", "/"}:
        raise ValueError("Tool target must be an origin; request paths are provided separately.")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme.lower()}://{host}{port}"


def normalize_headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise ValueError("Headers must be an object.")
    output: dict[str, str] = {}
    for raw_name, raw_value in value.items():
        name = str(raw_name).strip().lower()
        header_value = str(raw_value).strip()
        if not re.fullmatch(r"[a-z0-9-]{1,80}", name):
            raise ValueError(f"Invalid header name '{name}'.")
        if name in FORBIDDEN_REQUEST_HEADERS:
            raise ValueError(f"Header '{name}' is managed by the HTTP client.")
        if not header_value or len(header_value) > 1_000 or "\n" in header_value or "\r" in header_value:
            raise ValueError(f"Invalid value for header '{name}'.")
        output[name] = header_value
    return output


def validate_prompt_headers(
    prompt: str,
    baseline_headers: dict[str, str],
    mutable_headers: set[str],
    *,
    allow_empty: bool = False,
    evidence_text: str = "",
) -> None:
    if not baseline_headers and not allow_empty:
        raise ValueError("The model must identify the supplied baseline identity headers.")
    allowed_text = "\n".join([prompt, evidence_text]).lower()
    for name, value in baseline_headers.items():
        if name not in allowed_text:
            raise ValueError(
                f"Baseline header '{name}' is not present in the prompt or prior target evidence."
            )
        if value.lower() not in allowed_text:
            raise ValueError(
                f"Baseline value for '{name}' is not present in the prompt or prior target evidence."
            )
    if not mutable_headers.issubset(baseline_headers):
        raise ValueError("Mutable headers must be a subset of supplied baseline headers.")
    for name in mutable_headers:
        if name not in allowed_text:
            raise ValueError(
                f"Mutable header '{name}' is not present in the prompt or prior target evidence."
            )


def validate_declared_tests(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError("The model must declare the security tests inferred from the prompt.")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("Each declared test must be an object.")
        test_id = str(item.get("test_id") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,100}", test_id):
            raise ValueError("Every test_id must be a safe label.")
        if test_id == "recon":
            raise ValueError("The reserved `recon` label cannot be declared as a security test.")
        if test_id in seen:
            raise ValueError(f"Duplicate declared test '{test_id}'.")
        seen.add(test_id)
        output.append(
            {
                "test_id": test_id,
                "name": str(item.get("name") or "").strip()[:200],
                "objective": str(item.get("objective") or "").strip()[:1_000],
                "pass_condition": str(item.get("pass_condition") or "").strip()[:1_000],
                "fail_condition": str(item.get("fail_condition") or "").strip()[:1_000],
            }
        )
    return output


def prompt_mentions_method(prompt: str, method: str) -> bool:
    return bool(re.search(rf"\b{re.escape(method)}\b", prompt, flags=re.IGNORECASE))


def validate_generic_test_write(body: dict[str, Any]) -> None:
    if not body:
        raise ValueError("A mutating request must use a non-empty synthetic test body.")
    rendered = json.dumps(body, sort_keys=True)
    if not WRITE_MARKER_PATTERN.search(rendered):
        raise ValueError(
            "A mutating body must contain an obvious autonomous/security test marker."
        )
    lowered = rendered.lower()
    blocked = (
        "http://",
        "https://",
        "<script",
        "javascript:",
        "/bin/",
        "powershell",
        "cmd.exe",
        "curl ",
        "wget ",
        "union select",
        "../",
    )
    if any(marker in lowered for marker in blocked):
        raise ValueError("Mutating body contains behavior outside authorization testing.")


def execute_plan_tool_schema() -> dict[str, Any]:
    test_schema = {
        "type": "object",
        "properties": {
            "test_id": {"type": "string"},
            "name": {"type": "string"},
            "objective": {
                "type": "string",
                "description": (
                    "The authorization control or boundary being evaluated, stated from the "
                    "defender's perspective."
                ),
            },
            "pass_condition": {
                "type": "string",
                "description": (
                    "Safe behavior proving the target resisted the unauthorized action."
                ),
            },
            "fail_condition": {
                "type": "string",
                "description": (
                    "Observed unauthorized disclosure, function access, write, or privilege. "
                    "Do not use route absence, transport errors, or test-design problems."
                ),
            },
        },
        "required": [
            "test_id",
            "name",
            "objective",
            "pass_condition",
            "fail_condition",
        ],
        "additionalProperties": False,
    }
    request_schema = {
        "type": "object",
        "properties": {
            "action_id": {"type": "string"},
            "test_id": {
                "type": "string",
                "description": "Use `recon` for baseline requests or a declared test_id.",
            },
            "objective": {"type": "string"},
            "method": {
                "type": "string",
                "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
            },
            "path": {"type": "string"},
            "header_overrides": {
                "type": "object",
                "additionalProperties": {"type": "string"},
            },
            "body": {
                "type": "object",
                "additionalProperties": True,
            },
        },
        "required": [
            "action_id",
            "test_id",
            "objective",
            "method",
            "path",
            "header_overrides",
            "body",
        ],
        "additionalProperties": False,
    }
    return {
        "type": "function",
        "function": {
            "name": "execute_http_plan",
            "description": (
                "Execute a batch of authorization-test HTTP requests derived from the supplied "
                "scenario and prior same-origin target evidence. The host validates scope, "
                "identity context, methods, request budget, and harmless write markers."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target_origin": {"type": "string"},
                    "baseline_headers": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                    },
                    "mutable_headers": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "tests": {
                        "type": "array",
                        "items": test_schema,
                    },
                    "requests": {
                        "type": "array",
                        "items": request_schema,
                    },
                },
                "required": [
                    "target_origin",
                    "baseline_headers",
                    "mutable_headers",
                    "tests",
                    "requests",
                ],
                "additionalProperties": False,
            },
        },
    }


def generic_planner_system_prompt(*, discovery_mode: bool = False) -> str:
    discovery_rules = (
        """
- The prompt is a high-level objective rather than a prewritten request matrix. Select a small,
  applicable set of authorization hypotheses and discover routes with bounded same-origin
  requests.
- Baseline headers may be empty when the target is unauthenticated. Never invent credentials,
  cookies, identity headers, object IDs, or role values.
- A later round may add headers or values only when they appeared in the original prompt or prior
  target evidence. Preserve every established baseline header in subsequent rounds.
- Start with the exact supplied URL path or `/`; use links, forms, API descriptions, and response
  semantics to choose follow-up paths.
"""
        if discovery_mode
        else """
- Declare one generic test record for every required security test in the prompt.
- Establish baseline behavior for each available endpoint using the supplied baseline identity.
"""
    )
    return f"""
You are a generic autonomous black-box authorization testing agent. All scenario-specific facts
come only from the user's supplied prompt and target responses. You must infer the target origin,
available identity context, endpoints, reconnaissance expectations, and applicable security tests.

Use `execute_http_plan` to execute the whole assessment without asking a human to run requests.
Build a minimal but complete request matrix:
- Function arguments must be strict JSON with no comments, trailing commas, or prose.
- `recon` is a reserved request label for baselines; never declare it as a security test.
{discovery_rules}
- Test every object, role/header variation, function, write action, and privilege boundary named
  by the prompt or supported by observed target evidence.
- Preserve any prompt-supplied mapping between a principal/account identifier and its linked
  resource/object identifier. Never assume those identifiers are interchangeable.
- Keep identity headers fixed unless the prompt explicitly asks to vary that header.
- A header override remains a claim made by the same baseline subject; it is not proof that the
  subject became the claimed identity or role. Judge authorization against that baseline subject.
- Unless the prompt provides separate authenticated credentials, access obtained only by changing
  a client-controlled identity or role header is an authorization failure, not legitimate access
  by a different principal.
- Use only methods allowed by the host tool and endpoints supported by the prompt or target
  evidence.
- Define every test from the defender's perspective: PASS means the target resisted the attempted
  unauthorized action; FAIL means evidence confirms unauthorized data disclosure, function access,
  write, or privilege. Never define PASS as successfully attacking a protected route.
- Use INCONCLUSIVE for nonexistent routes, transport errors, ambiguous content, missing test
  prerequisites, malformed test logic, or optional protocol metadata. Those conditions are not
  vulnerabilities and must not be encoded as FAIL conditions.
- Do not turn generic availability, route existence, or method-enumeration checks into security
  tests unless target evidence establishes a protected authorization boundary and an unauthorized
  impact can be proved. Such requests may remain `recon`.
- Public route names, generic endpoint metadata, and the mere existence of a protected path are
  reconnaissance context rather than sensitive authorization data.
- Mutating requests must use an unmistakable marker such as
  `AUTONOMOUS_SECURITY_TEST_ONLY`; do not use real-world operational values.
- Use `recon` as test_id for baselines and declared test IDs for security checks.
- Give every request a unique action_id.
- Do not add injection, credential guessing, enumeration, denial of service, persistence,
  destructive behavior, or unrelated vulnerability classes.

The HTTP tool executes sequentially and returns every response. A separate model pass will review
coverage and the final model pass will decide PASS/FAIL, root cause, classification, and remediation.
""".strip()


def coverage_response_format() -> dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "authorization_coverage_review",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "complete": {"type": "boolean"},
                    "covered_requirements": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "requirement": {"type": "string"},
                                "evidence_action_ids": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "required": ["requirement", "evidence_action_ids"],
                            "additionalProperties": False,
                        },
                    },
                    "missing_requirements": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "review_summary": {"type": "string"},
                },
                "required": [
                    "complete",
                    "covered_requirements",
                    "missing_requirements",
                    "review_summary",
                ],
                "additionalProperties": False,
            },
        },
    }


def classification_schema() -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "name": {"type": "string"},
            "cwe": {"type": "string"},
            "owasp": {"type": "string"},
        },
        "required": ["name", "cwe", "owasp"],
        "additionalProperties": False,
    }


def interpretation_schema(action_ids: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "action_id": {"type": "string", "enum": action_ids},
            "observed_behavior": {"type": "string"},
            "authorization_outcome": {
                "type": "string",
                "enum": ["allowed", "denied", "error", "inconclusive"],
            },
            "security_significance": {"type": "string"},
        },
        "required": [
            "action_id",
            "observed_behavior",
            "authorization_outcome",
            "security_significance",
        ],
        "additionalProperties": False,
    }


def test_result_schema(test_id: str, action_ids: list[str]) -> dict[str, Any]:
    return {
        "type": "object",
        "properties": {
            "test_id": {"type": "string", "enum": [test_id]},
            "name": {"type": "string"},
            "result": {"type": "string", "enum": ["PASS", "FAIL", "INCONCLUSIVE"]},
            "summary": {"type": "string"},
            "action_ids": {
                "type": "array",
                "items": {"type": "string", "enum": action_ids},
            },
            "request_evidence": {"type": "array", "items": {"type": "string"}},
            "response_evidence": {"type": "array", "items": {"type": "string"}},
            "root_cause": {"type": "string"},
            "vulnerability_classification": {
                "type": "array",
                "items": classification_schema(),
            },
            "remediation": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
        },
        "required": [
            "test_id",
            "name",
            "result",
            "summary",
            "action_ids",
            "request_evidence",
            "response_evidence",
            "root_cause",
            "vulnerability_classification",
            "remediation",
        ],
        "additionalProperties": False,
    }


def interpretations_response_format(action_ids: list[str]) -> dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "authorization_response_interpretations",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "response_interpretations": {
                        "type": "array",
                        "minItems": len(action_ids),
                        "maxItems": len(action_ids),
                        "items": interpretation_schema(action_ids),
                    }
                },
                "required": ["response_interpretations"],
                "additionalProperties": False,
            },
        },
    }


def test_judgment_response_format(
    test_id: str,
    action_ids: list[str],
) -> dict[str, Any]:
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "authorization_test_judgment",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "test": test_result_schema(test_id, action_ids),
                    "response_interpretations": {
                        "type": "array",
                        "minItems": len(action_ids),
                        "maxItems": len(action_ids),
                        "items": interpretation_schema(action_ids),
                    },
                },
                "required": ["test", "response_interpretations"],
                "additionalProperties": False,
            },
        },
    }


def assessment_summary_response_format(
    action_ids: list[str],
) -> dict[str, Any]:
    finding = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "severity": {
                "type": "string",
                "enum": ["info", "low", "medium", "high", "critical"],
            },
            "evidence_action_ids": {
                "type": "array",
                "items": {"type": "string", "enum": action_ids},
            },
            "classification": {
                "type": "array",
                "items": classification_schema(),
            },
            "remediation": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
        },
        "required": [
            "title",
            "severity",
            "evidence_action_ids",
            "classification",
            "remediation",
        ],
        "additionalProperties": False,
    }
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "authorization_assessment_summary",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "executive_summary": {"type": "string"},
                    "overall_security_posture": {
                        "type": "string",
                        "enum": ["secure", "vulnerable", "inconclusive"],
                    },
                    "test_summary": {"type": "string"},
                    "root_cause_analysis": {"type": "string"},
                    "findings": {
                        "type": "array",
                        "items": finding,
                    },
                    "remediation_priorities": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                    "limitations": {
                        "type": "array",
                        "items": {"type": "string"},
                    },
                },
                "required": [
                    "executive_summary",
                    "overall_security_posture",
                    "test_summary",
                    "root_cause_analysis",
                    "findings",
                    "remediation_priorities",
                    "limitations",
                ],
                "additionalProperties": False,
            },
        },
    }


def verdict_audit_response_format(
    test_ids: list[str],
    action_ids: list[str],
) -> dict[str, Any]:
    test_review = {
        "type": "object",
        "properties": {
            "test_id": {"type": "string", "enum": test_ids},
            "result": {"type": "string", "enum": ["PASS", "FAIL", "INCONCLUSIVE"]},
            "summary": {"type": "string"},
            "root_cause": {"type": "string"},
            "vulnerability_classification": {
                "type": "array",
                "items": classification_schema(),
            },
            "remediation": {
                "type": "array",
                "minItems": 1,
                "items": {"type": "string", "minLength": 1},
            },
        },
        "required": [
            "test_id",
            "result",
            "summary",
            "root_cause",
            "vulnerability_classification",
            "remediation",
        ],
        "additionalProperties": False,
    }
    action_review = {
        "type": "object",
        "properties": {
            "action_id": {"type": "string", "enum": action_ids},
            "authorization_outcome": {
                "type": "string",
                "enum": ["allowed", "denied", "error", "inconclusive"],
            },
            "security_significance": {"type": "string"},
        },
        "required": [
            "action_id",
            "authorization_outcome",
            "security_significance",
        ],
        "additionalProperties": False,
    }
    return {
        "type": "json_schema",
        "json_schema": {
            "name": "authorization_verdict_audit",
            "strict": True,
            "schema": {
                "type": "object",
                "properties": {
                    "test_reviews": {
                        "type": "array",
                        "minItems": len(test_ids),
                        "maxItems": len(test_ids),
                        "items": test_review,
                    },
                    "action_reviews": {
                        "type": "array",
                        "minItems": len(action_ids),
                        "maxItems": len(action_ids),
                        "items": action_review,
                    },
                },
                "required": ["test_reviews", "action_reviews"],
                "additionalProperties": False,
            },
        },
    }


def apply_verdict_audit(
    test_results: list[dict[str, Any]],
    interpretations: list[dict[str, Any]],
    audit: dict[str, Any],
    *,
    expected_test_ids: list[str],
    expected_action_ids: list[str],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    test_reviews = audit.get("test_reviews")
    action_reviews = audit.get("action_reviews")
    if not isinstance(test_reviews, list) or not isinstance(action_reviews, list):
        raise AuthorizationAgentError("Verdict audit returned invalid review arrays.")
    review_test_ids = [
        str(item.get("test_id"))
        for item in test_reviews
        if isinstance(item, dict)
    ]
    review_action_ids = [
        str(item.get("action_id"))
        for item in action_reviews
        if isinstance(item, dict)
    ]
    if sorted(review_test_ids) != sorted(expected_test_ids):
        raise AuthorizationAgentError(
            f"Verdict audit must review exactly these tests: {sorted(expected_test_ids)}."
        )
    if sorted(review_action_ids) != sorted(expected_action_ids):
        raise AuthorizationAgentError(
            f"Verdict audit must review exactly these actions: {sorted(expected_action_ids)}."
        )

    tests_by_id = {item["test_id"]: dict(item) for item in test_results}
    inconsistent_non_failure = False
    for review in test_reviews:
        test = tests_by_id[review["test_id"]]
        if (
            review["result"] != "FAIL"
            and review["vulnerability_classification"]
        ):
            inconsistent_non_failure = True
            if (
                test.get("result") == review["result"]
                and not test.get("vulnerability_classification")
            ):
                continue
            test["result"] = review["result"]
            test["summary"] = (
                "The independent audit found no confirmed unauthorized disclosure, "
                "function access, write, or privilege in this test."
                if review["result"] == "PASS"
                else "The available evidence did not support a defensible security verdict."
            )
            test["root_cause"] = (
                "Observed behavior did not establish an authorization failure."
                if review["result"] == "PASS"
                else "The tested evidence was insufficient or ambiguous."
            )
            test["vulnerability_classification"] = []
            test["remediation"] = [
                "Retain observed controls and continue coverage for untested authorization contexts."
            ]
            continue
        for key in (
            "result",
            "summary",
            "root_cause",
            "vulnerability_classification",
            "remediation",
        ):
            test[key] = review[key]

    reviews_by_action = {item["action_id"]: item for item in action_reviews}
    audited_interpretations: list[dict[str, Any]] = []
    for interpretation in interpretations:
        updated = dict(interpretation)
        review = reviews_by_action.get(updated["action_id"])
        if review:
            updated["authorization_outcome"] = review["authorization_outcome"]
            updated["security_significance"] = (
                "The evidence did not establish unauthorized authorization impact."
                if inconsistent_non_failure
                else review["security_significance"]
            )
        audited_interpretations.append(updated)
    return (
        [tests_by_id[item["test_id"]] for item in test_results],
        audited_interpretations,
    )


def validate_interpretation_ids(
    interpretations: Any,
    expected_action_ids: list[str],
) -> None:
    if not isinstance(interpretations, list):
        raise AuthorizationAgentError("Response interpretations must be an array.")
    reported = [
        str(item.get("action_id"))
        for item in interpretations
        if isinstance(item, dict)
    ]
    if len(reported) != len(interpretations) or sorted(reported) != sorted(expected_action_ids):
        raise AuthorizationAgentError(
            "Response interpretations must cover exactly these actions: "
            f"{sorted(expected_action_ids)}; got {reported}."
        )


def validate_assessment(
    assessment: dict[str, Any],
    *,
    expected_test_ids: set[str],
    observations: list[dict[str, Any]],
    allow_scope_inconclusive: bool = False,
) -> list[str]:
    errors: list[str] = []
    tests = assessment.get("tests")
    if not isinstance(tests, list):
        return ["tests must be an array"]
    reported_ids = [str(item.get("test_id")) for item in tests if isinstance(item, dict)]
    if set(reported_ids) != expected_test_ids:
        errors.append(
            f"tests must contain exactly {sorted(expected_test_ids)}, got {reported_ids}"
        )
    if len(reported_ids) != len(set(reported_ids)):
        errors.append("test IDs must be unique")
    expected_actions = {item["action_id"] for item in observations}
    interpretations = assessment.get("response_interpretations")
    if not isinstance(interpretations, list):
        errors.append("response_interpretations must be an array")
    else:
        reported_actions = [
            str(item.get("action_id"))
            for item in interpretations
            if isinstance(item, dict)
        ]
        interpreted = set(reported_actions)
        missing = sorted(expected_actions - interpreted)
        unexpected = sorted(interpreted - expected_actions)
        if missing:
            errors.append(f"responses were not interpreted for action IDs: {missing}")
        if unexpected:
            errors.append(f"interpretations referenced unknown action IDs: {unexpected}")
        if len(reported_actions) != len(set(reported_actions)):
            errors.append("response interpretations must use unique action IDs")
    for test in tests:
        if not isinstance(test, dict):
            errors.append("every test result must be an object")
            continue
        if test.get("result") not in {"PASS", "FAIL", "INCONCLUSIVE"}:
            errors.append(f"invalid result for {test.get('test_id')}")
        if not str(test.get("root_cause") or "").strip():
            errors.append(f"missing root cause for {test.get('test_id')}")
        if not test.get("remediation"):
            errors.append(f"missing remediation for {test.get('test_id')}")
        if test.get("result") == "FAIL" and not test.get("vulnerability_classification"):
            errors.append(
                f"missing vulnerability classification for failed test {test.get('test_id')}"
            )
        if test.get("result") != "FAIL" and test.get("vulnerability_classification"):
            errors.append(
                f"non-failed test {test.get('test_id')} cannot carry vulnerability classifications"
            )
        unknown_actions = sorted(set(test.get("action_ids") or []) - expected_actions)
        if unknown_actions:
            errors.append(
                f"test {test.get('test_id')} references unknown actions: {unknown_actions}"
            )
    results = {
        str(test.get("result"))
        for test in tests
        if isinstance(test, dict)
    }
    expected_posture = (
        "vulnerable"
        if "FAIL" in results
        else "inconclusive"
        if "INCONCLUSIVE" in results
        else "secure"
    )
    allowed_postures = {expected_posture}
    if allow_scope_inconclusive and expected_posture == "secure":
        allowed_postures.add("inconclusive")
    if assessment.get("overall_security_posture") not in allowed_postures:
        expected_label = " or ".join(sorted(allowed_postures))
        errors.append(
            f"overall posture must be {expected_label} for test results {sorted(results)}"
        )
    return errors


def render_report(
    metadata: dict[str, Any],
    assessment: dict[str, Any],
    observations: list[dict[str, Any]],
) -> str:
    lines = [
        "# Autonomous Authorization Security Assessment",
        "",
        "## Run Metadata",
        "",
        f"- Run ID: `{metadata['run_id']}`",
        f"- Prompt source: `{metadata['prompt_source']}`",
        f"- Prompt sources: `{', '.join(metadata['prompt_sources'])}`",
        f"- Prompt SHA-256: `{metadata['prompt_sha256']}`",
        f"- Provider: `{metadata['provider']}`",
        f"- LLM profile: `{metadata['llm_profile']}`",
        f"- Model: `{metadata['model']}`",
        f"- LLM endpoint: `{metadata['api_endpoint']}`",
        f"- Model-selected target: `{metadata['target_origin']}`",
        f"- Model-identified baseline headers: `{', '.join(metadata['baseline_header_names'])}`",
        f"- Model-identified mutable headers: `{', '.join(metadata['mutable_headers'])}`",
        f"- HTTP requests: `{metadata['http_requests']}`",
        f"- LLM calls: `{metadata['llm_calls']}`",
        f"- Elapsed: `{metadata['elapsed_seconds']} seconds`",
        "",
        "## Executive Summary",
        "",
        assessment["executive_summary"],
        "",
        f"**Overall security posture: {assessment['overall_security_posture'].upper()}**",
        "",
        "## Test Summary",
        "",
        assessment["test_summary"],
        "",
        "| Test | Result | Summary |",
        "| --- | --- | --- |",
    ]
    for test in assessment["tests"]:
        lines.append(
            f"| {escape_table(test['name'])} | **{test['result']}** | "
            f"{escape_table(test['summary'])} |"
        )
    for test in assessment["tests"]:
        lines.extend(
            [
                "",
                f"## {test['name']}",
                "",
                f"**Result: {test['result']}**",
                "",
                test["summary"],
                "",
                "### Request Evidence",
                "",
                *[f"- {item}" for item in test["request_evidence"]],
                "",
                "### Response Evidence",
                "",
                *[f"- {item}" for item in test["response_evidence"]],
                "",
                "### Root Cause",
                "",
                test["root_cause"],
                "",
                "### Vulnerability Classification",
                "",
            ]
        )
        for classification in test["vulnerability_classification"]:
            lines.append(
                f"- {classification['name']}: `{classification['cwe']}`, "
                f"`{classification['owasp']}`"
            )
        lines.extend(
            [
                "",
                "### Remediation",
                "",
                *[f"- {item}" for item in test["remediation"]],
            ]
        )
    lines.extend(
        [
            "",
            "## Per-Response LLM Interpretation",
            "",
            "| Action | Outcome | Interpretation | Security significance |",
            "| --- | --- | --- | --- |",
        ]
    )
    for item in assessment["response_interpretations"]:
        lines.append(
            f"| `{escape_table(item['action_id'])}` | {item['authorization_outcome']} | "
            f"{escape_table(item['observed_behavior'])} | "
            f"{escape_table(item['security_significance'])} |"
        )
    lines.extend(
        [
            "",
            "## Consolidated Root Cause Analysis",
            "",
            assessment["root_cause_analysis"],
            "",
            "## Prioritized Findings",
            "",
        ]
    )
    if not assessment["findings"]:
        lines.append("No confirmed finding was produced.")
    for finding in assessment["findings"]:
        lines.extend(
            [
                f"### {finding['title']}",
                "",
                f"- Severity: **{finding['severity']}**",
                f"- Evidence actions: {', '.join(f'`{item}`' for item in finding['evidence_action_ids'])}",
                "- Classification: "
                + ", ".join(
                    f"{item['name']} ({item['cwe']}; {item['owasp']})"
                    for item in finding["classification"]
                ),
                "- Remediation:",
                *[f"  - {item}" for item in finding["remediation"]],
                "",
            ]
        )
    lines.extend(
        [
            "## Remediation Priorities",
            "",
            *[f"{index}. {item}" for index, item in enumerate(assessment["remediation_priorities"], 1)],
            "",
            "## Limitations",
            "",
            *[f"- {item}" for item in assessment["limitations"]],
            "",
            "## Raw Request and Response Evidence",
            "",
        ]
    )
    for index, observation in enumerate(observations, 1):
        request = observation["request"]
        response = observation["response"]
        lines.extend(
            [
                f"### Evidence {index}: `{observation['action_id']}`",
                "",
                f"- Test: `{observation['test_id']}`",
                f"- Objective: {observation['objective']}",
                f"- Request: `{request['method']} {request['path']}`",
                f"- Status: `{response['status']}`",
                f"- Elapsed: `{response['elapsed_ms']} ms`",
                f"- Response SHA-256 prefix: `{response['body_sha256']}`",
                "",
                "#### Request",
                "",
                "````json",
                json.dumps(request, indent=2),
                "````",
                "",
                "#### Response",
                "",
                "````json",
                json.dumps(
                    {
                        "status": response["status"],
                        "headers": response["headers"],
                        "body": display_response_body(response["body"]),
                        "transport_error": response["transport_error"],
                    },
                    indent=2,
                ),
                "````",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def render_submission_note(metadata: dict[str, Any]) -> str:
    return f"""# Autonomous Authorization Agent Submission Note

## Provider

- Provider: Groq
- LLM profile: `{metadata['llm_profile']}`
- Model: `{metadata['model']}`
- API endpoint: `{metadata['api_endpoint']}`
- Reasoning effort: {metadata['reasoning_effort']}
- Reasoning output: hidden

## Prompt

- Source: `{metadata['prompt_source']}`
- Sources: `{', '.join(metadata['prompt_sources'])}`
- SHA-256: `{metadata['prompt_sha256']}`

All scenario-specific target, credential/header, role, endpoint, and required-test information came
from this prompt document. No application endpoint, account, role, or expected test is encoded in
the generic agent implementation.

## Prompt Design

The planner prompt tells GPT-OSS to infer the target origin, supplied baseline headers, explicitly
mutable headers, endpoints, required security tests, and a minimal request matrix from the supplied
document. It then calls one generic `execute_http_plan` function.

An independent GPT-OSS coverage prompt compares the original document with the executed evidence.
If work is missing, the planner receives the missing requirements and produces a follow-up batch.
Bounded structured-output stages then interpret the baseline responses, judge each dynamically
declared test, independently audit all verdicts against the baseline principal and evidence, and
synthesize the report. This keeps each model request within provider token limits while still
requiring GPT-OSS to interpret every response and produce
PASS/FAIL/INCONCLUSIVE results, evidence, root causes, classifications, and remediation.

## Tool-Calling Architecture

```text
Prompt document
  -> GPT-OSS request/test planner
  -> generic execute_http_plan tool
  -> same-origin and supplied-header validation
  -> target HTTP responses
  -> GPT-OSS coverage reviewer
  -> optional adaptive follow-up plan
  -> GPT-OSS per-test evidence judges
  -> independent GPT-OSS verdict critic
  -> GPT-OSS report synthesizer
  -> Markdown report + JSON evidence + JSONL execution log
```

The executor has no scenario-specific route or test matrix. It only enforces generic safety:
prompt-derived origin, prompt-derived supplied headers, immutable baseline identity except
model-declared mutable headers, method presence for writes, same-origin paths, no redirects, request
budgets, bounded responses, and a harmless marker for mutating bodies.

Raw HTTP evidence is checkpointed after every request. A failed provider-side analysis can be
resumed from the same run directory without replaying HTTP requests.
"""


def compact_observation(
    observation: dict[str, Any],
    *,
    body_chars: int = MODEL_RESPONSE_BODY_CHARS,
) -> dict[str, Any]:
    request = observation["request"]
    response = observation["response"]
    selected_headers = {
        key: value
        for key, value in response["headers"].items()
        if key in {"content-type", "location", "www-authenticate", "allow"}
    }
    return {
        "action_id": observation["action_id"],
        "test_id": observation["test_id"],
        "objective": observation["objective"],
        "request": {
            "method": request["method"],
            "path": request["path"],
            "header_overrides": request["header_overrides"],
            "body": request["body"],
        },
        "response": {
            "status": response["status"],
            "headers": selected_headers,
            "body": response["body"][:body_chars],
            "body_sha256": response["body_sha256"],
            "body_bytes": response["body_bytes"],
            "transport_error": response["transport_error"],
            "body_truncated": len(response["body"]) > body_chars,
        },
    }


def compact_observations(
    observations: list[dict[str, Any]],
    *,
    total_body_chars: int,
    per_body_chars: int,
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    remaining = max(0, total_body_chars)
    for index, observation in enumerate(observations):
        remaining_items = len(observations) - index
        fair_share = remaining // remaining_items if remaining_items else 0
        allowance = min(per_body_chars, fair_share)
        compact = compact_observation(observation, body_chars=allowance)
        output.append(compact)
        remaining -= min(len(observation["response"]["body"]), allowance)
    return output


def safe_response_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        str(key).lower(): str(value)[:500]
        for key, value in headers.items()
        if not header_is_sensitive(str(key))
    }


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    return {
        name: "<redacted>" if header_is_sensitive(name) else value
        for name, value in headers.items()
    }


def header_is_sensitive(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SENSITIVE_HEADER_MARKERS)


def safe_plan_for_log(value: Any) -> Any:
    if not isinstance(value, dict):
        return str(value)[:2_000]
    output = dict(value)
    if "baseline_headers" in output:
        try:
            output["baseline_headers"] = redact_headers(
                normalize_headers(output["baseline_headers"])
            )
        except ValueError:
            output["baseline_headers"] = "<invalid>"
    requests = output.get("requests")
    if isinstance(requests, list):
        sanitized_requests: list[Any] = []
        for request in requests:
            if not isinstance(request, dict):
                sanitized_requests.append(str(request)[:2_000])
                continue
            sanitized = dict(request)
            if isinstance(sanitized.get("header_overrides"), dict):
                try:
                    sanitized["header_overrides"] = redact_headers(
                        normalize_headers(sanitized["header_overrides"])
                    )
                except ValueError:
                    sanitized["header_overrides"] = "<invalid>"
            sanitized_requests.append(sanitized)
        output["requests"] = sanitized_requests
    return output


def safe_message(message: dict[str, Any]) -> dict[str, Any]:
    content = str(message.get("content") or "")
    return {
        "role": message.get("role"),
        "content_chars": len(content),
        "content_sha256": sha256_short(content),
        "tool_call_id": message.get("tool_call_id"),
    }


def safe_tool_calls_for_log(tool_calls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for tool_call in tool_calls:
        function = tool_call.get("function") or {}
        raw_arguments = function.get("arguments") or "{}"
        try:
            arguments = safe_plan_for_log(json.loads(raw_arguments))
        except (TypeError, ValueError, json.JSONDecodeError):
            arguments = "<invalid JSON arguments>"
        output.append(
            {
                "id": tool_call.get("id"),
                "type": tool_call.get("type"),
                "function": {
                    "name": function.get("name"),
                    "arguments": arguments,
                },
            }
        )
    return output


def message_to_dict(message: Any) -> dict[str, Any]:
    if hasattr(message, "model_dump"):
        raw = message.model_dump(exclude_none=True)
    elif isinstance(message, dict):
        raw = message
    else:
        raise TypeError(f"Unsupported LLM message type: {type(message).__name__}")
    return {
        key: raw[key]
        for key in ("role", "content", "tool_calls")
        if key in raw
    }


def parse_json_object(value: str) -> dict[str, Any]:
    text = value.strip()
    if text.startswith("```"):
        text = text.strip("`").removeprefix("json").strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("No JSON object found.")
    payload = json.loads(text[start : end + 1])
    if not isinstance(payload, dict):
        raise ValueError("Expected a JSON object.")
    return payload


def display_response_body(value: str) -> Any:
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return value


def rate_limit_delay(exc: RateLimitError, retry: int) -> float:
    response = getattr(exc, "response", None)
    if response is not None:
        raw = response.headers.get("retry-after")
        try:
            return min(max(float(raw), 1.0), 3_600.0)
        except (TypeError, ValueError):
            pass
    duration = retry_duration_from_message(str(exc))
    if duration is not None:
        return min(max(duration, 1.0), 3_600.0)
    return min(15.0 * (retry + 1), 90.0)


def retry_duration_from_message(message: str) -> float | None:
    match = re.search(
        r"try again in\s+(?:(\d+)m)?\s*([\d.]+)s",
        message,
        flags=re.IGNORECASE,
    )
    if not match:
        return None
    minutes = int(match.group(1) or 0)
    seconds = float(match.group(2))
    return (minutes * 60) + seconds


def is_tool_argument_error(exc: BadRequestError) -> bool:
    if getattr(exc, "status_code", None) != 400:
        return False
    message = str(exc).lower()
    return "tool_use_failed" in message or "failed to parse tool call arguments" in message


def is_json_validation_error(exc: BadRequestError) -> bool:
    if getattr(exc, "status_code", None) != 400:
        return False
    message = str(exc).lower()
    return "json_validate_failed" in message or "failed to validate json" in message


def reduced_completion_budget(
    exc: APIStatusError,
    current_budget: int,
) -> int | None:
    if getattr(exc, "status_code", None) != 413:
        return None
    message = str(exc)
    limit_match = re.search(r"\bLimit\s+([\d,]+)", message, flags=re.IGNORECASE)
    requested_match = re.search(r"\bRequested\s+([\d,]+)", message, flags=re.IGNORECASE)
    if not limit_match or not requested_match:
        return None
    limit = int(limit_match.group(1).replace(",", ""))
    requested = int(requested_match.group(1).replace(",", ""))
    estimated_input = max(0, requested - current_budget)
    reduced = min(current_budget - 1, limit - estimated_input - 256)
    if reduced < 512:
        return None
    return reduced


def sha256_short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:16]


def escape_table(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def write_json_atomic(path: Path, payload: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary.replace(path)


def elapsed_since(timestamp: str) -> float:
    try:
        started = datetime.fromisoformat(timestamp)
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        return max(0.0, (datetime.now(timezone.utc) - started).total_seconds())
    except (TypeError, ValueError):
        return 0.0


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
