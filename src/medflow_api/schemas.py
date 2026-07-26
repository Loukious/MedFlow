from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


Provider = Literal["gpt_oss", "llama", "qwen"]
ExecutionMode = Literal["safe", "aggressive_lab"]
MetasploitAction = Literal["plan", "check", "exploit"]
ToolQualityState = Literal["candidate", "fixture_passed", "shadow", "trusted", "degraded", "quarantined"]
ToolQualityOutcome = Literal["completed", "confirmed", "contradicted", "fixture_passed", "inconclusive", "tool_error"]


class WebAuthContextRequest(BaseModel):
    """Pre-authenticated lab context. Values are redacted from persisted results."""

    name: str = Field(..., min_length=1)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    owned_object_ids: list[str] = Field(default_factory=list)


class CampaignRequest(BaseModel):
    goal: str = Field(..., min_length=1)
    target: str | None = None
    target_url: str | None = None
    ports: list[int] | None = None
    execute_recon: bool = True
    execute_validation: bool = False
    max_capabilities: int = Field(default=5, ge=1, le=50)
    execution_mode: ExecutionMode = "safe"
    metasploit_action: MetasploitAction = "check"
    use_llm: bool = False
    provider: Provider = "gpt_oss"
    results: int = Field(default=5, ge=1, le=30)
    graph_memory: str = "data/graph/medflow_graph.json"
    update_graph: bool = False
    graph_dedup: bool = False
    loop: bool = False
    max_rounds: int = Field(default=3, ge=1, le=20)
    max_tools: int = Field(default=12, ge=1, le=100)
    max_failed_rounds: int = Field(default=2, ge=1, le=20)
    stop_on_success: bool = True
    output_dir: str = "reports/redteam_campaign"
    web_auth_contexts: list[WebAuthContextRequest] = Field(default_factory=list, max_length=4)
    stateful_api: bool = False
    stateful_max_requests: int = Field(default=40, ge=1, le=200)
    stateful_max_workflows: int = Field(default=8, ge=1, le=30)

    @model_validator(mode="after")
    def validate_scope(self) -> "CampaignRequest":
        if self.target and self.target_url:
            raise ValueError("Supply either target or target_url, not both.")
        return self


class GraphSearchRequest(BaseModel):
    query: str = Field(..., min_length=1)
    limit: int = Field(default=10, ge=1, le=100)
    node_types: list[str] | None = None
    graph: str = "data/graph/medflow_graph.json"


class ToolsmithLookupRequest(BaseModel):
    query: str = Field(..., min_length=1)
    limit: int = Field(default=5, ge=1, le=50)
    graph: str = "data/graph/medflow_graph.json"


class ToolsmithCreateRequest(BaseModel):
    id: str = Field(..., min_length=1)
    template: Literal["tcp_banner"] | None = None
    service: str = ""
    port: int = 0
    prompt: str = ""
    provider: Provider = "gpt_oss"
    graph: str = "data/graph/medflow_graph.json"
    overwrite: bool = False


class ToolQualityStateRequest(BaseModel):
    state: ToolQualityState
    reason: str = Field(..., min_length=1)
    force: bool = False


class ToolQualityOutcomeRequest(BaseModel):
    outcome: ToolQualityOutcome
    reason: str = ""
    evidence_id: str = ""


class ApiResponse(BaseModel):
    ok: bool = True
    data: Any
