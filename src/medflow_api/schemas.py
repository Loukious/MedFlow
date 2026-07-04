from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


Provider = Literal["llama", "qwen"]
ExecutionMode = Literal["safe", "aggressive_lab"]
MetasploitAction = Literal["plan", "check", "exploit"]


class CampaignRequest(BaseModel):
    goal: str = Field(..., min_length=1)
    target: str | None = None
    ports: list[int] | None = None
    execute_recon: bool = True
    execute_validation: bool = False
    max_capabilities: int = Field(default=5, ge=1, le=50)
    execution_mode: ExecutionMode = "safe"
    metasploit_action: MetasploitAction = "check"
    use_llm: bool = False
    provider: Provider = "llama"
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
    provider: Provider = "llama"
    graph: str = "data/graph/medflow_graph.json"
    overwrite: bool = False


class ApiResponse(BaseModel):
    ok: bool = True
    data: Any
