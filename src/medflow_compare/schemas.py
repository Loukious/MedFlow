from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class RedTeamScenario:
    name: str
    objective: str
    environment: str
    scope: list[str]
    out_of_scope: list[str]
    sample_telemetry: list[str]
    deliverable: str


@dataclass
class ToolTrace:
    name: str
    input: str
    output_preview: str


@dataclass
class ComparisonRun:
    framework: str
    provider: str
    scenario_name: str
    answer: str
    sources: list[dict[str, Any]] = field(default_factory=list)
    steps: list[str] = field(default_factory=list)
    tool_traces: list[ToolTrace] = field(default_factory=list)
    elapsed_seconds: float = 0.0
    error: str | None = None
