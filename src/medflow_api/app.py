from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException

from medflow_graph.memory import GraphStore, ingest_campaign_report
from medflow_redteam.campaign import run_campaign, save_campaign_run
from medflow_redteam.config_loader import ROOT
from medflow_redteam.debug import build_campaign_debug, load_campaign_payload
from medflow_redteam.toolsmith import ToolsmithAgent
from medflow_redteam.tool_quality import list_quality_entries, record_quality_outcome, set_quality_state
from medflow_redteam.web_app import WebAuthContext

from .jobs import JobManager, job_to_dict
from .schemas import (
    ApiResponse,
    CampaignRequest,
    GraphSearchRequest,
    ToolQualityOutcomeRequest,
    ToolQualityStateRequest,
    ToolsmithCreateRequest,
    ToolsmithLookupRequest,
)


app = FastAPI(
    title="MedFlow Red-Team API",
    version="0.1.0",
    description="REST API for MedFlow campaign orchestration, graph memory, and Toolsmith-generated tools.",
)
jobs = JobManager(max_workers=4)


@app.get("/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "medflow-redteam-api"}


@app.post("/campaigns", response_model=ApiResponse)
def create_campaign(request: CampaignRequest) -> ApiResponse:
    record = jobs.submit(
        "campaign",
        lambda: run_campaign_job(request),
        metadata={
            "goal": request.goal,
            "target": request.target,
            "target_url": request.target_url,
        },
    )
    return ApiResponse(data=job_to_dict(record))


@app.get("/jobs", response_model=ApiResponse)
def list_jobs(limit: int = 50) -> ApiResponse:
    return ApiResponse(data=[job_to_dict(record) for record in jobs.list(limit=limit)])


@app.get("/jobs/{job_id}", response_model=ApiResponse)
def get_job(job_id: str) -> ApiResponse:
    record = jobs.get(job_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    return ApiResponse(data=job_to_dict(record))


@app.get("/jobs/{job_id}/debug", response_model=ApiResponse)
def get_job_debug(job_id: str) -> ApiResponse:
    record = jobs.get(job_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Job not found.")
    if record.result is None:
        raise HTTPException(status_code=409, detail=f"Job is {record.status}; debug is available after completion.")
    return ApiResponse(data=build_campaign_debug(record.result))


@app.get("/debug/campaign-report", response_model=ApiResponse)
def campaign_report_debug(path: str) -> ApiResponse:
    report = Path(path)
    if not report.is_absolute():
        report = ROOT / report
    report = report.resolve()
    if not str(report).startswith(str(ROOT.resolve())):
        raise HTTPException(status_code=400, detail="Report path must stay inside the project workspace.")
    if not report.exists():
        raise HTTPException(status_code=404, detail="Campaign report not found.")
    return ApiResponse(data=build_campaign_debug(load_campaign_payload(report)))


@app.post("/graph/search", response_model=ApiResponse)
def graph_search(request: GraphSearchRequest) -> ApiResponse:
    store = GraphStore.load(request.graph)
    node_types = set(request.node_types or []) or None
    return ApiResponse(data=store.search(request.query, limit=request.limit, node_types=node_types))


@app.get("/graph/summary", response_model=ApiResponse)
def graph_summary(graph: str = "data/graph/medflow_graph.json") -> ApiResponse:
    return ApiResponse(data=GraphStore.load(graph).summary())


@app.post("/toolsmith/lookup", response_model=ApiResponse)
def toolsmith_lookup(request: ToolsmithLookupRequest) -> ApiResponse:
    agent = ToolsmithAgent(graph_path=request.graph)
    return ApiResponse(data=agent.lookup(request.query, limit=request.limit))


@app.post("/toolsmith/tools", response_model=ApiResponse)
def toolsmith_create(request: ToolsmithCreateRequest) -> ApiResponse:
    agent = ToolsmithAgent(graph_path=request.graph, provider=request.provider)
    if request.template:
        if not request.service or not request.port:
            raise HTTPException(status_code=400, detail="Template creation requires service and port.")
        result = agent.create_from_template(
            tool_id=request.id,
            template=request.template,
            service=request.service,
            port=request.port,
            overwrite=request.overwrite,
        )
    elif request.prompt:
        result = agent.create_from_prompt(tool_id=request.id, prompt=request.prompt, overwrite=request.overwrite)
    else:
        raise HTTPException(status_code=400, detail="Provide either template or prompt.")
    return ApiResponse(
        data={
            "action": result.action,
            "tool_id": (result.spec or {}).get("id"),
            "artifact_hash": (result.spec or {}).get("artifact_hash"),
            "quality_state": (result.spec or {}).get("quality_state"),
            "quality_score": (result.spec or {}).get("quality_score"),
            "paths": {key: str(value) for key, value in (result.paths or {}).items()},
            "graph_node_id": result.graph_node_id,
        }
    )


@app.get("/toolsmith/cache", response_model=ApiResponse)
def tool_cache_list(state: str | None = None) -> ApiResponse:
    entries = list_quality_entries()
    if state:
        entries = [entry for entry in entries if entry.get("state") == state]
    return ApiResponse(data=entries)


@app.get("/toolsmith/cache/{reference}", response_model=ApiResponse)
def tool_cache_inspect(reference: str) -> ApiResponse:
    entries = [
        entry
        for entry in list_quality_entries()
        if entry.get("tool_id") == reference
        or entry.get("artifact_hash") == reference
        or str(entry.get("artifact_hash") or "").startswith(reference)
    ]
    if not entries:
        raise HTTPException(status_code=404, detail="Cached tool artifact not found.")
    return ApiResponse(data=entries)


@app.post("/toolsmith/cache/{reference}/state", response_model=ApiResponse)
def tool_cache_set_state(reference: str, request: ToolQualityStateRequest) -> ApiResponse:
    try:
        result = set_quality_state(reference, request.state, reason=request.reason, force=request.force)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return ApiResponse(data=result)


@app.post("/toolsmith/cache/{reference}/outcomes", response_model=ApiResponse)
def tool_cache_record_outcome(reference: str, request: ToolQualityOutcomeRequest) -> ApiResponse:
    try:
        result = record_quality_outcome(
            reference,
            request.outcome,
            reason=request.reason,
            evidence_id=request.evidence_id,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return ApiResponse(data=result)


def run_campaign_job(request: CampaignRequest) -> dict[str, Any]:
    run = run_campaign(
        goal=request.goal,
        target=request.target,
        target_url=request.target_url,
        ports=request.ports,
        provider=request.provider,
        execute_recon=request.execute_recon,
        execute_validation=request.execute_validation or request.loop,
        max_capabilities=request.max_capabilities,
        execution_mode=request.execution_mode,
        metasploit_action=request.metasploit_action,
        use_llm=request.use_llm,
        n_results=request.results,
        graph_memory_path=Path(request.graph_memory) if request.graph_memory else None,
        loop=request.loop,
        max_rounds=request.max_rounds,
        max_tools=request.max_tools,
        max_failed_rounds=request.max_failed_rounds,
        stop_on_success=request.stop_on_success,
        web_auth_contexts=[
            WebAuthContext(
                name=context.name,
                headers=context.headers,
                cookies=context.cookies,
                owned_object_ids=context.owned_object_ids,
            )
            for context in request.web_auth_contexts
        ],
        stateful_api=request.stateful_api,
        stateful_max_requests=request.stateful_max_requests,
        stateful_max_workflows=request.stateful_max_workflows,
        authorization_output_root=Path(request.output_dir) / "authorization",
    )
    saved = save_campaign_run(run, Path(request.output_dir))
    payload = asdict(run)
    payload["saved"] = {key: str(value) for key, value in saved.items()}
    if request.update_graph:
        store = GraphStore.load(request.graph_memory)
        ingest_stats = ingest_campaign_report(store, saved["json"])
        dedup_stats = store.dream_dedup() if request.graph_dedup else {"merged": 0, "reviews_added": 0}
        store.save()
        payload["graph_update"] = {
            "path": request.graph_memory,
            "ingest": ingest_stats,
            "dedup": dedup_stats,
            "summary": store.summary(),
        }
    return payload
