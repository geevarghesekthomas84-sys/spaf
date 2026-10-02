"""
SPAF HTTP API.

Everything the service does, over REST, with live scan events over WebSocket.
Secure by default: all endpoints except /health and /version require an API key;
active scans are scope-gated (out-of-scope → 403). Scans and agent runs are
asynchronous jobs — POST returns a job id, progress streams over
`/ws/jobs/{id}`, and the final result is available at GET /jobs/{id}.
"""

from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from spaf.service import SpafService, ScopeError, EventBus
from spaf.api.auth import load_keys, make_auth_dependency
from spaf.api.jobs import JobManager


class ScanRequest(BaseModel):
    module: str = Field(description="recon | toolkit | scan | webscan | crawl")
    target: str
    options: Dict[str, Any] = Field(default_factory=dict)


class AgentRequest(BaseModel):
    target: str
    goal: str = ""
    dry_run: bool = True
    aggressive: bool = False


class ScopeAddRequest(BaseModel):
    value: str


def create_app(scope_file: str = "scope.json") -> FastAPI:
    app = FastAPI(
        title="SPAF API",
        version=_version(),
        summary="AI-orchestrated offensive security — authorized testing only.",
    )
    svc = SpafService(scope_file=scope_file)
    jobs = JobManager()
    keys = load_keys()
    auth = Depends(make_auth_dependency(keys))

    app.state.api_keys = keys  # used by the WebSocket handler

    # ── Open endpoints ────────────────────────────────────────────────
    @app.get("/health")
    async def health():
        return {"status": "ok", "version": _version()}

    @app.get("/version")
    async def version():
        return {"version": _version()}

    # ── Scope & status ────────────────────────────────────────────────
    @app.get("/scope", dependencies=[auth])
    async def get_scope():
        return svc.scope_state().model_dump()

    @app.post("/scope", dependencies=[auth])
    async def add_scope(req: ScopeAddRequest):
        return svc.scope_add(req.value).model_dump()

    @app.get("/tools", dependencies=[auth])
    async def tools():
        return {"tools": [t.model_dump() for t in svc.tools_status()]}

    # ── Scans & agent (async jobs) ────────────────────────────────────
    @app.post("/scans", dependencies=[auth], status_code=202)
    async def start_scan(req: ScanRequest):
        _ensure_in_scope(svc, req.target)

        async def run(bus: EventBus):
            r = await svc.run_module(req.module, req.target, req.options, bus=bus, surface="api")
            return r.model_dump(mode="json")

        job = jobs.start("scan", req.target, run)
        return {"job_id": job.id, "status": job.status}

    @app.post("/agent", dependencies=[auth], status_code=202)
    async def start_agent(req: AgentRequest):
        if not req.dry_run:
            _ensure_in_scope(svc, req.target)

        async def run(bus: EventBus):
            r = await svc.run_agent(req.target, req.goal, dry_run=req.dry_run,
                                    aggressive=req.aggressive, bus=bus, surface="api")
            return r.model_dump(mode="json")

        job = jobs.start("agent", req.target, run)
        return {"job_id": job.id, "status": job.status}

    @app.get("/jobs/{job_id}", dependencies=[auth])
    async def get_job(job_id: str):
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(404, "job not found")
        return {"job_id": job.id, "kind": job.kind, "target": job.target,
                "status": job.status, "result": job.result, "error": job.error}

    # ── Reads ─────────────────────────────────────────────────────────
    @app.get("/scans/recent", dependencies=[auth])
    async def recent(target: Optional[str] = None, limit: int = 20):
        return {"scans": [s.model_dump(mode="json") for s in await svc.list_scans(target, limit)]}

    @app.get("/findings/{scan_id}", dependencies=[auth])
    async def findings(scan_id: str):
        return {"findings": [f.model_dump() for f in await svc.get_findings(scan_id)]}

    # ── Live events ───────────────────────────────────────────────────
    @app.websocket("/ws/jobs/{job_id}")
    async def ws_job(ws: WebSocket, job_id: str):
        key = ws.query_params.get("api_key") or ws.headers.get("x-api-key", "")
        if key not in app.state.api_keys:
            await ws.close(code=1008)  # policy violation
            return
        job = jobs.get(job_id)
        if not job:
            await ws.close(code=1011)
            return
        await ws.accept()
        if job.status != "running":
            await ws.send_json({"kind": "done", "status": job.status, "error": job.error})
            await ws.close()
            return
        try:
            async for ev in job.bus.subscribe():
                await ws.send_json({"kind": ev.kind, "module": ev.module,
                                    "message": ev.message, "pct": ev.pct, "data": ev.data})
            await ws.send_json({"kind": "done", "status": job.status,
                                "error": job.error})
        except WebSocketDisconnect:
            pass
        finally:
            try:
                await ws.close()
            except RuntimeError:
                pass

    return app


def _ensure_in_scope(svc: SpafService, target: str) -> None:
    try:
        svc._check_scope(target, "api")  # noqa: SLF001 - intentional internal use
    except ScopeError as exc:
        raise HTTPException(403, str(exc))


def _version() -> str:
    try:
        from spaf.cli.main import get_version
        return get_version()
    except Exception:
        return "0"
