"""
SPAF HTTP API.

Everything the service does, over REST, with live scan events over WebSocket,
Prometheus metrics, an audit view, and a built-in web dashboard. Secure by
default: all endpoints except /health, /version, /metrics and the dashboard
require an API key; active scans are scope-gated (out-of-scope → 403). Scans and
agent runs are asynchronous jobs — POST returns a job id, progress streams over
`/ws/jobs/{id}`, and the final result is available at GET /jobs/{id}.

Multi-engagement + RBAC (Phase 7): each request carries an API key (→ a
*principal* with a role) and optionally an `X-Engagement` header selecting an
isolated workspace. Viewers may read; operators may launch scans/agent runs;
leads may manage scope and create engagements. Active runs on a persisted
engagement require a valid signed authorization when a signing key is set.
"""

import json
import os
from typing import Any, Dict, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field

from spaf.service import SpafService, ScopeError, EventBus
from spaf.service.audit import AUDIT_PATH
from spaf.api.jobs import JobManager
from spaf.api.metrics import Metrics
from spaf.workspaces import EngagementManager, Role, authorization
from spaf.workspaces.principals import load_registry


class ScanRequest(BaseModel):
    module: str = Field(description="recon | toolkit | scan | webscan | crawl | <plugin>")
    target: str
    options: Dict[str, Any] = Field(default_factory=dict)


class AgentRequest(BaseModel):
    target: str
    goal: str = ""
    dry_run: bool = True
    aggressive: bool = False


class ScopeAddRequest(BaseModel):
    value: str


class EngagementRequest(BaseModel):
    name: str
    in_scope: list = Field(default_factory=list)
    out_of_scope: list = Field(default_factory=list)
    retention_days: int = 0
    authorized_by: str = ""


def create_app(scope_file: str = "scope.json") -> FastAPI:
    app = FastAPI(
        title="SPAF API",
        version=_version(),
        summary="AI-orchestrated offensive security — authorized testing only.",
    )
    jobs = JobManager()
    metrics = Metrics()
    principals = load_registry()
    manager = EngagementManager()
    app.state.principals = principals  # used by the WebSocket handler

    # ── Identity, engagement & role dependencies ──────────────────────
    async def get_principal(x_api_key: str = Header(default="")):
        principal = principals.authenticate(x_api_key)
        if principal is None:
            metrics.inc("spaf_auth_failures_total")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                "Missing or invalid API key (send it in 'X-API-Key').")
        return principal

    def get_engagement(x_engagement: str = Header(default=""), principal=Depends(get_principal)):
        eid = (x_engagement or "default").strip()
        if eid == "default":
            eng = manager.default(scope_file, AUDIT_PATH)
        else:
            eng = manager.get(eid)
            if eng is None:
                raise HTTPException(404, f"engagement '{eid}' not found")
        if not principal.can_access(eng.id):
            raise HTTPException(403, f"principal not authorized for engagement '{eng.id}'")
        return eng

    def service_for(principal, eng) -> SpafService:
        return SpafService(scope_file=eng.scope_file, audit_path=eng.audit_path,
                           actor=principal.key_id, engagement=eng.id)

    def require(principal, role: Role) -> None:
        if not principal.has_role(role):
            raise HTTPException(403, f"role '{principal.role.label}' insufficient; "
                                     f"'{role.label}' or higher required.")

    def require_active_authorization(eng) -> None:
        """Active runs on a persisted engagement need a valid signed authorization
        once a signing key is configured."""
        if eng.id == "default" or not authorization.signing_configured():
            return
        if not manager.authorization_valid(eng):
            raise HTTPException(403, f"engagement '{eng.id}' has no valid signed "
                                     f"authorization for active testing.")

    def _record_scan(result: Dict[str, Any]) -> None:
        module = result.get("module", "unknown")
        if result.get("status") == "completed":
            metrics.inc("spaf_scans_completed_total", {"module": module})
        else:
            metrics.inc("spaf_scans_failed_total", {"module": module})
        for sev, n in (result.get("counts") or {}).items():
            if n:
                metrics.inc("spaf_findings_total", {"severity": sev}, n)

    # ── Open endpoints ────────────────────────────────────────────────
    @app.get("/health")
    async def health():
        return {"status": "ok", "version": _version()}

    @app.get("/version")
    async def version():
        return {"version": _version()}

    @app.get("/metrics")
    async def prometheus():
        return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.get("/", response_class=HTMLResponse)
    @app.get("/dashboard", response_class=HTMLResponse)
    async def dashboard():
        return HTMLResponse(_dashboard_html())

    # ── Identity ──────────────────────────────────────────────────────
    @app.get("/whoami")
    async def whoami(principal=Depends(get_principal)):
        return {"key_id": principal.key_id, "name": principal.name,
                "role": principal.role.label, "engagements": principal.engagements}

    # ── Engagements ───────────────────────────────────────────────────
    @app.get("/engagements")
    async def list_engagements(principal=Depends(get_principal)):
        out = []
        for e in manager.list():
            if principal.can_access(e.id):
                out.append({"id": e.id, "name": e.name, "created_at": e.created_at.isoformat(),
                            "authorized": manager.authorization_valid(e),
                            "retention_days": e.retention.days})
        return {"engagements": out}

    @app.post("/engagements", status_code=201)
    async def create_engagement(req: EngagementRequest, principal=Depends(get_principal)):
        require(principal, Role.LEAD)
        eng = manager.create(req.name, created_by=principal.key_id,
                             in_scope=req.in_scope, out_of_scope=req.out_of_scope,
                             retention_days=req.retention_days,
                             authorized_by=req.authorized_by or None)
        return {"id": eng.id, "name": eng.name, "scope_file": eng.scope_file,
                "authorized": manager.authorization_valid(eng)}

    # ── Scope & status (engagement-scoped) ────────────────────────────
    @app.get("/scope")
    async def get_scope(eng=Depends(get_engagement), principal=Depends(get_principal)):
        return service_for(principal, eng).scope_state().model_dump()

    @app.post("/scope")
    async def add_scope(req: ScopeAddRequest, eng=Depends(get_engagement),
                        principal=Depends(get_principal)):
        require(principal, Role.LEAD)
        return service_for(principal, eng).scope_add(req.value).model_dump()

    @app.get("/tools")
    async def tools(eng=Depends(get_engagement), principal=Depends(get_principal)):
        return {"tools": [t.model_dump() for t in service_for(principal, eng).tools_status()]}

    @app.get("/audit")
    async def audit(limit: int = 100, eng=Depends(get_engagement),
                   principal=Depends(get_principal)):
        return {"entries": _tail_audit(eng.audit_path, limit)}

    # ── Scans & agent (async jobs) ────────────────────────────────────
    @app.post("/scans", status_code=202)
    async def start_scan(req: ScanRequest, eng=Depends(get_engagement),
                        principal=Depends(get_principal)):
        require(principal, Role.OPERATOR)
        require_active_authorization(eng)
        svc = service_for(principal, eng)
        _ensure_in_scope(svc, req.target)
        metrics.inc("spaf_scans_started_total", {"module": req.module})

        async def run(bus: EventBus):
            r = await svc.run_module(req.module, req.target, req.options, bus=bus, surface="api")
            payload = r.model_dump(mode="json")
            _record_scan(payload)
            return payload

        job = jobs.start("scan", req.target, run)
        return {"job_id": job.id, "status": job.status}

    @app.post("/agent", status_code=202)
    async def start_agent(req: AgentRequest, eng=Depends(get_engagement),
                         principal=Depends(get_principal)):
        require(principal, Role.OPERATOR)
        svc = service_for(principal, eng)
        if not req.dry_run:
            require_active_authorization(eng)
            _ensure_in_scope(svc, req.target)
        metrics.inc("spaf_agent_runs_total", {"mode": "plan" if req.dry_run else "active"})

        async def run(bus: EventBus):
            r = await svc.run_agent(req.target, req.goal, dry_run=req.dry_run,
                                    aggressive=req.aggressive, bus=bus, surface="api")
            payload = r.model_dump(mode="json")
            for sev, n in (payload.get("counts") or {}).items():
                if n:
                    metrics.inc("spaf_findings_total", {"severity": sev}, n)
            return payload

        job = jobs.start("agent", req.target, run)
        return {"job_id": job.id, "status": job.status}

    @app.get("/jobs/{job_id}")
    async def get_job(job_id: str, principal=Depends(get_principal)):
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(404, "job not found")
        return {"job_id": job.id, "kind": job.kind, "target": job.target,
                "status": job.status, "result": job.result, "error": job.error}

    # ── Reads ─────────────────────────────────────────────────────────
    @app.get("/scans/recent")
    async def recent(target: Optional[str] = None, limit: int = 20,
                    eng=Depends(get_engagement), principal=Depends(get_principal)):
        svc = service_for(principal, eng)
        return {"scans": [s.model_dump(mode="json") for s in await svc.list_scans(target, limit)]}

    @app.get("/findings/{scan_id}")
    async def findings(scan_id: str, eng=Depends(get_engagement),
                      principal=Depends(get_principal)):
        svc = service_for(principal, eng)
        return {"findings": [f.model_dump() for f in await svc.get_findings(scan_id)]}

    # ── Live events ───────────────────────────────────────────────────
    @app.websocket("/ws/jobs/{job_id}")
    async def ws_job(ws: WebSocket, job_id: str):
        key = ws.query_params.get("api_key") or ws.headers.get("x-api-key", "")
        if app.state.principals.authenticate(key) is None:
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
            await ws.send_json({"kind": "done", "status": job.status, "error": job.error})
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


def _tail_audit(path: str, limit: int) -> list:
    if not path or not os.path.exists(path):
        return []
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()[-max(1, min(limit, 1000)):]
        out = []
        for ln in lines:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
        return list(reversed(out))
    except OSError:
        return []


def _dashboard_html() -> str:
    from importlib.resources import files
    return (files("spaf.api") / "static" / "dashboard.html").read_text(encoding="utf-8")


def _version() -> str:
    try:
        from spaf.cli.main import get_version
        return get_version()
    except Exception:
        return "0"
