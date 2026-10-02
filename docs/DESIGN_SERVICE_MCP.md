# Design spec — Phase 0 (service layer) + minimal Phase 2 (MCP server)

Detailed, build-ready design for the first v2 slice. No code yet — this is the
contract we implement against. Built with the `mcp-builder` skill at code time.

Goal of this slice: **SPAF runs as a local MCP server that Claude Desktop (or any
MCP host) can drive — scope-gated, headless, tested** — on top of a clean,
CLI-independent service layer.

---

## A. Phase 0 — the service layer

### Why
Today the engine renders with Rich and the agent/CLI are intertwined. The API
and MCP server both need to call SPAF *headlessly* and get *typed* results +
*events*. So we carve out a thin, UI-free facade.

### New package: `spaf/service/`
```
spaf/service/
  __init__.py        # exports SpafService, EventBus, models
  models.py          # Pydantic v2 models (the shared contract)
  events.py          # EventBus (async pub/sub) + Event types
  service.py         # SpafService facade over engine/agent/scope/db
```

### Models (`models.py`) — the one contract for CLI/API/MCP
- `Finding` — target, vuln_type, detail, severity, severity_order, cvss_range,
  recommendation, scan_type, extra, discovered_at. (Mirrors `build_finding`.)
- `ScanRequest` — module, target, options (typed per module later).
- `ScanResult` — scan_id, module, target, started_at, completed_at, status,
  findings: list[Finding], severity_counts.
- `AgentPlanStep` — module, reason, scope_ok.
- `AgentResult` — target, goal, plan: list[AgentPlanStep], findings, assessment?.
- `ScopeEntry`, `ToolStatus`, `ScanSummary` (for listings).

All severity/ordering reuse `spaf.utils.risk`.

### EventBus (`events.py`)
Async pub/sub so a run emits progress without knowing who's listening.
- Event types: `run_started`, `step_started`, `step_progress(pct, note)`,
  `finding(Finding)`, `step_completed`, `run_completed(ScanResult)`,
  `run_failed(error)`.
- `EventBus.subscribe() -> async iterator`; `publish(event)`.
- Consumers: the **CLI** (renders via the existing `ui` design system), the
  **API** (WebSocket), the **MCP server** (progress notifications).

### SpafService (`service.py`) — the facade
Async, UI-free, returns models, emits events, enforces scope + audit centrally.
```python
class SpafService:
    async def run_module(self, module: str, target: str, options: dict,
                         bus: EventBus | None = None) -> ScanResult
    async def run_agent(self, target: str, goal: str = "", *, dry_run=False,
                        aggressive=False, bus=None) -> AgentResult
    async def plan_agent(self, target, goal="") -> list[AgentPlanStep]
    async def list_scans(self, target=None, limit=20) -> list[ScanSummary]
    async def get_findings(self, target_or_scan: str) -> list[Finding]
    async def generate_report(self, target, fmt="html", with_ai=False) -> str  # path
    # scope
    def scope_show(self, path="scope.json") -> dict
    def scope_add(self, value, path="scope.json") -> dict
    def is_allowed(self, target, path="scope.json") -> bool
    # tools
    def tools_status(self) -> list[ToolStatus]
```

### Refactor strategy (low risk)
- `ScanEngine.run_module` gains an optional `bus` param; when present it
  publishes events instead of (or alongside) Rich rendering. CLI keeps current
  look by subscribing and rendering through `ui`.
- `PentestAgent` already separates `plan/execute/summarize`; `run_agent` wraps it.
- No behavior change to the CLI; covered by existing tests + new service tests.

### Audit (lightweight, lands now)
- `spaf/service/audit.py` appends a JSONL record for every **active** action
  (who=operator/local, action, module, target, scope_ok, ts). Written to
  `./logs/audit.jsonl` (configurable). The MCP/API paths always audit; CLI opt-in.

### Acceptance (Phase 0)
- CLI output identical to today (spot-checked).
- `pytest` drives a scan through `SpafService` and receives a typed `ScanResult`
  plus an ordered event stream; `run_agent(dry_run=True)` returns a plan.
- No new runtime dependency (Pydantic already transitive via FastAPI later; add
  `pydantic>=2` to core).

---

## B. Phase 2 (minimal) — the MCP server

### Transport
- **stdio first** (what Claude Desktop launches). Streamable-HTTP/SSE is Phase 2.5
  and goes behind the gateway with auth — explicitly out of scope here.

### Package
```
spaf/mcp/
  __init__.py
  server.py          # builds the MCP server (FastMCP), registers tools/resources/prompts
  shaping.py         # LLM-friendly output shaping (summaries, caps, truncation)
```
Launched by a new CLI command: `spaf mcp` (stdio).

### Tools (model-callable) — all go through `SpafService`, all scope-gated
| Tool | Input | Returns (to the model) |
|---|---|---|
| `recon` | target, passive=true | severity summary + top findings; full set as a resource |
| `toolkit` | target, stages?, nuclei_severity? | summary + findings; resource link |
| `scan` | target, ports?, intensity? | open ports + CVEs summary |
| `webscan` | url | web findings summary |
| `crawl` | url, depth? | endpoints/forms summary |
| `agent_run` | target, goal?, dry_run=true default | the plan; findings+assessment when not dry_run |
| `scope_show` | — | current in/out-of-scope lists |
| `scope_add` | value | updated scope |
| `tools_status` | — | which external binaries are installed |
| `report_generate` | target, fmt=html, with_ai? | path/resource to the report |

### Resources (model-readable, not actions)
- `scan://{scan_id}` → full findings JSON for a run.
- `report://{target}/{fmt}` → generated report artifact.
- `scans://recent` → recent scan summaries.

### Prompts (reusable templates)
- `analyze_recon`, `analyze_web`, `analyze_network` — the existing module
  analysis templates, exposed so a host can invoke them on findings.

### Progress for long scans
- Tools run to completion but stream **MCP progress notifications** from the
  EventBus (`step_progress`, `finding`) so the host shows live status. (Job-id
  async mode is a later enhancement with the HTTP transport.)

### Safety model (critical — a model is calling these)
- **Scope is enforced inside every active tool.** Out-of-scope target → the tool
  returns a structured error: *"<target> is out of engagement scope; call
  scope_add first (authorized targets only)."* No bypass flag is exposed over
  MCP, so a model cannot disable scope. The human operator sets scope via
  `scope_add` or the CLI.
- **`agent_run` defaults to `dry_run=true`** (plan only). Running active steps
  requires `dry_run=false` *and* an in-scope target. Document that the operator
  owns authorization.
- **No raw-command tool.** The model only selects from SPAF's fixed modules —
  never arbitrary shell. (Same principle as the existing agent.)
- Every active tool call writes an **audit** record.
- Output shaping caps finding counts / truncates details so a huge scan can't
  blow the context window; full data via the `scan://` resource.

### Packaging
- New extra: **`spaf[mcp]`** → depends on `mcp` (official SDK).
- `spaf mcp` command (guarded import; friendly error if extra not installed).
- Docs include a copy-paste **Claude Desktop** config:
  ```json
  {
    "mcpServers": {
      "spaf": { "command": "spaf", "args": ["mcp"] }
    }
  }
  ```

### Tests
- Service facade: module run → typed result + events; scope gating.
- MCP tools: input-schema validation; each active tool refuses out-of-scope;
  `agent_run` dry-run returns a plan; output shaping caps results. (Engine calls
  mocked so tests need no network/binaries — same pattern as `tests/test_*`.)

### Acceptance (minimal Phase 2)
- `spaf mcp` starts a stdio server.
- Added to Claude Desktop, the host lists SPAF's tools; "recon example.com and
  summarize" calls `recon` (after `scope_add example.com`) and returns a summary;
  an out-of-scope target is refused with the scope message.
- CI runs the new tests under the `mcp` extra.

---

## C. Versioning & rollout
- This slice ships as **`2.0.0a1`** (PyPI pre-release) — installable with
  `pip install --pre "spaf[mcp]"`, so `1.4.x` users are undisturbed.
- `main` stays green; the CLI is unchanged for existing users.

---

## D. Decisions to confirm before coding
1. **Agent over MCP:** default `agent_run` to **plan-only (dry_run)**, requiring
   an explicit `dry_run=false` for active execution? (Recommended: yes — safest.)
2. **Scan concurrency over MCP:** run tools **synchronously with progress**
   now (simpler), and add job-id/async with the HTTP transport later? (Recommended: yes.)
3. **Version:** ship as **`2.0.0a1` pre-release** on PyPI vs. a `1.5.0` feature
   release? (Recommended: `2.0.0a1` to signal the platform shift.)
4. **Pydantic in core:** add `pydantic>=2` to core deps (it's small and becomes
   the shared contract), or keep it under the `mcp`/`api` extras? (Recommended: core.)

Once these are confirmed, implementation order: `service/models` → `events` →
`service` + engine `bus` hook → CLI wiring (no visual change) → `mcp/server` →
`spaf mcp` → docs + tests → `2.0.0a1`.
