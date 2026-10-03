# SPAF architecture & extension guide

How SPAF is laid out, how a request flows through it, and the three seams where
you extend it (modules, AI providers, report/output consumers) without touching
the core.

## 1. Layers

SPAF is a layered system: every surface talks to one **service engine**, which
runs **modules**, which produce one typed **result contract**.

```
 surfaces        spaf/cli · spaf/api · spaf/mcp
                       │   (thin adapters — no business logic)
 engine          spaf/service (SpafService)  ·  spaf/core (ScanEngine)
                       │   scope · RBAC · audit · events · mock
 intelligence    spaf/agent · spaf/orchestration · spaf/utils/ai
                       │   plan → route → cache → budget → fallback
 modules         spaf/modules/*  (recon · network · webscan · crawler · toolkit)
                       │   + spaf/plugins (third-party modules)
 contract        spaf/service/models.py  →  spaf/service/schema.py (JSON Schema)
 storage         spaf/database (mongo | sqlite) · spaf/reports · audit JSONL
 governance      spaf/workspaces (engagements · roles · signed authorizations)
```

**Rule:** surfaces never contain business logic — they parse input, call the
service, and format output. The service is the only place scope, RBAC, audit, and
mock mode are enforced, so every surface inherits them identically.

## 2. Request flow (a scan)

```
client ─▶ surface ─▶ validate input (utils/validator)
        ─▶ SpafService.run_module
             ├─ mock? ──────────────▶ synthetic result (no target touched)
             ├─ overly-broad target? ▶ reject (InputError)
             ├─ scope check ─────────▶ reject if out of engagement scope
             ├─ audit record (who/what/target/when)
             ├─ resolve module (built-in MODULE_MAP or plugin registry)
             ├─ module.run(progress) ─▶ raw findings
             ├─ Finding.from_dict × N ─▶ typed ScanResult
             ├─ persist (optional) + emit events on the EventBus
             └─ return ScanResult  ──▶ surface formats (Rich / JSON / WS)
```

The **agent** (`spaf/agent`) sits above this: it asks the orchestrator to *plan*
an ordered list of module steps from a fixed, safe action set, then executes each
step through the same `run_module` path — so planning is the only AI-driven part;
execution is deterministic and governed.

## 3. The result contract

`spaf/service/models.py` defines the Pydantic models every surface returns
(`Finding`, `ScanResult`, `AgentResult`, …). `spaf/service/schema.py` emits their
**JSON Schema** (`spaf schema`, `GET /schema`, and the checked-in
[`schemas/`](schemas/)) so external consumers validate SPAF output instead of
guessing. Change a model → regenerate schemas with `spaf schema --write docs/schemas`.

## 4. Extension points

### a. Add a scan module
Subclass `BaseModule` (or `PluginModule`) and advertise it on the `spaf.modules`
entry-point group, or register it in-process:

```python
from spaf.plugins import spaf_module, PluginModule

@spaf_module("myscan")
class MyScanModule(PluginModule):
    async def run(self, progress):
        return [ { "target": self.target, "vuln_type": "...", "severity": "Info",
                   "recommendation": "...", "scan_type": "myscan" } ]
```

Return dicts in the `build_finding` shape; the service converts them to typed
`Finding`s. Registered modules run through CLI/API/MCP automatically. They are
**deliberately not** added to the agent's fixed action set (that stays curated).

### b. Add an AI provider
Providers live behind `spaf/utils/ai.py` (`complete(system, prompt, *, model=)`),
normalised in `_normalise_provider`. The orchestrator (`spaf/orchestration`) adds
routing, caching, budgets, and a fallback chain on top — so a new provider is one
branch in the provider abstraction, and routing/limits come for free.

### c. Consume output
Read the typed models or the JSON Schema. Live runs stream `Event`s over the
`EventBus` (`/ws/jobs/{id}`); finished runs expose `ScanResult`/`AgentResult`
(REST + MCP). Reports render from the same findings via `spaf/reports`.

## 5. Governance & safety seams

- **Scope** (`utils/scope.py`) and **signed authorizations** (`workspaces/`) gate
  *whether* a target may be touched.
- **RBAC** (`workspaces/principals.py`) gates *who* may do it.
- **Input validation** + **rate limiting** + **command/output safety**
  (`utils/validator.py`, `api/ratelimit.py`, `utils/safety.py`) bound *how much*
  and *how safely*.
- **Audit** (`service/audit.py`) records *what happened*.

See [`THREAT_MODEL.md`](THREAT_MODEL.md) for the per-workflow risk classification,
and [`DESIGN_SERVICE_MCP.md`](DESIGN_SERVICE_MCP.md) for the service/MCP design notes.
