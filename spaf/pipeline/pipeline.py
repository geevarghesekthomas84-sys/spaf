"""
Staged pipeline runner: discovery → validation → remediation → report.

Each stage is a pure-ish step with a strict interface — it takes the previous
stage's :class:`StageResult` (plus the target/options) and returns its own. The
runner owns ordering and the final aggregation; stages never see each other's
internals. Active module execution goes through :class:`SpafService.run_module`,
so scope, RBAC, audit, rate limiting, and **mock mode** all apply unchanged.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from spaf.service.events import Event, EventBus
from spaf.service.models import Finding, severity_counts
from spaf.pipeline.models import (
    PipelineResult, Stage, StageResult, STAGE_MODULES,
)


class Pipeline:
    def __init__(self, service, *, bus: Optional[EventBus] = None, surface: str = "pipeline"):
        self.svc = service
        self.bus = bus
        self.surface = surface

    # ── public entry point ────────────────────────────────────────────
    async def run(self, target: str, options: Optional[Dict[str, Any]] = None, *,
                  stages: Optional[List[Stage]] = None,
                  report_dir: Optional[str] = None) -> PipelineResult:
        options = dict(options or {})
        order = stages or [Stage.DISCOVERY, Stage.VALIDATION, Stage.REMEDIATION, Stage.REPORT]
        result = PipelineResult(target=target)

        for stage in order:
            self._emit("stage_started", stage)
            if stage == Stage.DISCOVERY:
                sr = await self._run_module_stage(Stage.DISCOVERY, target, options)
            elif stage == Stage.VALIDATION:
                sr = await self._run_module_stage(Stage.VALIDATION, target, options)
            elif stage == Stage.REMEDIATION:
                # Remediation enriches the full consolidated finding set produced
                # by discovery+validation — the pipeline's product, passed
                # explicitly (not another stage's internals).
                sr = self._remediate(result.findings)
            elif stage == Stage.REPORT:
                sr = self._report(target, result.findings, report_dir, options)
            else:  # pragma: no cover - guarded by enum
                continue
            result.stages.append(sr)
            # Accumulate findings from discovery/validation into the running set.
            if stage in (Stage.DISCOVERY, Stage.VALIDATION):
                result.findings = _dedupe(result.findings + sr.findings)
            elif stage == Stage.REMEDIATION:
                result.findings = sr.findings  # enriched consolidated set
            self._emit("stage_completed", stage, count=len(sr.findings))

        result.counts = severity_counts(result.findings)
        report = result.stage(Stage.REPORT)
        if report:
            result.report_path = report.meta.get("path")
        return result

    # ── stages ────────────────────────────────────────────────────────
    async def _run_module_stage(self, stage: Stage, target: str,
                                options: Dict[str, Any]) -> StageResult:
        """Discovery/validation: run this stage's allowed modules, collect findings."""
        findings: List[Finding] = []
        ran: List[str] = []
        errors: List[str] = []
        for module in STAGE_MODULES[stage]:
            try:
                scan = await self.svc.run_module(module, target, dict(options),
                                                 bus=self.bus, surface=self.surface)
                ran.append(module)
                if scan.status == "completed":
                    findings.extend(scan.findings)
                elif scan.error:
                    errors.append(f"{module}: {scan.error}")
            except Exception as exc:  # a module that can't run never sinks the stage
                errors.append(f"{module}: {exc}")
        status = "completed" if not errors or findings else ("failed" if not ran else "completed")
        return StageResult(
            stage=stage, status=status, findings=_dedupe(findings),
            summary=f"{len(findings)} finding(s) from {', '.join(ran) or 'no modules'}",
            error="; ".join(errors) or None, meta={"modules": ran},
        )

    def _remediate(self, findings: Optional[List[Finding]]) -> StageResult:
        """Attach remediation guidance to the consolidated findings. Touches no
        target — pure enrichment, and never mutates the inputs."""
        src = list(findings or [])
        enriched: List[Finding] = []
        added = 0
        for f in src:
            rec = f.recommendation.strip()
            if not rec:
                rec = _default_remediation(f.severity)
                added += 1
            enriched.append(f.model_copy(update={"recommendation": rec}))
        return StageResult(
            stage=Stage.REMEDIATION, findings=enriched,
            summary=f"remediation attached ({added} generated, {len(enriched) - added} from scanners)",
            meta={"generated": added},
        )

    def _report(self, target: str, findings: List[Finding],
                report_dir: Optional[str], options: Dict[str, Any]) -> StageResult:
        """Render a JSON deliverable from the final findings."""
        report_dir = report_dir or options.get("report_dir") or "reports"
        try:
            from spaf.reports.generator import ReportGenerator
            os.makedirs(report_dir, exist_ok=True)
            safe = target.replace("://", "_").replace("/", "_").replace(":", "_")
            path = os.path.join(report_dir, f"pipeline_{safe}.json")
            data = [f.model_dump() for f in findings]
            gen = ReportGenerator(target, data, meta={"source": "pipeline"})
            gen.generate_json(path)
            return StageResult(stage=Stage.REPORT, summary=f"report written: {path}",
                               meta={"path": path, "findings": len(findings)})
        except Exception as exc:
            return StageResult(stage=Stage.REPORT, status="failed", error=str(exc),
                               summary="report generation failed")

    # ── events ────────────────────────────────────────────────────────
    def _emit(self, kind: str, stage: Stage, **data: Any) -> None:
        if self.bus:
            self.bus.publish(Event(kind, module=stage.value, data=data or None))


def _dedupe(findings: List[Finding]) -> List[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.target, f.vuln_type, f.scan_type)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _default_remediation(severity: str) -> str:
    base = {
        "Critical": "Remediate immediately; isolate the affected asset until patched.",
        "High": "Prioritise remediation this cycle; apply vendor patches/config hardening.",
        "Medium": "Schedule remediation; validate configuration against the baseline.",
        "Low": "Track and remediate opportunistically.",
        "Info": "No action required; retain for context.",
    }
    return base.get(severity, base["Info"])
