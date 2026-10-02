"""
Shared typed contract for CLI / API / MCP.

These Pydantic models are the one data shape every surface speaks. They mirror
the dicts produced by `spaf.utils.risk.build_finding` and the engine, so the
service can hand back typed objects without changing module internals.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


class Finding(BaseModel):
    target: str
    vuln_type: str
    detail: str = ""
    severity: str = "Info"
    severity_order: int = 5
    recommendation: str = ""
    scan_type: str = ""
    extra: Dict[str, Any] = Field(default_factory=dict)
    discovered_at: Optional[str] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        return cls(
            target=str(d.get("target", "")),
            vuln_type=str(d.get("vuln_type", "")),
            detail=str(d.get("detail", "")),
            severity=str(d.get("severity", "Info")),
            severity_order=int(d.get("severity_order", 5)),
            recommendation=str(d.get("recommendation", "")),
            scan_type=str(d.get("scan_type", "")),
            extra=d.get("extra", {}) or {},
            discovered_at=d.get("discovered_at"),
        )


def severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


class ScanResult(BaseModel):
    scan_id: Optional[str] = None
    module: str
    target: str
    status: str = "completed"
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    findings: List[Finding] = Field(default_factory=list)
    counts: Dict[str, int] = Field(default_factory=dict)
    error: Optional[str] = None


class AgentPlanStep(BaseModel):
    module: str
    reason: str = ""
    scope_ok: bool = True


class AgentResult(BaseModel):
    target: str
    goal: str = ""
    dry_run: bool = True
    plan: List[AgentPlanStep] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    counts: Dict[str, int] = Field(default_factory=dict)
    assessment: Optional[str] = None


class ScanSummary(BaseModel):
    scan_id: str
    target: str
    module: str
    status: str = ""
    findings_count: int = 0
    started_at: Optional[datetime] = None


class ToolStatus(BaseModel):
    name: str
    installed: bool
    role: str = ""
    url: str = ""


class ScopeState(BaseModel):
    in_scope: List[str] = Field(default_factory=list)
    out_of_scope: List[str] = Field(default_factory=list)
    enforced: bool = False
