"""
Typed contract for the staged pipeline.

The pipeline runs four ordered stages — **discovery → validation → remediation →
report** — with *strict* hand-offs: each stage receives only the previous stage's
:class:`StageResult`, never another stage's internals, so there is no cross-stage
data leakage. Every stage speaks the same shared :class:`Finding` type.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from spaf.service.models import Finding


class Stage(str, Enum):
    DISCOVERY = "discovery"      # find assets/endpoints (recon, toolkit, crawl)
    VALIDATION = "validation"    # confirm & classify (webscan, network/CVE)
    REMEDIATION = "remediation"  # attach fix guidance (no target contact)
    REPORT = "report"            # render the deliverable


# The modules each stage is allowed to invoke. Deliberately fixed, so a stage
# cannot reach outside its remit (e.g. discovery can never launch a network scan).
STAGE_MODULES: Dict[Stage, List[str]] = {
    Stage.DISCOVERY: ["recon", "toolkit", "crawl"],
    Stage.VALIDATION: ["webscan", "scan"],
}


class StageResult(BaseModel):
    stage: Stage
    status: str = "completed"          # completed | failed | skipped
    findings: List[Finding] = Field(default_factory=list)
    summary: str = ""
    error: Optional[str] = None
    # Stage-scoped metadata (e.g. which modules ran); never another stage's state.
    meta: Dict[str, Any] = Field(default_factory=dict)


class PipelineResult(BaseModel):
    target: str
    stages: List[StageResult] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)   # final, deduped
    counts: Dict[str, int] = Field(default_factory=dict)
    report_path: Optional[str] = None

    def stage(self, s: Stage) -> Optional[StageResult]:
        for r in self.stages:
            if r.stage == s:
                return r
        return None
