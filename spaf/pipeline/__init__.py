"""Staged pipeline: discovery → validation → remediation → report."""

from spaf.pipeline.models import PipelineResult, Stage, StageResult, STAGE_MODULES
from spaf.pipeline.pipeline import Pipeline

__all__ = [
    "Pipeline", "PipelineResult", "Stage", "StageResult", "STAGE_MODULES",
]
