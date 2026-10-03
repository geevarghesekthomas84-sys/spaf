"""
Machine-readable JSON Schema for SPAF's result contract.

Every surface (CLI/API/MCP) returns the same Pydantic models; this exposes their
**JSON Schema** so downstream tooling — SIEMs, dashboards, ticketing, other
agents — can validate and consume SPAF output without reverse-engineering it.

``build_schemas()`` returns ``{name: schema}``; ``write_schemas(dir)`` writes one
``<name>.schema.json`` per model plus a combined ``spaf.schema.json``. The CLI
exposes this as ``spaf schema``.
"""

from __future__ import annotations

import json
import os
from typing import Dict

from spaf.service.models import (
    AgentPlanStep, AgentResult, Finding, ScanResult, ScanSummary,
    ScopeState, ToolStatus,
)

# The public, documented result models (inputs are validated separately).
SCHEMA_MODELS = {
    "Finding": Finding,
    "ScanResult": ScanResult,
    "AgentPlanStep": AgentPlanStep,
    "AgentResult": AgentResult,
    "ScanSummary": ScanSummary,
    "ToolStatus": ToolStatus,
    "ScopeState": ScopeState,
}


def build_schemas() -> Dict[str, dict]:
    """Return {model_name: json_schema_dict} for every public result model."""
    return {name: model.model_json_schema() for name, model in SCHEMA_MODELS.items()}


def combined_schema() -> dict:
    """A single document with every model under ``$defs``."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SPAF result contract",
        "description": "JSON Schema for every SPAF result model (CLI/API/MCP).",
        "$defs": build_schemas(),
    }


def write_schemas(out_dir: str) -> list[str]:
    """Write one file per model plus a combined document. Returns written paths."""
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, schema in build_schemas().items():
        path = os.path.join(out_dir, f"{name}.schema.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(schema, fh, indent=2, sort_keys=True)
            fh.write("\n")
        written.append(path)
    combined = os.path.join(out_dir, "spaf.schema.json")
    with open(combined, "w", encoding="utf-8") as fh:
        json.dump(combined_schema(), fh, indent=2, sort_keys=True)
        fh.write("\n")
    written.append(combined)
    return written
