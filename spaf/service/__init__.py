"""SPAF service layer — the typed, UI-free facade shared by CLI, API, and MCP."""

from spaf.service.events import Event, EventBus
from spaf.service.models import (
    AgentPlanStep, AgentResult, Finding, ScanResult, ScanSummary,
    ScopeState, ToolStatus,
)
from spaf.service.service import SpafService, ScopeError, MODULE_MAP

__all__ = [
    "SpafService", "ScopeError", "MODULE_MAP",
    "Event", "EventBus",
    "Finding", "ScanResult", "AgentPlanStep", "AgentResult",
    "ScanSummary", "ToolStatus", "ScopeState",
]
