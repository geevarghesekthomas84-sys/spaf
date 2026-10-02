"""
Shape service results into compact, LLM-friendly payloads.

A full scan can be thousands of findings; handing all of that to a model wastes
context. We return a severity summary, a capped+truncated finding list, and the
scan_id so the host can fetch the complete set from the `scan://` resource.
"""

from typing import Any, Dict

from spaf.service.models import AgentResult, ScanResult

MAX_FINDINGS = 40
MAX_DETAIL = 240


def _finding(f) -> Dict[str, Any]:
    detail = f.detail if len(f.detail) <= MAX_DETAIL else f.detail[:MAX_DETAIL] + "…"
    return {
        "target": f.target,
        "type": f.vuln_type,
        "severity": f.severity,
        "detail": detail,
        "recommendation": f.recommendation[:MAX_DETAIL],
    }


def scan_payload(r: ScanResult) -> Dict[str, Any]:
    shown = r.findings[:MAX_FINDINGS]
    return {
        "module": r.module,
        "target": r.target,
        "status": r.status,
        "error": r.error,
        "scan_id": r.scan_id,
        "counts": r.counts,
        "total_findings": len(r.findings),
        "showing": len(shown),
        "findings": [_finding(f) for f in shown],
        "note": (f"Showing {len(shown)} of {len(r.findings)}; full set at scan://{r.scan_id}"
                 if r.scan_id and len(r.findings) > len(shown) else None),
    }


def agent_payload(r: AgentResult) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "target": r.target,
        "goal": r.goal,
        "dry_run": r.dry_run,
        "plan": [{"module": s.module, "reason": s.reason, "scope_ok": s.scope_ok} for s in r.plan],
    }
    if not r.dry_run:
        shown = r.findings[:MAX_FINDINGS]
        out.update({
            "counts": r.counts,
            "total_findings": len(r.findings),
            "findings": [_finding(f) for f in shown],
            "assessment": r.assessment,
        })
    return out
