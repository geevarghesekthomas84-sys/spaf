"""
Tiny in-process metrics in Prometheus text format — no extra dependency.

Only aggregate counters (no target names as labels), so `/metrics` is safe to
scrape without leaking engagement data.
"""

from collections import defaultdict
from threading import Lock
from typing import Dict, Optional, Tuple

_HELP = {
    "spaf_scans_started_total": "Scans started, by module.",
    "spaf_scans_completed_total": "Scans completed, by module.",
    "spaf_scans_failed_total": "Scans failed, by module.",
    "spaf_findings_total": "Findings produced, by severity.",
    "spaf_agent_runs_total": "Agent runs, by mode (plan|active).",
    "spaf_auth_failures_total": "Rejected requests (bad/missing API key).",
}


class Metrics:
    def __init__(self) -> None:
        self._c: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = defaultdict(float)
        self._lock = Lock()

    def inc(self, name: str, labels: Optional[Dict[str, str]] = None, amount: float = 1) -> None:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            self._c[key] += amount

    def render(self) -> str:
        lines = []
        emitted_help = set()
        with self._lock:
            items = sorted(self._c.items())
        for (name, labels), value in items:
            if name not in emitted_help:
                lines.append(f"# HELP {name} {_HELP.get(name, name)}")
                lines.append(f"# TYPE {name} counter")
                emitted_help.add(name)
            label_str = ""
            if labels:
                inner = ",".join(f'{k}="{v}"' for k, v in labels)
                label_str = "{" + inner + "}"
            lines.append(f"{name}{label_str} {value:g}")
        return "\n".join(lines) + "\n"
