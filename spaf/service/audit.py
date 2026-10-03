"""
Append-only audit trail for active actions.

Every scan/agent action taken through the service (and therefore through the API
and MCP) is recorded as one JSON line: who, what, target, whether it was in
scope, and when. This is the accountability record for engagements and the thing
that lets an operator prove what a model was allowed to do.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, Optional

from spaf.utils.logger import logger

AUDIT_PATH = os.getenv("SPAF_AUDIT_LOG", os.path.join("logs", "audit.jsonl"))


def record(action: str, target: str, *, actor: str = "local",
           scope_ok: Optional[bool] = None, surface: str = "service",
           engagement: Optional[str] = None,
           extra: Optional[Dict[str, Any]] = None,
           path: Optional[str] = None) -> None:
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "actor": actor,
        "surface": surface,
        "action": action,
        "target": target,
        "scope_ok": scope_ok,
        **({"engagement": engagement} if engagement else {}),
        **(extra or {}),
    }
    dest = path or AUDIT_PATH
    try:
        os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
        with open(dest, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as exc:
        logger.warning(f"audit: could not write {dest}: {exc}")
