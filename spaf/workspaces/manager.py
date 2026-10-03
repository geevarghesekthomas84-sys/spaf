"""
EngagementManager — create, list, and resolve isolated engagement workspaces.

Each engagement lives in its own directory under the engagements base
(``SPAF_ENGAGEMENTS_DIR``, default ``./engagements``)::

    engagements/<id>/
        engagement.json     # metadata + signed authorization + retention
        scope.json          # this engagement's scope (isolated)
        audit.jsonl         # this engagement's audit trail (isolated)
        reports/            # per-engagement report output

Two engagements never share scope or audit state, so work in one cannot leak
into another. A *default* engagement can be resolved without persisting anything
(it reuses a caller-provided scope/audit path), which keeps the single-engagement
API path backwards-compatible.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from datetime import datetime
from typing import List, Optional

from spaf.utils.logger import logger
from spaf.workspaces import authorization as authz
from spaf.workspaces.models import (
    Engagement, EngagementAuthorization, RetentionPolicy,
)

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(name: str) -> str:
    slug = _SLUG_RE.sub("-", name.strip().lower()).strip("-")
    return slug or "engagement"


def base_dir() -> str:
    return os.getenv("SPAF_ENGAGEMENTS_DIR", "engagements")


class EngagementManager:
    def __init__(self, root: Optional[str] = None):
        self.root = root or base_dir()

    # ------------------------------------------------------------------
    def _dir(self, engagement_id: str) -> str:
        return os.path.join(self.root, engagement_id)

    def _meta_path(self, engagement_id: str) -> str:
        return os.path.join(self._dir(engagement_id), "engagement.json")

    def _unique_id(self, name: str) -> str:
        base = _slugify(name)
        eid, n = base, 2
        while os.path.exists(self._dir(eid)):
            eid, n = f"{base}-{n}", n + 1
        return eid

    # ------------------------------------------------------------------
    def create(self, name: str, *, created_by: str = "local",
               in_scope: Optional[List[str]] = None,
               out_of_scope: Optional[List[str]] = None,
               retention_days: int = 0,
               authorized_by: Optional[str] = None,
               expires_at: Optional[datetime] = None) -> Engagement:
        eid = self._unique_id(name)
        d = self._dir(eid)
        os.makedirs(os.path.join(d, "reports"), exist_ok=True)

        scope_file = os.path.join(d, "scope.json")
        with open(scope_file, "w", encoding="utf-8") as fh:
            json.dump({"in_scope": list(in_scope or []),
                       "out_of_scope": list(out_of_scope or [])}, fh, indent=2)

        auth: Optional[EngagementAuthorization] = None
        if authorized_by:
            auth = authz.sign(eid, authorized_by,
                              authz.scope_hash(in_scope or [], out_of_scope or []),
                              expires_at=expires_at)

        eng = Engagement(
            id=eid, name=name, created_by=created_by,
            scope_file=scope_file,
            audit_path=os.path.join(d, "audit.jsonl"),
            storage_dir=d,
            authorization=auth,
            retention=RetentionPolicy(days=max(0, retention_days)),
        )
        self._write(eng)
        logger.info(f"engagement created: {eid} (by {created_by})")
        return eng

    def _write(self, eng: Engagement) -> None:
        with open(self._meta_path(eng.id), "w", encoding="utf-8") as fh:
            fh.write(eng.model_dump_json(indent=2))

    # ------------------------------------------------------------------
    def get(self, engagement_id: str) -> Optional[Engagement]:
        path = self._meta_path(engagement_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                return Engagement.model_validate_json(fh.read())
        except (OSError, ValueError) as exc:
            logger.warning(f"engagement {engagement_id}: unreadable metadata ({exc}).")
            return None

    def list(self) -> List[Engagement]:
        if not os.path.isdir(self.root):
            return []
        out: List[Engagement] = []
        for entry in sorted(os.listdir(self.root)):
            if os.path.exists(self._meta_path(entry)):
                eng = self.get(entry)
                if eng:
                    out.append(eng)
        return out

    def exists(self, engagement_id: str) -> bool:
        return os.path.exists(self._meta_path(engagement_id))

    # ------------------------------------------------------------------
    def default(self, scope_file: str, audit_path: str) -> Engagement:
        """A non-persisted engagement reusing caller-provided paths.

        Keeps the single-engagement API path working unchanged: when no explicit
        engagement is selected, this stands in with id ``default``.
        """
        return Engagement(
            id="default", name="default", created_by="local",
            scope_file=scope_file, audit_path=audit_path,
            storage_dir=os.path.dirname(audit_path) or ".",
        )

    def authorization_valid(self, eng: Engagement) -> bool:
        """True if the stored authorization signature verifies and is unexpired."""
        if eng.authorization is None:
            return False
        return authz.verify(eng.id, eng.authorization)

    # ------------------------------------------------------------------
    def purge_expired(self, engagement_id: str, *, now: Optional[datetime] = None) -> int:
        """Delete report files older than the retention cutoff. Returns count removed."""
        eng = self.get(engagement_id)
        if not eng:
            return 0
        cutoff = eng.retention.cutoff(now)
        if cutoff is None:
            return 0
        reports = os.path.join(eng.storage_dir, "reports")
        if not os.path.isdir(reports):
            return 0
        removed = 0
        for fname in os.listdir(reports):
            fp = os.path.join(reports, fname)
            try:
                if datetime.utcfromtimestamp(os.path.getmtime(fp)) < cutoff:
                    (shutil.rmtree(fp) if os.path.isdir(fp) else os.remove(fp))
                    removed += 1
            except OSError:
                continue
        return removed
