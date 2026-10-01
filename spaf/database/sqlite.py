"""
SQLite storage backend — a zero-setup offline fallback for MongoDB.

Implements the same async surface as ``spaf.database.mongo.MongoDB`` so the rest
of SPAF can use it interchangeably (see ``spaf.database`` for backend selection).
All blocking sqlite3 calls are offloaded to a thread so they don't block the
asyncio event loop. Findings are stored as JSON blobs to preserve every field,
with a few indexed columns for querying and dedup.
"""

import asyncio
import json
import os
import sqlite3
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from spaf.utils.logger import logger

DEFAULT_SQLITE_PATH = os.getenv("SPAF_SQLITE_PATH", "spaf.db")


def _new_id() -> str:
    return uuid.uuid4().hex


class SQLiteDB:
    def __init__(self, path: str = DEFAULT_SQLITE_PATH):
        self.path = path
        self._initialized = False

    # ------------------------------------------------------------------
    # Connection / schema
    # ------------------------------------------------------------------
    async def connect(self):
        await asyncio.to_thread(self._connect_sync)
        self._initialized = True
        logger.info(f"Using SQLite database at {os.path.abspath(self.path)}")

    def _connect_sync(self):
        con = self._con()
        try:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id             TEXT PRIMARY KEY,
                    target         TEXT,
                    type           TEXT,
                    status         TEXT,
                    options        TEXT,
                    started_at     TEXT,
                    completed_at   TEXT,
                    findings_count INTEGER DEFAULT 0,
                    error          TEXT
                );
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id             TEXT PRIMARY KEY,
                    scan_id        TEXT,
                    target         TEXT,
                    vuln_type      TEXT,
                    severity_order INTEGER,
                    created_at     TEXT,
                    updated_at     TEXT,
                    data           TEXT,
                    UNIQUE(scan_id, vuln_type, target)
                );
                CREATE INDEX IF NOT EXISTS idx_scans_target   ON scans(target, started_at);
                CREATE INDEX IF NOT EXISTS idx_vulns_target   ON vulnerabilities(target, created_at);
                CREATE INDEX IF NOT EXISTS idx_vulns_scan     ON vulnerabilities(scan_id);
                """
            )
            con.commit()
        finally:
            con.close()

    def _con(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------
    async def create_scan(self, target: str, scan_type: str, options: Dict[str, Any]) -> str:
        scan_id = _new_id()

        def _run():
            con = self._con()
            try:
                con.execute(
                    "INSERT INTO scans (id, target, type, status, options, started_at, "
                    "completed_at, findings_count, error) VALUES (?,?,?,?,?,?,?,?,?)",
                    (scan_id, target, scan_type, "running",
                     json.dumps(options, default=str), datetime.utcnow().isoformat(),
                     None, 0, None),
                )
                con.commit()
            finally:
                con.close()

        await asyncio.to_thread(_run)
        return scan_id

    async def complete_scan(self, scan_id: str, findings_count: int):
        def _run():
            con = self._con()
            try:
                con.execute(
                    "UPDATE scans SET status=?, completed_at=?, findings_count=? WHERE id=?",
                    ("completed", datetime.utcnow().isoformat(), findings_count, scan_id),
                )
                con.commit()
            finally:
                con.close()

        await asyncio.to_thread(_run)

    async def fail_scan(self, scan_id: str, error: str):
        def _run():
            con = self._con()
            try:
                con.execute(
                    "UPDATE scans SET status=?, completed_at=?, error=? WHERE id=?",
                    ("failed", datetime.utcnow().isoformat(), error, scan_id),
                )
                con.commit()
            finally:
                con.close()

        await asyncio.to_thread(_run)

    async def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        def _run():
            con = self._con()
            try:
                row = con.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
                return self._scan_row(row) if row else None
            finally:
                con.close()

        return await asyncio.to_thread(_run)

    async def get_scan_meta(self, scan_id: str) -> Optional[Dict[str, Any]]:
        return await self.get_scan(scan_id)

    async def get_scan_history(self, target: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        def _run():
            con = self._con()
            try:
                if target:
                    rows = con.execute(
                        "SELECT * FROM scans WHERE target=? ORDER BY started_at DESC LIMIT ?",
                        (target, limit),
                    ).fetchall()
                else:
                    rows = con.execute(
                        "SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (limit,)
                    ).fetchall()
                return [self._scan_row(r) for r in rows]
            finally:
                con.close()

        return await asyncio.to_thread(_run)

    async def get_scan_ids_for_target(self, target: str, limit: int = 50) -> List[str]:
        scans = await self.get_scan_history(target, limit)
        return [s["_id"] for s in scans]

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------
    async def upsert_vulnerability(self, scan_id: str, vuln_dict: Dict[str, Any]):
        now = datetime.utcnow().isoformat()
        record = dict(vuln_dict)
        record["scan_id"] = scan_id
        record["updated_at"] = now
        record.setdefault("created_at", now)
        target = record.get("target", "")
        vuln_type = record.get("vuln_type", "")
        sev_order = record.get("severity_order", 99)

        def _run():
            con = self._con()
            try:
                existing = con.execute(
                    "SELECT id, created_at FROM vulnerabilities "
                    "WHERE scan_id=? AND vuln_type=? AND target=?",
                    (scan_id, vuln_type, target),
                ).fetchone()
                if existing:
                    record["created_at"] = existing["created_at"]
                    con.execute(
                        "UPDATE vulnerabilities SET severity_order=?, updated_at=?, data=? WHERE id=?",
                        (sev_order, now, json.dumps(record, default=str), existing["id"]),
                    )
                else:
                    con.execute(
                        "INSERT INTO vulnerabilities (id, scan_id, target, vuln_type, "
                        "severity_order, created_at, updated_at, data) VALUES (?,?,?,?,?,?,?,?)",
                        (_new_id(), scan_id, target, vuln_type, sev_order,
                         record["created_at"], now, json.dumps(record, default=str)),
                    )
                con.commit()
            finally:
                con.close()

        await asyncio.to_thread(_run)

    async def get_vulnerabilities_for_scan(self, scan_id: str) -> List[Dict[str, Any]]:
        def _run():
            con = self._con()
            try:
                rows = con.execute(
                    "SELECT id, data FROM vulnerabilities WHERE scan_id=? ORDER BY severity_order ASC",
                    (scan_id,),
                ).fetchall()
                return [self._vuln_row(r) for r in rows]
            finally:
                con.close()

        return await asyncio.to_thread(_run)

    async def get_all_vulnerabilities_for_target(self, target: str) -> List[Dict[str, Any]]:
        def _run():
            con = self._con()
            try:
                # Latest finding per vuln_type for this target, severity-sorted.
                rows = con.execute(
                    "SELECT id, data, created_at, severity_order, vuln_type "
                    "FROM vulnerabilities WHERE target=? ORDER BY created_at DESC",
                    (target,),
                ).fetchall()
                seen = {}
                for r in rows:
                    vt = r["vuln_type"]
                    if vt not in seen:
                        seen[vt] = self._vuln_row(r)
                results = list(seen.values())
                results.sort(key=lambda x: x.get("severity_order", 99))
                return results
            finally:
                con.close()

        return await asyncio.to_thread(_run)

    async def get_all_vulnerabilities_for_export(self, target: str) -> List[Dict[str, Any]]:
        return await self.get_all_vulnerabilities_for_target(target)

    async def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        def _run():
            con = self._con()
            try:
                row = con.execute(
                    "SELECT id, data FROM vulnerabilities WHERE id=?", (finding_id,)
                ).fetchone()
                return self._vuln_row(row) if row else None
            finally:
                con.close()

        return await asyncio.to_thread(_run)

    # ------------------------------------------------------------------
    # Row helpers
    # ------------------------------------------------------------------
    def _scan_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        d["_id"] = d.pop("id")
        if d.get("options"):
            try:
                d["options"] = json.loads(d["options"])
            except (TypeError, json.JSONDecodeError):
                pass
        # MongoDB returns native datetimes; mirror that so callers that call
        # .strftime() on these fields work identically across backends.
        for field in ("started_at", "completed_at"):
            if isinstance(d.get(field), str):
                try:
                    d[field] = datetime.fromisoformat(d[field])
                except ValueError:
                    pass
        return d

    def _vuln_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        try:
            data = json.loads(row["data"])
        except (TypeError, json.JSONDecodeError):
            data = {}
        data["_id"] = row["id"]
        return data


# Single instance for the application (path from SPAF_SQLITE_PATH).
db = SQLiteDB()
