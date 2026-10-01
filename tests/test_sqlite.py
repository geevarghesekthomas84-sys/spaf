import asyncio
from datetime import datetime

from spaf.database.sqlite import SQLiteDB


def _finding(vuln_type="missing_hsts", detail="x", sev="High", order=2):
    return {
        "target": "example.com", "vuln_type": vuln_type, "detail": detail,
        "severity": sev, "severity_order": order, "recommendation": "fix",
        "scan_type": "webscan", "discovered_at": "2026-01-01", "created_at": "2026-01-01",
    }


def _db(tmp_path):
    db = SQLiteDB(str(tmp_path / "t.db"))
    asyncio.run(db.connect())
    return db


def test_create_and_complete_scan(tmp_path):
    db = _db(tmp_path)

    async def run():
        sid = await db.create_scan("example.com", "toolkit", {"a": 1})
        assert isinstance(sid, str) and sid
        await db.complete_scan(sid, 3)
        meta = await db.get_scan_meta(sid)
        assert meta["status"] == "completed"
        assert meta["findings_count"] == 3
        # Dates come back as datetime objects, matching the Mongo backend.
        assert isinstance(meta["started_at"], datetime)

    asyncio.run(run())


def test_upsert_dedup_updates_in_place(tmp_path):
    db = _db(tmp_path)

    async def run():
        sid = await db.create_scan("example.com", "webscan", {})
        await db.upsert_vulnerability(sid, _finding(detail="first"))
        await db.upsert_vulnerability(sid, _finding(detail="second"))  # same key
        vulns = await db.get_vulnerabilities_for_scan(sid)
        assert len(vulns) == 1
        assert vulns[0]["detail"] == "second"
        assert "_id" in vulns[0]

    asyncio.run(run())


def test_get_finding_by_id(tmp_path):
    db = _db(tmp_path)

    async def run():
        sid = await db.create_scan("example.com", "webscan", {})
        await db.upsert_vulnerability(sid, _finding())
        vulns = await db.get_vulnerabilities_for_scan(sid)
        fid = vulns[0]["_id"]
        found = await db.get_finding(fid)
        assert found and found["vuln_type"] == "missing_hsts"
        assert await db.get_finding("nonexistent") is None

    asyncio.run(run())


def test_dedup_by_vuln_type_across_scans(tmp_path):
    db = _db(tmp_path)

    async def run():
        s1 = await db.create_scan("example.com", "webscan", {})
        await db.upsert_vulnerability(s1, _finding(vuln_type="missing_hsts"))
        await db.upsert_vulnerability(s1, _finding(vuln_type="open_port", order=5))
        latest = await db.get_all_vulnerabilities_for_target("example.com")
        types = {v["vuln_type"] for v in latest}
        assert types == {"missing_hsts", "open_port"}
        # severity-sorted: High (2) before Info-ish (5)
        assert latest[0]["severity_order"] <= latest[-1]["severity_order"]

    asyncio.run(run())


def test_scan_history_filters_by_target(tmp_path):
    db = _db(tmp_path)

    async def run():
        await db.create_scan("a.com", "recon", {})
        await db.create_scan("b.com", "recon", {})
        a_hist = await db.get_scan_history("a.com")
        assert len(a_hist) == 1 and a_hist[0]["target"] == "a.com"
        all_hist = await db.get_scan_history()
        assert len(all_hist) == 2

    asyncio.run(run())


def test_backend_selector(monkeypatch):
    import importlib
    import spaf.database as database

    monkeypatch.setenv("SPAF_DB_BACKEND", "sqlite")
    importlib.reload(database)
    assert type(database.db).__name__ == "SQLiteDB"

    monkeypatch.setenv("SPAF_DB_BACKEND", "mongo")
    importlib.reload(database)
    assert type(database.db).__name__ == "MongoDB"
