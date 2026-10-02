import json
import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

import spaf.service.service as svcmod  # noqa: E402
from spaf.api import create_app  # noqa: E402

KEY = "testkey"
H = {"X-API-Key": KEY}


class _FakeModule:
    def __init__(self, target, options, scan_id=None):
        self.target = target

    async def run(self, progress):
        return [{"target": self.target, "vuln_type": "missing_hsts", "detail": "x",
                 "severity": "High", "severity_order": 2, "recommendation": "fix",
                 "scan_type": "webscan", "discovered_at": "2026-01-01"}]


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SPAF_API_KEY", KEY)
    monkeypatch.setitem(svcmod.MODULE_MAP, "webscan", _FakeModule)
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"in_scope": ["example.com"], "out_of_scope": []}))
    return TestClient(create_app(str(p)))


def test_health_and_version_are_open(client):
    assert client.get("/health").json()["status"] == "ok"
    assert "version" in client.get("/version").json()


def test_auth_required(client):
    assert client.get("/scope").status_code == 401
    assert client.get("/scope", headers=H).status_code == 200


def test_out_of_scope_scan_rejected(client):
    r = client.post("/scans", json={"module": "webscan", "target": "https://evil.com"}, headers=H)
    assert r.status_code == 403


def test_scan_job_lifecycle(client):
    r = client.post("/scans", json={"module": "webscan", "target": "https://example.com",
                                    "options": {"no_db": True}}, headers=H)
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    result = None
    for _ in range(30):
        j = client.get(f"/jobs/{job_id}", headers=H).json()
        if j["status"] != "running":
            result = j
            break
        time.sleep(0.05)
    assert result and result["status"] == "completed"
    assert len(result["result"]["findings"]) == 1
    assert result["result"]["counts"]["High"] == 1


def test_agent_dry_run(client):
    r = client.post("/agent", json={"target": "example.com", "dry_run": True}, headers=H)
    assert r.status_code == 202
    job_id = r.json()["job_id"]
    for _ in range(30):
        j = client.get(f"/jobs/{job_id}", headers=H).json()
        if j["status"] != "running":
            assert "plan" in j["result"]
            return
        time.sleep(0.05)
    pytest.fail("agent job did not finish")


def test_unknown_job_404(client):
    assert client.get("/jobs/nope", headers=H).status_code == 404


def test_tools_endpoint(client):
    data = client.get("/tools", headers=H).json()
    assert len(data["tools"]) == 10


def test_scope_add(client):
    r = client.post("/scope", json={"value": "new.com"}, headers=H)
    assert "new.com" in r.json()["in_scope"]
