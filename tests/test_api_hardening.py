import json
import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from spaf.api import create_app  # noqa: E402

KEY = "testkey"
H = {"X-API-Key": KEY}


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SPAF_API_KEY", KEY)
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"in_scope": ["example.com"], "out_of_scope": []}))
    return TestClient(create_app(str(p)))


def test_overly_broad_target_rejected(client):
    for bad in ["0.0.0.0/0", "*", "10.0.0.0/8"]:
        r = client.post("/scans", json={"module": "webscan", "target": bad}, headers=H)
        assert r.status_code == 422, bad


def test_bad_module_name_rejected(client):
    r = client.post("/scans", json={"module": "web scan!", "target": "example.com"}, headers=H)
    assert r.status_code == 422


def test_agent_goal_payload_capped(client):
    r = client.post("/agent", json={"target": "example.com", "goal": "x" * 5000}, headers=H)
    assert r.status_code == 422


def test_mock_mode_scan_touches_nothing(client):
    r = client.post("/scans", json={"module": "scan", "target": "example.com",
                                     "options": {"mock": True, "no_db": True}}, headers=H)
    assert r.status_code == 202
    jid = r.json()["job_id"]
    result = None
    for _ in range(30):
        j = client.get(f"/jobs/{jid}", headers=H).json()
        if j["status"] != "running":
            result = j
            break
        time.sleep(0.05)
    assert result and result["status"] == "completed"
    f = result["result"]["findings"]
    assert len(f) == 1 and f[0]["vuln_type"] == "mock_scan_finding"


def test_pipeline_endpoint_mock(client):
    r = client.post("/pipeline", json={"target": "example.com",
                                        "options": {"mock": True, "no_db": True}}, headers=H)
    assert r.status_code == 202
    jid = r.json()["job_id"]
    result = None
    for _ in range(40):
        j = client.get(f"/jobs/{jid}", headers=H).json()
        if j["status"] != "running":
            result = j
            break
        time.sleep(0.05)
    assert result and result["status"] == "completed"
    stages = [s["stage"] for s in result["result"]["stages"]]
    assert stages == ["discovery", "validation", "remediation", "report"]


def test_rate_limit_returns_429(tmp_path, monkeypatch):
    monkeypatch.setenv("SPAF_API_KEY", KEY)
    monkeypatch.setenv("SPAF_RATE_LIMIT", "3")
    monkeypatch.setenv("SPAF_RATE_BURST", "3")
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"in_scope": ["example.com"], "out_of_scope": []}))
    c = TestClient(create_app(str(p)))
    codes = [c.get("/scope", headers=H).status_code for _ in range(6)]
    assert 429 in codes
    assert "spaf_rate_limited_total" in c.get("/metrics").text
