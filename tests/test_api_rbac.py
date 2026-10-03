import json

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

import spaf.service.service as svcmod  # noqa: E402
from spaf.api import create_app  # noqa: E402


class _FakeModule:
    def __init__(self, target, options, scan_id=None):
        self.target = target

    async def run(self, progress):
        return []


@pytest.fixture()
def rbac_client(tmp_path, monkeypatch):
    # Two engagements, isolated on disk.
    eng_dir = tmp_path / "eng"
    monkeypatch.setenv("SPAF_ENGAGEMENTS_DIR", str(eng_dir))
    monkeypatch.setitem(svcmod.MODULE_MAP, "webscan", _FakeModule)

    from spaf.workspaces import EngagementManager
    mgr = EngagementManager(root=str(eng_dir))
    acme = mgr.create("Acme", in_scope=["acme.com"])
    globex = mgr.create("Globex", in_scope=["globex.com"])

    principals = {
        "LEADKEY": {"name": "lead", "role": "lead", "engagements": ["*"]},
        "OPKEY": {"name": "op", "role": "operator", "engagements": [acme.id]},
        "VIEWKEY": {"name": "viewer", "role": "viewer", "engagements": [acme.id]},
    }
    monkeypatch.setenv("SPAF_PRINCIPALS", json.dumps(principals))

    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"in_scope": ["default.com"], "out_of_scope": []}))
    client = TestClient(create_app(str(p)))
    client.acme, client.globex = acme.id, globex.id
    return client


def H(key):
    return {"X-API-Key": key}


def test_whoami_roles(rbac_client):
    assert rbac_client.get("/whoami", headers=H("OPKEY")).json()["role"] == "operator"
    assert rbac_client.get("/whoami", headers=H("VIEWKEY")).json()["role"] == "viewer"
    assert rbac_client.get("/whoami").status_code == 401


def test_viewer_cannot_launch_active_scan(rbac_client):
    # Viewer may read scope...
    r = rbac_client.get("/scope", headers={"X-API-Key": "VIEWKEY", "X-Engagement": rbac_client.acme})
    assert r.status_code == 200
    # ...but cannot start a scan (needs operator).
    r = rbac_client.post("/scans",
                         json={"module": "webscan", "target": "acme.com", "options": {"no_db": True}},
                         headers={"X-API-Key": "VIEWKEY", "X-Engagement": rbac_client.acme})
    assert r.status_code == 403


def test_operator_can_launch_in_its_engagement(rbac_client):
    r = rbac_client.post("/scans",
                         json={"module": "webscan", "target": "acme.com", "options": {"no_db": True}},
                         headers={"X-API-Key": "OPKEY", "X-Engagement": rbac_client.acme})
    assert r.status_code == 202


def test_operator_blocked_from_other_engagement(rbac_client):
    # OPKEY is only granted the acme engagement.
    r = rbac_client.get("/scope",
                        headers={"X-API-Key": "OPKEY", "X-Engagement": rbac_client.globex})
    assert r.status_code == 403


def test_engagement_scope_isolation(rbac_client):
    acme_scope = rbac_client.get(
        "/scope", headers={"X-API-Key": "LEADKEY", "X-Engagement": rbac_client.acme}).json()
    globex_scope = rbac_client.get(
        "/scope", headers={"X-API-Key": "LEADKEY", "X-Engagement": rbac_client.globex}).json()
    assert acme_scope["in_scope"] == ["acme.com"]
    assert globex_scope["in_scope"] == ["globex.com"]
    # A target in one engagement's scope is out-of-scope in the other.
    r = rbac_client.post("/scans",
                        json={"module": "webscan", "target": "globex.com", "options": {"no_db": True}},
                        headers={"X-API-Key": "LEADKEY", "X-Engagement": rbac_client.acme})
    assert r.status_code == 403  # globex.com not in acme scope


def test_only_lead_creates_engagements(rbac_client):
    body = {"name": "New Client", "in_scope": ["new.com"]}
    assert rbac_client.post("/engagements", json=body,
                            headers=H("OPKEY")).status_code == 403
    r = rbac_client.post("/engagements", json=body, headers=H("LEADKEY"))
    assert r.status_code == 201 and r.json()["id"]


def test_viewer_cannot_add_scope(rbac_client):
    r = rbac_client.post("/scope", json={"value": "x.com"},
                        headers={"X-API-Key": "VIEWKEY", "X-Engagement": rbac_client.acme})
    assert r.status_code == 403


def test_unknown_engagement_404(rbac_client):
    r = rbac_client.get("/scope", headers={"X-API-Key": "LEADKEY", "X-Engagement": "ghost"})
    assert r.status_code == 404
