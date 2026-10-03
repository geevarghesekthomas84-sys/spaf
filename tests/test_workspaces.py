import json

import pytest

from spaf.workspaces import EngagementManager, Role, authorization
from spaf.workspaces.models import Principal
from spaf.workspaces.principals import PrincipalRegistry, load_registry


# ── Roles ──────────────────────────────────────────────────────────────
def test_role_ordering_and_parse():
    assert Role.LEAD > Role.OPERATOR > Role.VIEWER
    assert Role.parse("operator") is Role.OPERATOR
    assert Role.parse("LEAD") is Role.LEAD
    with pytest.raises(ValueError):
        Role.parse("superuser")


def test_principal_access_and_role():
    p = Principal(key_id="k_x", name="op", role=Role.OPERATOR, engagements=["acme"])
    assert p.can_access("acme") and not p.can_access("other")
    assert p.has_role(Role.VIEWER) and p.has_role(Role.OPERATOR)
    assert not p.has_role(Role.LEAD)
    wild = Principal(key_id="k_y", role=Role.VIEWER, engagements=["*"])
    assert wild.can_access("anything")


# ── Engagement isolation ────────────────────────────────────────────────
def test_two_engagements_are_isolated(tmp_path):
    mgr = EngagementManager(root=str(tmp_path / "eng"))
    a = mgr.create("Acme", in_scope=["acme.com"])
    b = mgr.create("Globex", in_scope=["globex.com"])
    assert a.id != b.id
    # Separate scope files with separate contents.
    assert json.load(open(a.scope_file))["in_scope"] == ["acme.com"]
    assert json.load(open(b.scope_file))["in_scope"] == ["globex.com"]
    # Separate audit paths.
    assert a.audit_path != b.audit_path
    # Round-trips through metadata.
    assert mgr.get(a.id).name == "Acme"
    ids = {e.id for e in mgr.list()}
    assert {a.id, b.id} <= ids


def test_duplicate_names_get_unique_ids(tmp_path):
    mgr = EngagementManager(root=str(tmp_path / "eng"))
    a = mgr.create("Acme Corp")
    b = mgr.create("Acme Corp")
    assert a.id != b.id


# ── Signed authorizations ────────────────────────────────────────────────
def test_authorization_signature_detects_tampering(tmp_path, monkeypatch):
    monkeypatch.setenv("SPAF_AUTH_SIGNING_KEY", "unit-test-signing-key")
    mgr = EngagementManager(root=str(tmp_path / "eng"))
    eng = mgr.create("Signed", in_scope=["x.com"], authorized_by="client@x.com")
    assert mgr.authorization_valid(eng)
    # Tamper with the scope hash → signature no longer verifies.
    eng.authorization.scope_hash = "deadbeef"
    assert not authorization.verify(eng.id, eng.authorization)


def test_authorization_expiry(tmp_path, monkeypatch):
    from datetime import datetime, timedelta
    monkeypatch.setenv("SPAF_AUTH_SIGNING_KEY", "unit-test-signing-key")
    mgr = EngagementManager(root=str(tmp_path / "eng"))
    eng = mgr.create("Expiring", in_scope=["x.com"], authorized_by="c",
                     expires_at=datetime.utcnow() - timedelta(days=1))
    assert not mgr.authorization_valid(eng)  # signature fine, but expired


# ── Principal registry ───────────────────────────────────────────────────
def test_registry_from_config():
    cfg = {"OPKEY": {"name": "op", "role": "operator", "engagements": ["acme"]},
           "VIEWKEY": {"name": "v", "role": "viewer", "engagements": ["acme"]}}
    import spaf.workspaces.principals as pr
    reg = PrincipalRegistry(pr._parse_config(json.dumps(cfg)))
    assert reg.authenticate("OPKEY").role is Role.OPERATOR
    assert reg.authenticate("VIEWKEY").role is Role.VIEWER
    assert reg.authenticate("nope") is None


def test_registry_fallback_to_api_keys(monkeypatch):
    monkeypatch.delenv("SPAF_PRINCIPALS", raising=False)
    monkeypatch.delenv("SPAF_PRINCIPALS_FILE", raising=False)
    monkeypatch.setenv("SPAF_API_KEY", "legacy-key")
    reg = load_registry()
    p = reg.authenticate("legacy-key")
    assert p is not None and p.role is Role.LEAD and p.can_access("anything")
