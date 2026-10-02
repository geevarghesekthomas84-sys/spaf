import asyncio

import pytest

from spaf.service import SpafService, ScopeError
from spaf.service.models import Finding, severity_counts
from spaf.service.events import EventBus


class _FakeModule:
    """Stand-in module: no network, returns canned findings."""
    def __init__(self, target, options, scan_id=None):
        self.target = target

    async def run(self, progress):
        return [
            {"target": self.target, "vuln_type": "missing_hsts", "detail": "no HSTS",
             "severity": "High", "severity_order": 2, "recommendation": "add it",
             "scan_type": "webscan", "discovered_at": "2026-01-01"},
            {"target": self.target, "vuln_type": "info_leak", "detail": "x",
             "severity": "Low", "severity_order": 4, "recommendation": "y",
             "scan_type": "webscan"},
        ]


def _svc(tmp_path, scope=None):
    import json
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(scope or {"in_scope": ["example.com"], "out_of_scope": []}))
    return SpafService(str(p))


def test_scope_state_and_add(tmp_path):
    svc = _svc(tmp_path)
    assert svc.scope_state().enforced is True
    assert svc.is_allowed("api.example.com") is True
    assert svc.is_allowed("evil.com") is False
    svc.scope_add("evil.com")
    assert svc.is_allowed("evil.com") is True


def test_run_module_blocks_out_of_scope(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    monkeypatch.setitem(__import__("spaf.service.service", fromlist=["MODULE_MAP"]).MODULE_MAP,
                        "webscan", _FakeModule)
    with pytest.raises(ScopeError):
        asyncio.run(svc.run_module("webscan", "https://evil.com", {"no_db": True}))


def test_run_module_headless_returns_typed_result(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    import spaf.service.service as svcmod
    monkeypatch.setitem(svcmod.MODULE_MAP, "webscan", _FakeModule)
    res = asyncio.run(svc.run_module("webscan", "https://example.com", {"no_db": True}))
    assert res.status == "completed"
    assert len(res.findings) == 2
    assert res.counts["High"] == 1 and res.counts["Low"] == 1
    assert all(isinstance(f, Finding) for f in res.findings)


def test_run_module_emits_events(tmp_path, monkeypatch):
    svc = _svc(tmp_path)
    import spaf.service.service as svcmod
    monkeypatch.setitem(svcmod.MODULE_MAP, "webscan", _FakeModule)
    bus = EventBus()
    seen = []

    async def collect():
        async for ev in bus.subscribe():
            seen.append(ev.kind)

    async def main():
        task = asyncio.create_task(collect())
        await asyncio.sleep(0)
        await svc.run_module("webscan", "https://example.com", {"no_db": True}, bus=bus)
        bus.close()
        await task

    asyncio.run(main())
    assert "run_started" in seen and "run_completed" in seen
    assert seen.count("finding") == 2


def test_unknown_module_raises(tmp_path):
    svc = _svc(tmp_path)
    with pytest.raises(ValueError):
        asyncio.run(svc.run_module("nope", "example.com", {"no_db": True}))


def test_tools_status(tmp_path):
    svc = _svc(tmp_path)
    tools = svc.tools_status()
    assert len(tools) == 10
    assert {t.name for t in tools} >= {"subfinder", "httpx", "nuclei"}


def test_severity_counts_helper():
    fs = [Finding(target="a", vuln_type="x", severity="High"),
          Finding(target="a", vuln_type="y", severity="High"),
          Finding(target="a", vuln_type="z", severity="Info")]
    c = severity_counts(fs)
    assert c["High"] == 2 and c["Info"] == 1 and c["Critical"] == 0
