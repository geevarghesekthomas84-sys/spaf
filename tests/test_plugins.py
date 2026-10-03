import asyncio

import pytest

from spaf import plugins
from spaf.core.engine import BaseModule
from spaf.service import SpafService


class _MyPlugin(BaseModule):
    async def run(self, progress):
        return [{"target": self.target, "vuln_type": "custom_finding", "detail": "hi",
                 "severity": "Low", "severity_order": 4, "recommendation": "ok",
                 "scan_type": "myplugin"}]

    def render_results(self, results):
        pass


def test_register_and_lookup():
    plugins.register_module("myplugin", _MyPlugin)
    assert plugins.get_module("myplugin") is _MyPlugin
    assert "myplugin" in plugins.registered_modules()


def test_decorator_registers():
    @plugins.spaf_module("decorated")
    class _D(BaseModule):
        async def run(self, progress):
            return []

        def render_results(self, results):
            pass

    assert plugins.get_module("decorated") is _D


def test_register_rejects_non_module():
    with pytest.raises(TypeError):
        plugins.register_module("bad", object)
    with pytest.raises(ValueError):
        plugins.register_module("", _MyPlugin)


def test_service_runs_registered_plugin(tmp_path):
    import json
    plugins.register_module("myplugin", _MyPlugin)
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"in_scope": ["example.com"], "out_of_scope": []}))
    svc = SpafService(str(p))
    res = asyncio.run(svc.run_module("myplugin", "example.com", {"no_db": True}))
    assert res.status == "completed"
    assert res.findings and res.findings[0].vuln_type == "custom_finding"


def test_service_unknown_module_lists_plugins(tmp_path):
    import json
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"in_scope": ["example.com"], "out_of_scope": []}))
    svc = SpafService(str(p))
    with pytest.raises(ValueError):
        asyncio.run(svc.run_module("does-not-exist", "example.com", {"no_db": True}))
