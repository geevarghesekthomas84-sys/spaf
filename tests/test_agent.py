from rich.console import Console

from spaf.agent.orchestrator import PentestAgent, ACTIONS, ACTIVE_ACTIONS


def _agent(target="example.com", options=None):
    return PentestAgent(target, "", options or {}, Console(quiet=True))


def test_action_set_is_fixed_and_known():
    assert set(ACTIONS) == {"recon", "toolkit", "scan", "webscan", "crawl"}
    assert ACTIVE_ACTIONS.issubset(set(ACTIONS))
    assert "recon" not in ACTIVE_ACTIONS  # recon is passive-ish, not scope-gated


def test_parse_plan_extracts_valid_modules_only():
    ag = _agent()
    raw = """Sure, here is the plan:
    [{"module": "recon", "reason": "map surface"},
     {"module": "webscan", "reason": "web audit"},
     {"module": "rm -rf", "reason": "evil"},
     {"module": "recon", "reason": "dup ignored"}]
    """
    steps = ag._parse_plan(raw)
    mods = [s["module"] for s in steps]
    assert mods == ["recon", "webscan"]  # invalid dropped, dup deduped


def test_parse_plan_handles_garbage():
    ag = _agent()
    assert ag._parse_plan("no json here") == []
    assert ag._parse_plan("[not valid json}") == []


def test_default_plan_skips_network_scan_for_urls():
    ag = _agent(target="https://example.com/app")
    mods = [s["module"] for s in ag._default_plan("test")]
    assert "scan" not in mods
    assert "recon" in mods and "webscan" in mods


def test_default_plan_includes_scan_for_hosts():
    ag = _agent(target="example.com")
    mods = [s["module"] for s in ag._default_plan("test")]
    assert "scan" in mods


def test_scope_blocks_active_steps_out_of_scope():
    scope = {"in_scope": ["allowed.com"], "out_of_scope": []}
    ag = _agent(target="evil.com", options={"scope": scope})
    assert ag.scope_blocks("webscan") is True   # active + out of scope
    assert ag.scope_blocks("recon") is False     # passive, never gated


def test_scope_allows_in_scope_target():
    scope = {"in_scope": ["example.com"], "out_of_scope": []}
    ag = _agent(target="api.example.com", options={"scope": scope})
    assert ag.scope_blocks("toolkit") is False


def test_module_options_presets():
    ag = _agent(options={"aggressive": True})
    opts = ag._module_options("scan")
    assert opts["intensity"] == "aggressive"
    assert opts["no_ai"] is True  # sub-steps silent; agent does one final summary
    t = ag._module_options("toolkit")
    assert t["nuclei_dast"] is True
