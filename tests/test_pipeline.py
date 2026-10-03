import asyncio
import json

import pytest

from spaf.pipeline import Pipeline, Stage, STAGE_MODULES
from spaf.pipeline.pipeline import _dedupe, _default_remediation
from spaf.service import SpafService
from spaf.service.models import Finding


@pytest.fixture()
def svc(tmp_path):
    # no scope file → scope not enforced; mock mode avoids any network.
    return SpafService(scope_file=str(tmp_path / "scope.json"))


def _run(coro):
    return asyncio.run(coro)


# ── golden: full staged run in mock mode ─────────────────────────────────
def test_pipeline_runs_all_stages_in_order(svc, tmp_path):
    res = _run(svc.run_pipeline("example.com", {"mock": True, "no_db": True},
                                report_dir=str(tmp_path / "rep")))
    stages = [s.stage for s in res.stages]
    assert stages == [Stage.DISCOVERY, Stage.VALIDATION, Stage.REMEDIATION, Stage.REPORT]
    assert all(s.status in ("completed", "skipped") for s in res.stages)


def test_final_set_includes_discovery_and_validation(svc, tmp_path):
    # mock mode yields one finding per module: recon/toolkit/crawl + webscan/scan = 5,
    # all distinct, all carried through remediation into the final set.
    res = _run(svc.run_pipeline("example.com", {"mock": True, "no_db": True},
                                report_dir=str(tmp_path / "rep")))
    assert len(res.findings) == 5
    scan_types = {f.scan_type for f in res.findings}
    assert {"recon", "webscan", "scan"} <= scan_types
    # every finding has a remediation after the remediation stage
    assert all(f.recommendation for f in res.findings)


def test_pipeline_report_written(svc, tmp_path):
    rep = tmp_path / "rep"
    res = _run(svc.run_pipeline("example.com", {"mock": True, "no_db": True}, report_dir=str(rep)))
    assert res.report_path and res.report_path.endswith(".json")
    doc = json.load(open(res.report_path))
    assert doc["target"] == "example.com" and "findings" in doc


def test_discovery_only_runs_allowed_modules(svc):
    # Mock findings carry their scan_type = module name; discovery must only
    # contain discovery-stage modules, never a validation module.
    res = _run(svc.run_pipeline("example.com", {"mock": True, "no_db": True},
                                stages=[Stage.DISCOVERY]))
    disc = res.stage(Stage.DISCOVERY)
    scan_types = {f.scan_type for f in disc.findings}
    assert scan_types <= set(STAGE_MODULES[Stage.DISCOVERY])
    assert "scan" not in scan_types and "webscan" not in scan_types


def test_remediation_fills_missing_recommendations():
    pipe = Pipeline(service=None)
    findings = [
        Finding(target="x", vuln_type="a", severity="High", recommendation=""),
        Finding(target="x", vuln_type="b", severity="Low", recommendation="patch it"),
    ]
    out = pipe._remediate(findings)
    recs = {f.vuln_type: f.recommendation for f in out.findings}
    assert recs["a"]  # filled from default
    assert recs["b"] == "patch it"  # preserved from scanner
    assert out.meta["generated"] == 1


def test_remediation_does_not_mutate_input():
    pipe = Pipeline(service=None)
    f = Finding(target="x", vuln_type="a", severity="High", recommendation="")
    pipe._remediate([f])
    assert f.recommendation == ""  # original untouched (no cross-stage leakage)


def test_dedupe():
    a = Finding(target="x", vuln_type="t", scan_type="recon")
    b = Finding(target="x", vuln_type="t", scan_type="recon")
    c = Finding(target="x", vuln_type="t", scan_type="webscan")
    assert len(_dedupe([a, b, c])) == 2


def test_default_remediation_by_severity():
    assert "immediately" in _default_remediation("Critical").lower()
    assert _default_remediation("Nonsense") == _default_remediation("Info")
