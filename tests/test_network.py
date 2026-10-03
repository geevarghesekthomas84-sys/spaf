from spaf.modules.network import NetworkModule
from spaf.utils.validator import validate_target, sanitize_domain


def _mod():
    return NetworkModule("example.com", {})


def test_nmap_args_are_lists_not_strings():
    # exec form requires arg lists so the target cannot be shell-interpreted.
    for intensity in ("light", "normal", "aggressive"):
        args = _mod()._get_nmap_args(intensity, "1-1024")
        assert isinstance(args, list)
        assert all(isinstance(a, str) for a in args)
    # port range is passed as its own argument, never interpolated into a flag.
    assert "1-1024" in _mod()._get_nmap_args("normal", "1-1024")


def test_rustscan_nmap_args_have_no_port_flag():
    args = _mod()._get_nmap_args_for_rustscan("normal")
    assert isinstance(args, list)
    assert "-p" not in args  # RustScan injects the ports itself


def test_unknown_intensity_falls_back_to_normal():
    assert _mod()._get_nmap_args("bogus", "1-100") == _mod()._get_nmap_args("normal", "1-100")


def test_injection_target_is_rejected_by_validation():
    # The scan CLI validates targets before they reach the scanner.
    malicious = "example.com; touch /tmp/pwned"
    assert validate_target(sanitize_domain(malicious)) is False
    assert validate_target(sanitize_domain("example.com")) is True
    assert validate_target(sanitize_domain("10.0.0.5")) is True


def test_engine_mock_mode(monkeypatch):
    import asyncio
    from spaf.core.engine import ScanEngine
    from spaf.modules.webscan import WebscanModule
    monkeypatch.setenv("SPAF_MOCK", "1")
    eng = ScanEngine()
    res = asyncio.run(eng.run_module(WebscanModule, "example.com", {"no_db": True}))
    assert len(res) == 1 and res[0]["vuln_type"] == "mock_webscan_finding"
    assert "no target was touched" in res[0]["detail"]
