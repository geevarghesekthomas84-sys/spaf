import json

from spaf.utils.scope import (
    is_in_scope,
    has_scope,
    load_scope,
    save_scope,
    _host_of,
)


def test_host_of_strips_scheme_path_and_port():
    assert _host_of("https://api.example.com/path?x=1") == "api.example.com"
    assert _host_of("http://example.com:8080") == "example.com"
    assert _host_of("EXAMPLE.com/") == "example.com"


def test_empty_scope_allows_everything():
    scope = {"in_scope": [], "out_of_scope": []}
    assert has_scope(scope) is False
    assert is_in_scope("anything.com", scope) is True


def test_domain_covers_subdomains():
    scope = {"in_scope": ["example.com"], "out_of_scope": []}
    assert is_in_scope("example.com", scope) is True
    assert is_in_scope("api.example.com", scope) is True
    assert is_in_scope("https://deep.api.example.com", scope) is True
    assert is_in_scope("notexample.com", scope) is False
    assert is_in_scope("example.com.evil.com", scope) is False


def test_out_of_scope_takes_precedence():
    scope = {"in_scope": ["example.com"], "out_of_scope": ["blog.example.com"]}
    assert is_in_scope("blog.example.com", scope) is False
    assert is_in_scope("api.example.com", scope) is True


def test_cidr_membership():
    scope = {"in_scope": ["10.0.0.0/24"], "out_of_scope": []}
    assert is_in_scope("10.0.0.5", scope) is True
    assert is_in_scope("10.0.1.5", scope) is False
    assert is_in_scope("192.168.1.1", scope) is False


def test_exact_ip_entry():
    scope = {"in_scope": ["192.168.1.10"], "out_of_scope": []}
    assert is_in_scope("192.168.1.10", scope) is True
    assert is_in_scope("192.168.1.11", scope) is False


def test_load_scope_missing_file_returns_empty(tmp_path):
    data = load_scope(str(tmp_path / "does_not_exist.json"))
    assert data == {"in_scope": [], "out_of_scope": []}


def test_load_scope_malformed_file_returns_empty(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{ not valid json ")
    assert load_scope(str(p)) == {"in_scope": [], "out_of_scope": []}


def test_save_and_load_roundtrip(tmp_path):
    p = tmp_path / "scope.json"
    save_scope(str(p), {"in_scope": ["a.com"], "out_of_scope": ["x.a.com"]})
    loaded = load_scope(str(p))
    assert loaded["in_scope"] == ["a.com"]
    assert loaded["out_of_scope"] == ["x.a.com"]
    # File is valid JSON on disk.
    assert json.loads(p.read_text())["in_scope"] == ["a.com"]
