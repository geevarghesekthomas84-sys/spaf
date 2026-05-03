import pytest
from spaf.utils.validator import validate_target, validate_url, sanitize_domain

def test_validate_target():
    assert validate_target("google.com") is True
    assert validate_target("127.0.0.1") is True
    assert validate_target("invalid target!") is False

def test_validate_url():
    assert validate_url("https://google.com") is True
    assert validate_url("http://localhost:8080") is True
    assert validate_url("google.com") is False

def test_sanitize_domain():
    assert sanitize_domain("https://google.com") == "google.com"
    assert sanitize_domain("http://api.target.local/") == "api.target.local"
    assert sanitize_domain("target.com") == "target.com"
