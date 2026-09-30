"""
Engagement scope management and enforcement.

A scope file is a JSON document::

    {"in_scope": ["example.com", "10.0.0.0/24"], "out_of_scope": ["blog.example.com"]}

``is_in_scope`` is the safety gate the active scanners consult before touching a
host. Matching rules:

* ``out_of_scope`` always wins — a host matching any exclusion is rejected.
* A domain entry matches the domain itself **and** any subdomain of it
  (``example.com`` covers ``api.example.com``).
* An IP/CIDR entry matches any address inside that network.
* Exact string equality is the final fallback.

If ``in_scope`` is empty the scope is considered *undefined* and everything is
allowed — this keeps behaviour backwards-compatible for users who never set up a
scope file. Callers that want to fail closed should check ``has_scope`` first.
"""

import ipaddress
import json
import os
from typing import Any, Dict, List

DEFAULT_SCOPE_FILE = "scope.json"


def load_scope(path: str = DEFAULT_SCOPE_FILE) -> Dict[str, List[str]]:
    """Load a scope file, returning an empty scope if it does not exist."""
    if path and os.path.exists(path):
        try:
            with open(path) as fh:
                data = json.load(fh)
            data.setdefault("in_scope", [])
            data.setdefault("out_of_scope", [])
            return data
        except (OSError, json.JSONDecodeError):
            pass
    return {"in_scope": [], "out_of_scope": []}


def save_scope(path: str, data: Dict[str, Any]) -> None:
    """Persist a scope dict to disk as indented JSON."""
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2)


def has_scope(scope: Dict[str, List[str]]) -> bool:
    """True if an in-scope list has been defined (scope is being enforced)."""
    return bool(scope and scope.get("in_scope"))


def _host_of(target: str) -> str:
    """Strip scheme/path/port from a target, leaving a bare host or IP."""
    t = target.strip().lower()
    if "://" in t:
        t = t.split("://", 1)[1]
    t = t.split("/")[0]
    # Strip a trailing :port, but not the colons inside an IPv6 literal.
    if t.count(":") == 1:
        t = t.split(":")[0]
    return t


def _matches_entry(host: str, entry: str) -> bool:
    entry = entry.strip().lower()
    if not entry:
        return False
    if host == entry:
        return True

    # CIDR / IP network membership.
    try:
        net = ipaddress.ip_network(entry, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    except ValueError:
        pass

    # Domain suffix match: entry "example.com" covers "*.example.com".
    return host == entry or host.endswith("." + entry)


def is_in_scope(target: str, scope: Dict[str, List[str]]) -> bool:
    """
    Return True if ``target`` is permitted by ``scope``.

    An empty/undefined ``in_scope`` list means the scope is not being enforced
    and every target is allowed.
    """
    host = _host_of(target)

    # Exclusions always take precedence.
    for entry in scope.get("out_of_scope", []) or []:
        if _matches_entry(host, entry):
            return False

    in_scope = scope.get("in_scope", []) or []
    if not in_scope:
        return True  # scope not enforced

    return any(_matches_entry(host, entry) for entry in in_scope)
