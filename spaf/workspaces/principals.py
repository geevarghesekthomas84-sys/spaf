"""
Principal registry — maps API keys to RBAC roles and engagement access.

Configuration (either source; JSON maps a raw API key to its grant)::

    SPAF_PRINCIPALS='{"KEY1":{"name":"lead","role":"lead","engagements":["*"]},
                      "KEY2":{"name":"intern","role":"viewer","engagements":["acme"]}}'
    # or a file:
    SPAF_PRINCIPALS_FILE=/run/secrets/spaf_principals.json

Backwards-compatible fallback: if no principals are configured but the existing
``SPAF_API_KEYS`` / ``SPAF_API_KEY`` are set, each of those keys becomes a
**lead** with access to all engagements — so single-key deployments keep working
exactly as before, and RBAC is strictly opt-in.

Raw keys are never stored in the resulting :class:`Principal` objects (only a
short non-secret hash prefix as ``key_id``); lookup is by constant-time digest
comparison.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from typing import Dict, Optional

from spaf.utils.logger import logger
from spaf.workspaces.models import Principal, Role


def _key_id(key: str) -> str:
    return "k_" + hashlib.sha256(key.encode("utf-8")).hexdigest()[:10]


class PrincipalRegistry:
    def __init__(self, principals: Dict[str, Principal]):
        # digest -> Principal, so the raw key is not held in memory as a dict key.
        self._by_digest: Dict[str, Principal] = {
            hashlib.sha256(k.encode("utf-8")).hexdigest(): p for k, p in principals.items()
        }

    def __len__(self) -> int:
        return len(self._by_digest)

    def authenticate(self, key: str) -> Optional[Principal]:
        if not key:
            return None
        digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
        for known, principal in self._by_digest.items():
            if hmac.compare_digest(known, digest):
                return principal
        return None


def _parse_config(raw: str) -> Dict[str, Principal]:
    principals: Dict[str, Principal] = {}
    data = json.loads(raw)
    for key, spec in data.items():
        key = key.strip()
        if not key:
            continue
        spec = spec or {}
        principals[key] = Principal(
            key_id=_key_id(key),
            name=spec.get("name", _key_id(key)),
            role=Role.parse(spec.get("role", "viewer")),
            engagements=list(spec.get("engagements", ["*"])) or ["*"],
        )
    return principals


def load_registry() -> PrincipalRegistry:
    raw = os.getenv("SPAF_PRINCIPALS", "").strip()
    if not raw:
        path = os.getenv("SPAF_PRINCIPALS_FILE", "").strip()
        if path and os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    raw = fh.read()
            except OSError as exc:
                logger.warning(f"principals: could not read {path}: {exc}")

    if raw:
        try:
            principals = _parse_config(raw)
            if principals:
                return PrincipalRegistry(principals)
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning(f"principals: invalid SPAF_PRINCIPALS ({exc}); "
                           f"falling back to SPAF_API_KEYS.")

    # Fallback: existing API keys become all-access leads (opt-in RBAC).
    from spaf.api.auth import load_keys
    keys = load_keys()
    principals = {
        k: Principal(key_id=_key_id(k), name="lead", role=Role.LEAD, engagements=["*"])
        for k in keys
    }
    if principals:
        print("[spaf.rbac] no SPAF_PRINCIPALS set — existing API key(s) act as "
              "all-access 'lead'. Set SPAF_PRINCIPALS to enable roles.",
              file=sys.stderr, flush=True)
    return PrincipalRegistry(principals)
