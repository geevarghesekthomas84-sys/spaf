"""
Signed engagement authorizations.

Active testing is only lawful with the client's written go-ahead. SPAF records
that as a tamper-evident HMAC signature over the engagement's identity, scope,
who authorized it, and when it expires. Anyone can *verify* an authorization,
but only a holder of the signing key (``SPAF_AUTH_SIGNING_KEY``) can *mint* one —
so a stored ``engagement.json`` cannot be edited to widen scope or extend an
expiry without invalidating the signature.

If no signing key is configured the functions still work with a process-stable
development key, but :func:`signing_configured` reports ``False`` so callers can
refuse to run active scans until a real key is set.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime
from typing import List, Optional

from spaf.workspaces.models import EngagementAuthorization

_ENV_KEY = "SPAF_AUTH_SIGNING_KEY"
# Stable within a process so unsigned/dev setups are still internally consistent.
_DEV_KEY = "spaf-dev-" + hashlib.sha256(os.urandom(16)).hexdigest()[:16]


def signing_configured() -> bool:
    return bool(os.getenv(_ENV_KEY, "").strip())


def _key() -> bytes:
    return (os.getenv(_ENV_KEY, "").strip() or _DEV_KEY).encode("utf-8")


def scope_hash(in_scope: List[str], out_of_scope: Optional[List[str]] = None) -> str:
    """A stable hash of a scope definition, order-independent."""
    canonical = json.dumps(
        {"in": sorted(in_scope or []), "out": sorted(out_of_scope or [])},
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _payload(engagement_id: str, authorized_by: str, scope_hash_: str,
             authorized_at: datetime, expires_at: Optional[datetime]) -> bytes:
    canonical = json.dumps({
        "eid": engagement_id,
        "by": authorized_by,
        "scope": scope_hash_,
        "at": authorized_at.isoformat(),
        "exp": expires_at.isoformat() if expires_at else None,
    }, separators=(",", ":"))
    return canonical.encode("utf-8")


def sign(engagement_id: str, authorized_by: str, scope_hash_: str, *,
         expires_at: Optional[datetime] = None) -> EngagementAuthorization:
    at = datetime.utcnow()
    sig = hmac.new(_key(), _payload(engagement_id, authorized_by, scope_hash_, at, expires_at),
                   hashlib.sha256).hexdigest()
    return EngagementAuthorization(
        authorized_by=authorized_by, authorized_at=at,
        expires_at=expires_at, scope_hash=scope_hash_, signature=sig,
    )


def verify(engagement_id: str, auth: EngagementAuthorization) -> bool:
    """True if the signature is intact (constant-time) and not expired."""
    if not auth or not auth.signature:
        return False
    expected = hmac.new(
        _key(),
        _payload(engagement_id, auth.authorized_by, auth.scope_hash,
                 auth.authorized_at, auth.expires_at),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(expected, auth.signature):
        return False
    return not auth.is_expired()
