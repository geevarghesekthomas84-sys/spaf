"""
API-key authentication for the SPAF API.

Secure by default: if no keys are configured via SPAF_API_KEYS / SPAF_API_KEY,
one is generated at startup and logged to stderr so nothing is ever exposed
without a key. Read-only health/version endpoints are open; everything else
requires a valid `X-API-Key` header.
"""

import os
import secrets
import sys
from typing import Set

from fastapi import Header, HTTPException, status


def load_keys() -> Set[str]:
    keys = set()
    for raw in (os.getenv("SPAF_API_KEYS", ""), os.getenv("SPAF_API_KEY", "")):
        for k in raw.split(","):
            k = k.strip()
            if k:
                keys.add(k)
    if not keys:
        generated = secrets.token_urlsafe(24)
        keys.add(generated)
        print(f"[spaf.api] no SPAF_API_KEYS set — generated one for this run:\n"
              f"           X-API-Key: {generated}", file=sys.stderr, flush=True)
    return keys


def make_auth_dependency(keys: Set[str]):
    async def require_key(x_api_key: str = Header(default="")) -> str:
        if x_api_key not in keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing or invalid API key. Send it in the 'X-API-Key' header.",
            )
        return x_api_key
    return require_key
