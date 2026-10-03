"""
Tiny in-process token-bucket rate limiter for the API.

Per-identity (principal key id) buckets smooth out bursts and cap sustained
request rate, so a stuck client or an abusive key cannot hammer the service or,
through it, external targets. Dependency-free and thread-safe; limits are set via
``SPAF_RATE_LIMIT`` (requests per minute, default 120) and ``SPAF_RATE_BURST``
(default = one minute's worth).

This is an app-level backstop; the Caddy gateway can add edge rate-limiting too.
"""

from __future__ import annotations

import os
import time
from threading import Lock
from typing import Dict


def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.getenv(name, "").strip() or default))
    except ValueError:
        return default


class RateLimiter:
    def __init__(self, rate_per_min: int | None = None, burst: int | None = None):
        self.rate = (rate_per_min if rate_per_min is not None
                     else _int_env("SPAF_RATE_LIMIT", 120))
        self.burst = (burst if burst is not None
                      else _int_env("SPAF_RATE_BURST", self.rate))
        self._fill = self.rate / 60.0  # tokens per second
        self._buckets: Dict[str, tuple[float, float]] = {}  # id -> (tokens, ts)
        self._lock = Lock()

    def allow(self, identity: str) -> bool:
        """Consume one token for *identity*; False when the bucket is empty."""
        now = time.monotonic()
        with self._lock:
            tokens, ts = self._buckets.get(identity, (float(self.burst), now))
            tokens = min(self.burst, tokens + (now - ts) * self._fill)
            if tokens < 1.0:
                self._buckets[identity] = (tokens, now)
                return False
            self._buckets[identity] = (tokens - 1.0, now)
            return True
