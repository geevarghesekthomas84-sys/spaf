"""
Prompt → response cache.

Keyed by a hash of (provider, model, system, prompt), stored in a local SQLite
file. Cuts cost and latency on repeated analysis and makes agent runs
deterministically replayable. Safe to disable (SPAF_CACHE=off).
"""

import hashlib
import os
import sqlite3
import time
from typing import Optional

CACHE_PATH = os.getenv("SPAF_CACHE_PATH", os.path.join("logs", "ai_cache.db"))
CACHE_ENABLED = os.getenv("SPAF_CACHE", "on").strip().lower() not in ("off", "0", "false", "no")


def make_key(provider: str, model: str, system: str, prompt: str) -> str:
    h = hashlib.sha256()
    h.update(f"{provider}\x00{model}\x00{system}\x00{prompt}".encode("utf-8", "ignore"))
    return h.hexdigest()


class ResponseCache:
    def __init__(self, path: str = CACHE_PATH, enabled: bool = CACHE_ENABLED):
        self.path = path
        self.enabled = enabled
        if self.enabled:
            self._init()

    def _init(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            con = sqlite3.connect(self.path)
            con.execute("CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT, ts REAL)")
            con.commit()
            con.close()
        except sqlite3.Error:
            self.enabled = False  # degrade silently to no cache

    def get(self, key: str) -> Optional[str]:
        if not self.enabled:
            return None
        try:
            con = sqlite3.connect(self.path)
            row = con.execute("SELECT v FROM cache WHERE k=?", (key,)).fetchone()
            con.close()
            return row[0] if row else None
        except sqlite3.Error:
            return None

    def set(self, key: str, value: str) -> None:
        if not self.enabled:
            return
        try:
            con = sqlite3.connect(self.path)
            con.execute("INSERT OR REPLACE INTO cache (k, v, ts) VALUES (?,?,?)",
                        (key, value, time.time()))
            con.commit()
            con.close()
        except sqlite3.Error:
            pass
