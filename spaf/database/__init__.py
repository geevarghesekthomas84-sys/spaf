"""
Database backend selection.

SPAF stores scans and findings in MongoDB by default, but can fall back to a
zero-setup local SQLite file for offline use. Choose the backend with the
``SPAF_DB_BACKEND`` environment variable:

    SPAF_DB_BACKEND=mongo    (default) — MongoDB via Motor
    SPAF_DB_BACKEND=sqlite             — local SQLite file (SPAF_SQLITE_PATH)

Import the shared instance as ``from spaf.database import db``.
"""

import os

_backend = os.getenv("SPAF_DB_BACKEND", "mongo").strip().lower()

if _backend in ("sqlite", "sqlite3", "local", "file"):
    from spaf.database.sqlite import db  # noqa: F401
else:
    from spaf.database.mongo import db  # noqa: F401

__all__ = ["db"]
