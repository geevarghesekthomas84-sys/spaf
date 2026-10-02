"""
Task → model router.

Maps a task kind (plan / analyze / codegen / chat) to an ordered list of models
to try (first choice, then fallbacks) for the configured provider. Config-driven
so no model ids are hard-coded: set SPAF_MODEL_PLAN / SPAF_MODEL_ANALYZE /
SPAF_MODEL_CODEGEN (comma-separated for fallbacks); unset tasks fall back to
SPAF_MODEL_DEFAULT and then the provider's own configured model (``None``).
"""

import os
from typing import List, Optional

TASKS = ("plan", "analyze", "codegen", "chat")


def _models_from_env(var: str) -> List[str]:
    return [m.strip() for m in os.getenv(var, "").split(",") if m.strip()]


class ModelRouter:
    def __init__(self) -> None:
        self._default = _models_from_env("SPAF_MODEL_DEFAULT")
        self._by_task = {t: _models_from_env(f"SPAF_MODEL_{t.upper()}") for t in TASKS}

    def resolve(self, task: str) -> List[Optional[str]]:
        """Ordered models to try for a task. ``None`` means the provider default."""
        chain: List[Optional[str]] = []
        for m in self._by_task.get(task, []) + self._default:
            if m not in chain:
                chain.append(m)
        chain.append(None)  # always end with the provider's configured model
        return chain
