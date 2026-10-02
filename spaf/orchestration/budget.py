"""
Per-run budget: bound an orchestrated task's cost in calls, characters, and time.

Keeps an autonomous loop from running away. Defaults are generous and overridable
via env (SPAF_BUDGET_CALLS, SPAF_BUDGET_CHARS, SPAF_BUDGET_SECONDS).
"""

import os
import time
from dataclasses import dataclass, field


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Budget:
    max_calls: int = int(os.getenv("SPAF_BUDGET_CALLS", "16"))
    max_chars: int = int(os.getenv("SPAF_BUDGET_CHARS", "400000"))
    max_seconds: float = float(os.getenv("SPAF_BUDGET_SECONDS", "300"))
    calls: int = 0
    chars: int = 0
    started: float = field(default_factory=time.monotonic)

    def remaining_seconds(self) -> float:
        return self.max_seconds - (time.monotonic() - self.started)

    def would_exceed(self, prompt_chars: int) -> bool:
        return (self.calls + 1 > self.max_calls
                or self.chars + prompt_chars > self.max_chars
                or self.remaining_seconds() <= 0)

    def consume(self, prompt_chars: int) -> None:
        if self.would_exceed(prompt_chars):
            raise BudgetExceeded(
                f"run budget exhausted (calls={self.calls}/{self.max_calls}, "
                f"chars={self.chars}/{self.max_chars}, "
                f"time_left={self.remaining_seconds():.0f}s)"
            )
        self.calls += 1
        self.chars += prompt_chars
