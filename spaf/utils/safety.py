"""
Output-handling and command-execution safety controls.

Two jobs:

1. **Never execute untrusted text as a shell command.** SPAF builds subprocess
   argument *lists* (never ``shell=True``), but model-generated or
   finding-derived strings can still flow toward a command. :func:`assert_safe_argv`
   and :func:`is_dangerous_command` are a defence-in-depth denylist that refuses
   obviously destructive invocations.

2. **Sanitize generated content** before it is logged, stored, or rendered.
   :func:`sanitize_ai_text` strips control characters, caps length, and neutralises
   the markers a prompt-injection payload would use to look like instructions.

These are deliberately conservative: they reduce blast radius, they are not a
substitute for scope enforcement and authorization (which gate *whether* a target
may be touched at all).
"""

from __future__ import annotations

import re
import shlex
from typing import Iterable, List

# Maximum characters of model/finding-derived text kept in one field.
MAX_AI_TEXT = 20_000

# Substrings/patterns that mark a destructive or system-altering shell command.
_DANGEROUS_PATTERNS = [
    r"\brm\s+-rf?\b", r"\brmdir\b", r"\bmkfs\.", r"\bdd\s+if=", r"\b>\s*/dev/sd",
    r":\(\)\s*\{", r"\bfork\b\s*bomb", r"\bshutdown\b", r"\breboot\b", r"\bhalt\b",
    r"\bchmod\s+-R\s+0?777\b", r"\bchown\s+-R\b", r"/etc/passwd", r"/etc/shadow",
    r"\bcurl\b[^|]*\|\s*(sh|bash|zsh)\b", r"\bwget\b[^|]*\|\s*(sh|bash|zsh)\b",
    r"\bnc\b.*\s-e\b", r"\bbash\s+-i\b", r"\b/dev/tcp/", r"\beval\b", r"\bexec\b",
    r"\bsudo\b", r"\bsu\s+-", r"\bkill(all)?\s+-9\b", r"\bcrontab\b",
    r"\biptables\b", r"\bsystemctl\b", r"\bexport\s+\w+=", r"\$\(", r"`",
]
_DANGEROUS_RE = re.compile("|".join(_DANGEROUS_PATTERNS), re.IGNORECASE)

# Shell metacharacters that should never appear in a single argv token.
_SHELL_METACHARS = re.compile(r"[;&|`$><\n\r\\]")

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class UnsafeCommandError(ValueError):
    """Raised when a command or argument is rejected by the safety denylist."""


def is_dangerous_command(text: str) -> bool:
    """True if *text* matches a destructive/system-altering shell pattern."""
    return bool(text) and bool(_DANGEROUS_RE.search(text))


def assert_safe_argv(argv: Iterable[str]) -> List[str]:
    """
    Validate a subprocess argument list before it is executed.

    Rejects shell metacharacters embedded in any single token (which only matter
    if someone later re-routes the list through a shell) and any token matching
    the destructive-command denylist. Returns the list unchanged when safe.
    """
    argv = list(argv)
    joined = " ".join(argv)
    if is_dangerous_command(joined):
        raise UnsafeCommandError(f"refused dangerous command: {joined!r}")
    for tok in argv:
        if _SHELL_METACHARS.search(tok):
            raise UnsafeCommandError(f"refused argument with shell metacharacters: {tok!r}")
    return argv


def sanitize_ai_text(text: str, *, max_len: int = MAX_AI_TEXT) -> str:
    """
    Make model-generated (or otherwise untrusted) text safe to log/store/show.

    Strips control characters, caps length, and defangs prompt-injection markers
    so stored content can never masquerade as live instructions.
    """
    if text is None:
        return ""
    s = _CONTROL_CHARS.sub("", str(text))
    # Defang common injection framing without destroying readability.
    s = re.sub(r"(?i)\b(ignore|disregard)\s+(all\s+)?previous\s+instructions\b",
               "[redacted-injection]", s)
    s = s.replace(" ", " ").replace(" ", " ")
    if len(s) > max_len:
        s = s[:max_len] + "\n…[truncated]"
    return s.strip()


def shlex_safe_split(command: str) -> List[str]:
    """Split a command string into a validated argv list (no shell execution)."""
    return assert_safe_argv(shlex.split(command))
