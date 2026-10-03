import os
import re
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime
from rich.logging import RichHandler

# Constants from environment or defaults
LOG_DIR = os.getenv("SPAF_LOG_DIR", "./logs")
LOG_LEVEL = os.getenv("SPAF_LOG_LEVEL", "INFO").upper()

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)


# ── Secret redaction ─────────────────────────────────────────────────────────
# Never let API keys, tokens, or Authorization headers reach a log sink.
_REDACTIONS = [
    # key=value / "key": "value" for sensitive key names
    (re.compile(r'(?i)(api[-_]?key|token|secret|password|passwd|authorization|'
                r'x-api-key|signing[-_]?key|google_api_key|anthropic_api_key|'
                r'openai_api_key|shodan_api_key)'
                r'(["\']?\s*[:=]\s*["\']?)([^\s"\',;]+)'), r"\1\2***REDACTED***"),
    # Bearer tokens
    (re.compile(r'(?i)\bBearer\s+[A-Za-z0-9._\-]+'), "Bearer ***REDACTED***"),
    # Long opaque tokens (sk-..., AIza..., ghp_..., 32+ base64url runs)
    (re.compile(r'\b(sk-[A-Za-z0-9]{10,}|AIza[A-Za-z0-9_\-]{20,}|'
                r'gh[pousr]_[A-Za-z0-9]{20,})'), "***REDACTED***"),
]


def redact(text: str) -> str:
    """Redact secrets from an arbitrary string."""
    if not text:
        return text
    for pat, repl in _REDACTIONS:
        text = pat.sub(repl, text)
    return text


class _RedactionFilter(logging.Filter):
    """Scrubs secrets from every formatted log record before it is emitted."""
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = redact(record.msg)
            if record.args:
                record.args = tuple(
                    redact(a) if isinstance(a, str) else a for a in record.args
                )
        except Exception:
            pass
        return True

def get_logger(name: str) -> logging.Logger:
    """
    Configures and returns a logger instance with both file and Rich console handlers.
    """
    logger = logging.getLogger(name)
    logger.setLevel(LOG_LEVEL)

    # Avoid adding handlers multiple times
    if not logger.handlers:
        redaction = _RedactionFilter()
        logger.addFilter(redaction)

        # Rich Console Handler
        rich_handler = RichHandler(rich_tracebacks=True, markup=True)
        rich_handler.setLevel(LOG_LEVEL)
        rich_handler.addFilter(redaction)
        logger.addHandler(rich_handler)

        # File Handler (Daily rotation)
        log_filename = os.path.join(LOG_DIR, f"spaf_{datetime.now().strftime('%Y%m%d')}.log")
        file_handler = TimedRotatingFileHandler(
            log_filename, when="midnight", interval=1, backupCount=30
        )
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(LOG_LEVEL)
        file_handler.addFilter(redaction)
        logger.addHandler(file_handler)

    return logger

# Global logger instance for general use
logger = get_logger("SPAF")
