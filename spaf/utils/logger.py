import os
import logging
from logging.handlers import TimedRotatingFileHandler
from datetime import datetime
from rich.logging import RichHandler

# Constants from environment or defaults
LOG_DIR = os.getenv("SPAF_LOG_DIR", "./logs")
LOG_LEVEL = os.getenv("SPAF_LOG_LEVEL", "INFO").upper()

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def get_logger(name: str) -> logging.Logger:
    """
    Configures and returns a logger instance with both file and Rich console handlers.
    """
    logger = logging.getLogger(name)
    logger.setLevel(LOG_LEVEL)

    # Avoid adding handlers multiple times
    if not logger.handlers:
        # Rich Console Handler
        rich_handler = RichHandler(rich_tracebacks=True, markup=True)
        rich_handler.setLevel(LOG_LEVEL)
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
        logger.addHandler(file_handler)

    return logger

# Global logger instance for general use
logger = get_logger("SPAF")
