"""CyberShield - application logger (console + rotating file)."""
import logging
import os
from logging.handlers import RotatingFileHandler

from backend.config import Config

_LOG_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"
_configured = False


def setup_logging():
    global _configured
    if _configured:
        return
    os.makedirs(Config.DATA_DIR, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    console = logging.StreamHandler()
    console.setFormatter(logging.Formatter(_LOG_FORMAT))
    root.addHandler(console)

    file_handler = RotatingFileHandler(
        os.path.join(Config.DATA_DIR, "cybershield.log"),
        maxBytes=2_000_000, backupCount=3, encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT))
    root.addHandler(file_handler)
    _configured = True


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(name)
