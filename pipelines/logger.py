"""Shared logging setup for the vulnerability management pipeline.

Every module should import `get_logger` and request a logger named for
itself (usually `__name__`). The first call configures the root pipeline
logger with a console handler and a rotating-safe file handler writing
to `logs/pipeline.log`. Subsequent calls reuse that configuration.
"""

import logging
import os
from logging import Logger
from pathlib import Path

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
DEFAULT_LEVEL = logging.INFO

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_LOG_DIR = _PROJECT_ROOT / "logs"
_LOG_FILE = _LOG_DIR / "pipeline.log"

_ROOT_NAME = "pipeline"
_configured = False


def _configure_root() -> None:
    """Attach console + file handlers to the `pipeline` logger once."""
    global _configured
    if _configured:
        return

    _LOG_DIR.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger(_ROOT_NAME)
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    root.setLevel(getattr(logging, level_name, DEFAULT_LEVEL))
    root.propagate = False

    formatter = logging.Formatter(LOG_FORMAT)

    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root.addHandler(console)

    file_handler = logging.FileHandler(_LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    _configured = True


def get_logger(name: str | None = None) -> Logger:
    """Return a pipeline-scoped logger.

    Pass `__name__` from the caller; the returned logger inherits the
    shared handlers and format. If `name` is None, the root pipeline
    logger is returned.
    """
    _configure_root()
    if not name or name == _ROOT_NAME:
        return logging.getLogger(_ROOT_NAME)
    # Namespace every logger under `pipeline.` so one config applies.
    suffix = name.split(".")[-1] if name.startswith(_ROOT_NAME) else name
    return logging.getLogger(f"{_ROOT_NAME}.{suffix}")
