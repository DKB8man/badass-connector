import json
import logging
import sys
from datetime import datetime, timezone


class _StructuredFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict = {
            "time": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        if hasattr(record, "extra_fields"):
            entry.update(record.extra_fields)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry)


def get_logger(name: str = "badass_runner") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_StructuredFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def log(logger: logging.Logger, level: str, event: str, **fields) -> None:
    """Helper to emit a structured log entry with extra fields."""
    record = logger.makeRecord(
        logger.name, getattr(logging, level.upper()), "", 0, event, (), None
    )
    record.extra_fields = fields
    logger.handle(record)
