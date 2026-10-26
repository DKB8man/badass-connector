import json
import logging
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime, timezone

_known = ContextVar("runner_log_known_literals", default=())


@contextmanager
def log_secret_scope(values=()):
    """Keep known literals local to a job; never retain a previous job's secrets."""
    token = _known.set(tuple(values))
    try:
        yield
    finally:
        _known.reset(token)


def remember_log_secrets(values):
    _known.set(tuple(set(_known.get()) | {v for v in values if isinstance(v, str) and v}))


def redact_log_value(value):
    # harness.__init__ imports the executor, which imports this logger.
    from .harness.sanitize import _redact_value
    return _redact_value(value, list(_known.get()))


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
        if record.stack_info:
            entry["stack"] = record.stack_info
        return json.dumps(redact_log_value(entry))


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
    numeric_level = getattr(logging, level.upper())
    if not logger.isEnabledFor(numeric_level):
        return
    record = logger.makeRecord(
        logger.name, numeric_level, "", 0, event, (), None
    )
    record.extra_fields = fields
    logger.handle(record)
