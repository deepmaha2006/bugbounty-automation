"""Structured (JSON) logging with request/organization correlation
(CVM platform spec §22).

Every API/worker/connector log line should be machine-parseable and
correlated by request_id/job_id/organization_id. This module provides:
  - `configure_logging()`: installs a JSON formatter on the root logger.
  - `request_id_var`/`organization_id_var`: contextvars set per-request
    (main.py's middleware sets request_id; auth.py's `_resolve_user` sets
    organization_id once the caller's identity is known) and read back by
    `_ContextFilter` so every log record emitted during that request/task
    carries both — without every call site having to pass them explicitly.
"""
import contextvars
import json
import logging
import os

request_id_var: contextvars.ContextVar = contextvars.ContextVar("request_id", default=None)
organization_id_var: contextvars.ContextVar = contextvars.ContextVar("organization_id", default=None)

_RESERVED = set(logging.LogRecord(
    "", 0, "", 0, "", (), None
).__dict__.keys()) | {"message", "asctime"}


class _ContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        record.organization_id = organization_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", None),
            "organization_id": getattr(record, "organization_id", None),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and key not in payload:
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


_configured = False


def configure_logging(level: str = None) -> None:
    """Idempotent — safe to call from both the API startup path and test
    setup without installing duplicate handlers."""
    global _configured
    if _configured:
        return
    _configured = True
    root = logging.getLogger()
    root.setLevel((level or os.environ.get("HYDRAX_LOG_LEVEL", "INFO")).upper())
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    handler.addFilter(_ContextFilter())
    root.handlers = [handler]
