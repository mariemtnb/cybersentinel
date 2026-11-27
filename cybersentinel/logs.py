"""Structured logging.

Each log line is a single JSON object (timestamp, level, logger, message, plus any extra
fields such as source or run_id). JSON lines are easy to grep locally and easy to ship to a
log service later. A filter masks the NVD API key if it ever appears in a message (for
example inside a URL), so secrets do not leak into logs.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime

_RESERVED = set(vars(logging.LogRecord("x", 0, "", 0, "", None, None)).keys()) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="seconds"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class SecretMaskFilter(logging.Filter):
    """Replace known secret values with '***' in every log record."""

    def __init__(self) -> None:
        super().__init__()
        self.secrets = [s for s in (os.environ.get("NVD_API_KEY"), os.environ.get("ALERT_WEBHOOK_URL")) if s]

    def filter(self, record: logging.LogRecord) -> bool:
        if self.secrets:
            message = record.getMessage()
            for secret in self.secrets:
                message = message.replace(secret, "***")
            record.msg, record.args = message, None
        return True


def setup_logging(level: str = "INFO") -> None:
    # We do not use asyncio task names in logs. Disabling the lookup also avoids a crash seen
    # with CPython 3.13 on Windows when asyncio.current_task() is called outside an event loop.
    logging.logAsyncioTasks = False
    root = logging.getLogger()
    if any(getattr(h, "_cybersentinel", False) for h in root.handlers):
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    handler.addFilter(SecretMaskFilter())
    handler._cybersentinel = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level.upper())
    for noisy in ("urllib3", "botocore", "boto3", "s3transfer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"cybersentinel.{name}")
