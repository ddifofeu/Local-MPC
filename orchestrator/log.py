"""Logging to stderr only (I7: stdout carries the MCP protocol) plus small shared helpers."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from datetime import datetime, timezone


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        audit = getattr(record, "audit", None)
        if audit:
            out.update(audit)
        return json.dumps(out, ensure_ascii=False, default=str)


def _setup_logging() -> logging.Logger:
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
    # Third-party DEBUG logs can include request metadata: cap them.
    for noisy in ("httpx", "httpcore", "anthropic", "mcp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return logging.getLogger("orchestrator-mcp")


logger = _setup_logging()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
