from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Optional

from .log import logger, utcnow


class AuditLog:
    """Append-only JSONL audit trail, hash-chained so truncation/edits are detectable."""

    def __init__(self, path: Optional[str]):
        self._prev = "genesis"
        self._fh = None
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            if p.exists() and p.stat().st_size > 0:
                with p.open("rb") as f:
                    f.seek(max(0, p.stat().st_size - 65536))
                    last = f.read().splitlines()[-1]
                self._prev = hashlib.sha256(last).hexdigest()
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self._fh = os.fdopen(fd, "a", buffering=1, encoding="utf-8")

    def emit(self, event: str, **fields) -> None:
        rec = {"ts": utcnow(), "event": event, **fields, "prev": self._prev}
        line = json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str)
        self._prev = hashlib.sha256(line.encode()).hexdigest()
        logger.info(event, extra={"audit": rec})
        if self._fh:
            self._fh.write(line + "\n")
