from __future__ import annotations

import fcntl
import hashlib
import json
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from .log import logger, utcnow

_TAIL = 65536


def anchor_path(path) -> str:
    return f"{path}.anchor"


def _sha(line: bytes) -> str:
    return hashlib.sha256(line).hexdigest()


def _last_line(fd: int, size: int) -> bytes:
    """Read back from the end until a whole last line is in hand."""
    span = _TAIL
    while True:
        start = max(0, size - span)
        lines = os.pread(fd, size - start, start).splitlines()
        if start == 0 or len(lines) > 1:
            return lines[-1] if lines else b""
        span *= 2


def anchor_problem(fd: int, path) -> Optional[str]:
    """Why the log no longer matches its anchor, or None."""
    size = os.fstat(fd).st_size
    try:
        with open(anchor_path(path), encoding="utf-8") as f:
            anchor = json.load(f)
        anchored, expected = int(anchor["size"]), str(anchor["sha256"])
    except FileNotFoundError:
        return "anchor missing" if size else None
    except (ValueError, KeyError, TypeError):
        return "anchor unreadable"
    if size < anchored:
        return "log is shorter than its anchor"
    if anchored and (os.pread(fd, 1, anchored - 1) != b"\n" or _sha(_last_line(fd, anchored)) != expected):
        return "log differs from its anchor"
    return None


class AuditLog:
    """Append-only JSONL audit trail, hash-chained so edits and removals are detectable.

    The file can be shared: Claude Code starts one server per session, so each append takes an
    exclusive lock and chains from the file's real last line, not from a value kept in memory.

    A chain alone cannot show that records were cut from the end. The `.anchor` file beside the log
    records its size and last-record hash after every append, and a log that no longer matches is
    recorded as `audit_anchor_mismatch` at startup. Neither is keyed: someone who can rewrite the
    log and its anchor together goes undetected, unless the anchor is also copied elsewhere.
    """

    def __init__(self, path: Optional[str]):
        self._prev = "genesis"
        self._fd = None
        self._path = path
        problem = None
        if path:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
            self._fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
            with self._locked():
                problem = anchor_problem(self._fd, path)
        if problem:
            self.emit("audit_anchor_mismatch", problem=problem)

    @contextmanager
    def _locked(self):
        fcntl.flock(self._fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(self._fd, fcntl.LOCK_UN)

    def _write_anchor(self, size: int, last_hash: str) -> None:
        tmp = f"{anchor_path(self._path)}.{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"size": size, "sha256": last_hash}, f)
        os.replace(tmp, anchor_path(self._path))

    @staticmethod
    def _line(rec: dict, prev: str) -> str:
        return json.dumps({**rec, "prev": prev}, sort_keys=True, ensure_ascii=False, default=str)

    def emit(self, event: str, **fields) -> None:
        rec = {"ts": utcnow(), "event": event, **fields}
        if self._fd is None:
            line = self._line(rec, self._prev)
            self._prev = _sha(line.encode())
        else:
            with self._locked():
                size = os.fstat(self._fd).st_size
                prev = _sha(_last_line(self._fd, size)) if size else "genesis"
                line = self._line(rec, prev)
                data = line.encode() + b"\n"
                os.write(self._fd, data)
                self._write_anchor(size + len(data), _sha(line.encode()))
        logger.info(event, extra={"audit": json.loads(line)})
