"""I3: API keys come from secret files and never appear in logs, errors or repr()."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from .log import sha256


class Secret:
    """Opaque holder: never printed, logged or serialised by accident."""

    __slots__ = ("_v",)

    def __init__(self, value: str):
        self._v = value

    def reveal(self) -> str:
        return self._v

    def fingerprint(self) -> str:
        return sha256(self._v)[:12]

    def __repr__(self) -> str:
        return "Secret(****)"

    __str__ = __repr__

    def __reduce__(self):
        raise TypeError("Secret is not serialisable")


def load_secret(name: str) -> Optional[Secret]:
    """Read a secret from $CREDENTIALS_DIRECTORY (systemd) or /run/secrets (Docker).

    Environment variables are accepted only with ORCH_ALLOW_ENV_SECRETS=1
    (dev convenience) because they leak via `docker inspect` and /proc/*/environ.
    """
    # Never leave the key in our own environ, whichever source wins.
    env_value = os.environ.pop(name.upper(), None)
    dirs = [os.environ.get("CREDENTIALS_DIRECTORY"), os.environ.get("ORCH_SECRETS_DIR", "/run/secrets")]
    for d in filter(None, dirs):
        p = Path(d) / name
        if p.is_file():
            if p.stat().st_mode & 0o077:
                raise PermissionError(f"secret file {p} is group/world accessible — chmod 400 it")
            value = p.read_text(encoding="utf-8").strip()
            if value:
                return Secret(value)
    if os.environ.get("ORCH_ALLOW_ENV_SECRETS") == "1" and env_value:
        return Secret(env_value)
    return None
