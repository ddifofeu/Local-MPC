"""Transport-agnostic orchestrator: validation, rate limits, execution, history, error boundary."""

from __future__ import annotations

import asyncio
import os
import re
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Optional

import httpx

from .audit import AuditLog
from .config import OrchestratorConfig
from .errors import InvalidInput, OrchestratorError, PolicyViolation, RateLimited, UpstreamFailure
from .log import logger, sha256, utcnow
from .models import PrivacyLevel
from .providers import Provider, build_providers
from .routing import OVERRIDES, RoutingDecision, TaskRouter
from .secret import Secret


class _TokenBucket:
    def __init__(self, per_minute: int):
        self.capacity = float(per_minute)
        self.tokens = float(per_minute)
        self.rate = per_minute / 60.0
        self.last = time.monotonic()

    def take(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last) * self.rate)
        self.last = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Only "could not reach it" trips the cooldown; HTTP errors or bad payloads mean the node is up.
_UNREACHABLE = (httpx.ConnectError, httpx.ConnectTimeout)


class Orchestrator:
    def __init__(self, config: OrchestratorConfig, anthropic_key: Optional[Secret]):
        self.config = config
        self.audit = AuditLog(config.audit_log_file)
        self.providers = build_providers(config, anthropic_key)
        self.router = TaskRouter(config, self.providers)
        lim = config.limits
        self.history: deque = deque(maxlen=lim["history_size"])
        self.sem = asyncio.Semaphore(lim["max_concurrency"])
        self.bucket = _TokenBucket(lim["rate_per_minute"])
        self.cloud_calls = 0
        self.unreachable_until: dict = {}
        self.audit.emit("startup", providers=sorted(p.value for p in self.providers),
                        anthropic_key_fp=anthropic_key.fingerprint() if anthropic_key else None,
                        privacy_floor=config.privacy_floor.value)

    # ---------------------------------------------------------- validation
    def _task(self, task) -> str:
        if not isinstance(task, str):
            raise InvalidInput("task not a string", public="'task' must be a string")
        if _CTRL.search(task):
            raise InvalidInput("control characters", public="'task' contains control characters (NUL etc.)")
        if not task.strip():
            raise InvalidInput("empty", public="'task' is empty")
        if len(task) > self.config.limits["max_task_chars"]:
            raise InvalidInput("too long", public=f"'task' exceeds {self.config.limits['max_task_chars']} characters")
        return task

    @staticmethod
    def _override(o) -> Optional[str]:
        if o in (None, ""):
            return None
        if not isinstance(o, str) or o not in OVERRIDES:
            raise InvalidInput("bad override", public=f"'override' must be one of {sorted(OVERRIDES)}")
        return o

    @staticmethod
    def _declared(p) -> Optional[PrivacyLevel]:
        if p in (None, ""):
            return None
        try:
            return PrivacyLevel(p)
        except ValueError:
            raise InvalidInput("bad privacy", public="'privacy' must be low|medium|high|critical") from None

    def _path(self, p: str, must_exist: bool) -> Path:
        if not self.config.workdir:
            raise InvalidInput("no workdir", public="file I/O disabled (no 'workdir' configured)")
        root = Path(self.config.workdir).resolve()
        cand = (root / p).resolve()
        if not cand.is_relative_to(root):
            raise InvalidInput("path traversal", public="path must stay inside the configured workdir")
        if must_exist and not cand.is_file():
            raise InvalidInput("missing file", public="input_file not found")
        return cand

    def _gate(self):
        if not self.bucket.take():
            raise RateLimited("rate")

    # ---------------------------------------------------------- tools
    async def tool_route(self, task, override=None, privacy=None) -> dict:
        self._gate()
        d = self.router.route(self._task(task), self._override(override), self._declared(privacy))
        self._record(d, None, outcome="routed")
        return {"status": "success", "data": d.public()}

    async def tool_execute(self, task=None, override=None, privacy=None, input_file=None, output_file=None) -> dict:
        self._gate()
        if input_file is not None:
            if task:
                raise InvalidInput("both", public="use either 'task' or 'input_file', not both")
            p = self._path(input_file, must_exist=True)
            if p.stat().st_size > self.config.limits["max_task_chars"] * 4:
                raise InvalidInput("file too big", public="input_file too large")
            task = p.read_text(encoding="utf-8")
        task = self._task(task)
        d = self.router.route(task, self._override(override), self._declared(privacy))
        t0 = time.monotonic()
        async with self.sem:
            text, used = await self._run_chain(d, task)
        latency = int((time.monotonic() - t0) * 1000)
        self._record(d, used, outcome="success", latency_ms=latency, response_chars=len(text))
        result = {"provider": used.id.value, "latency_ms": latency, "timestamp": utcnow()}
        if output_file is not None:
            out = self._path(output_file, must_exist=False)
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            result.update(output_file=str(out), response_sha256=sha256(text)[:16], response_chars=len(text))
        else:
            result["response"] = text
        return {"status": "success", "routing": d.public(), "execution": result}

    async def _run_chain(self, d: RoutingDecision, task: str) -> tuple[str, Provider]:
        for pid in d.chain:  # finite, non-recursive (I6)
            provider = self.providers[pid]
            if not provider.is_local:
                # Defence in depth: re-check I1 at the last possible moment.
                if not self.router.cloud_allowed(d.privacy_level):
                    raise PolicyViolation("cloud provider in chain for sensitive task")
            if time.monotonic() < self.unreachable_until.get(pid, 0):
                self.audit.emit("provider_skipped", decision_id=d.decision_id, provider=pid.value, reason="cooldown")
                continue
            if not provider.is_local:
                if self.cloud_calls >= self.config.limits["cloud_calls_per_process"]:
                    self.audit.emit("budget_exceeded", decision_id=d.decision_id)
                    continue
                self.cloud_calls += 1
            try:
                text = await provider.generate(task)
                return text[: self.config.limits["max_response_chars"]], provider
            except Exception as e:  # noqa: BLE001
                if isinstance(e, _UNREACHABLE):
                    self.unreachable_until[pid] = time.monotonic() + self.config.limits["provider_cooldown_s"]
                self.audit.emit("provider_failure", decision_id=d.decision_id, provider=pid.value,
                                error=type(e).__name__, status=getattr(getattr(e, "response", None), "status_code", None))
        raise UpstreamFailure(f"chain exhausted: {[p.value for p in d.chain]}")

    async def tool_history(self, limit=10) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= self.history.maxlen:
            raise InvalidInput("bad limit", public=f"'limit' must be an integer in 1..{self.history.maxlen}")
        return {"status": "success", "data": list(self.history)[-limit:]}

    async def tool_resources(self) -> dict:
        self._gate()
        data = {pid.value: await p.health() for pid, p in self.providers.items() if p.is_local}
        return {"status": "success", "data": data}

    def _record(self, d: RoutingDecision, executed: Optional[Provider], **extra):
        rec = {**d.public(), **extra,
               "executed_on": executed.id.value if executed else None,
               "executed_local": executed.is_local if executed else None}
        self.history.append(rec)
        self.audit.emit("decision", **rec)

    async def call(self, name: str, args: dict) -> dict:
        """Uniform error boundary: callers only ever see a code + safe message + error_id."""
        handlers = {"route_task": self.tool_route, "execute_task": self.tool_execute,
                    "get_routing_history": self.tool_history, "check_resources": self.tool_resources}
        error_id = uuid.uuid4().hex[:12]
        try:
            if name not in handlers:
                raise InvalidInput("unknown tool", public="unknown tool")
            if not isinstance(args, dict):
                raise InvalidInput("args", public="arguments must be an object")
            return await handlers[name](**args)
        except TypeError as e:
            self.audit.emit("error", tool=name, code="INVALID_INPUT", error_id=error_id, error=type(e).__name__)
            return {"status": "error", "code": "INVALID_INPUT", "message": "unexpected or missing arguments", "error_id": error_id}
        except OrchestratorError as e:
            self.audit.emit("error", tool=name, code=e.code, error_id=error_id, detail=str(e)[:200])
            return {"status": "error", "code": e.code, "message": e.public_message, "error_id": error_id}
        except Exception as e:  # noqa: BLE001
            logger.error("unhandled", extra={"audit": {"tool": name, "error_id": error_id, "error": type(e).__name__}})
            return {"status": "error", "code": "INTERNAL", "message": "internal error", "error_id": error_id}
