#!/usr/bin/env python3
"""
Claude Orchestrator MCP Server (hardened)

Routes tasks across the Anthropic API and local inference (M970 / M5).

Security invariants (each one is enforced in code and covered by tests):
  I1  HIGH/CRITICAL tasks never reach a cloud provider — not by default routing,
      not by fallback, not by override. No route => error (fail closed).
  I2  Privacy detection can only RAISE the level (detectors, caller hint, floor).
  I3  API keys are read from secret files (/run/secrets or systemd credentials),
      never from config.json, and never appear in logs, errors or repr().
  I4  Prompts and responses are never logged or kept in history — only hashes,
      lengths, levels and routes.
  I5  Local inference is reached over HTTPS with a pinned CA (+ optional mTLS).
  I6  Every input is type/size-checked; concurrency, rate and cloud-call budget
      are bounded; fallback chains are finite and non-recursive.
  I7  stdout is reserved for the MCP stdio protocol; all logs go to stderr and
      to an append-only, hash-chained JSONL audit file.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import logging
import os
import re
import ssl
import sys
import time
import unicodedata
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import httpx

# ============================================================================
# Logging (stderr only — stdout carries the MCP protocol)
# ============================================================================


class _JsonFormatter(logging.Formatter):
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
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(os.getenv("LOG_LEVEL", "INFO").upper())
    # Third-party DEBUG logs can include request metadata: cap them.
    for noisy in ("httpx", "httpcore", "anthropic", "mcp"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    return logging.getLogger("orchestrator-mcp")


logger = _setup_logging()


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


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
        rec = {"ts": _utcnow(), "event": event, **fields, "prev": self._prev}
        line = json.dumps(rec, sort_keys=True, ensure_ascii=False, default=str)
        self._prev = hashlib.sha256(line.encode()).hexdigest()
        logger.info(event, extra={"audit": rec})
        if self._fh:
            self._fh.write(line + "\n")


# ============================================================================
# Types
# ============================================================================


class PrivacyLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)

    @staticmethod
    def max(*levels: "PrivacyLevel") -> "PrivacyLevel":
        return max(levels, key=lambda lv: lv.rank)


class TaskClassification(str, Enum):
    CODE_GENERATION = "code_generation"
    BUG_FIXING = "bug_fixing"
    ANALYSIS = "analysis"
    IMAGE_ANALYSIS = "image_analysis"
    REAL_TIME_KNOWLEDGE = "real_time_knowledge"
    TECHNICAL_WRITING = "technical_writing"
    DATA_PROCESSING = "data_processing"
    SECURITY_SENSITIVE = "security_sensitive"


class ModelProvider(str, Enum):
    CLAUDE_API = "claude_api"
    OPENAI_API = "openai_api"
    GEMINI_API = "gemini_api"
    LOCAL_M970 = "local_m970"
    LOCAL_M5 = "local_m5"


LOCAL_PROVIDERS = frozenset({ModelProvider.LOCAL_M970, ModelProvider.LOCAL_M5})
CLOUD_PROVIDERS = frozenset(set(ModelProvider) - LOCAL_PROVIDERS)


class OrchestratorError(Exception):
    code = "INTERNAL"
    public_message = "Internal error"

    def __init__(self, detail: str = "", public: Optional[str] = None):
        super().__init__(detail)
        if public:
            self.public_message = public


class InvalidInput(OrchestratorError):
    code = "INVALID_INPUT"
    public_message = "Invalid input"


class PolicyViolation(OrchestratorError):
    code = "POLICY_VIOLATION"
    public_message = "Request refused by privacy policy"


class NoRoute(OrchestratorError):
    code = "NO_ROUTE"
    public_message = "No provider allowed for this privacy level is available"


class RateLimited(OrchestratorError):
    code = "RATE_LIMITED"
    public_message = "Rate limit or budget exceeded"


class UpstreamFailure(OrchestratorError):
    code = "UPSTREAM_FAILURE"
    public_message = "All allowed providers failed"


# ============================================================================
# Secrets
# ============================================================================


class Secret:
    """Opaque holder: never printed, logged or serialised by accident."""

    __slots__ = ("_v",)

    def __init__(self, value: str):
        self._v = value

    def reveal(self) -> str:
        return self._v

    def fingerprint(self) -> str:
        return _sha256(self._v)[:12]

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


# ============================================================================
# Configuration (non-secret only)
# ============================================================================


DEFAULT_LIMITS = {
    "max_task_chars": 200_000,
    "max_response_chars": 400_000,
    "max_output_tokens": 4096,
    "max_concurrency": 4,
    "rate_per_minute": 30,
    "cloud_calls_per_process": 500,
    "request_timeout_s": 120,
    "history_size": 200,
}


@dataclass
class LocalEndpoint:
    provider: ModelProvider
    base_url: str
    model: str
    ca_file: Optional[str] = None
    client_cert: Optional[str] = None
    client_key: Optional[str] = None


@dataclass
class OrchestratorConfig:
    local_endpoints: dict = field(default_factory=dict)
    anthropic_model: str = "claude-sonnet-5-5"
    privacy_floor: PrivacyLevel = PrivacyLevel.LOW
    high_allows_cloud_fallback: bool = False  # keep False: HIGH == local-only
    extra_privacy_keywords: dict = field(default_factory=dict)
    limits: dict = field(default_factory=lambda: dict(DEFAULT_LIMITS))
    audit_log_file: Optional[str] = None
    workdir: Optional[str] = None  # allow-listed dir for input_file/output_file

    @classmethod
    def load(cls, path: Optional[str]) -> "OrchestratorConfig":
        path = path or os.getenv("ORCH_CONFIG", os.path.expanduser("~/.config/claude-orchestrator/config.json"))
        raw: dict = {}
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        if "api_keys" in raw:
            # I3: refuse to run with keys in a plaintext config file.
            raise PermissionError(
                f"{path} contains 'api_keys'. Remove them and use secret files "
                "(/run/secrets/anthropic_api_key)."
            )
        cfg = cls()
        allow_insecure = os.getenv("ORCH_ALLOW_INSECURE_LOCAL") == "1"
        for name, ep in (raw.get("local_endpoints") or {}).items():
            provider = ModelProvider(name)  # raises on unknown names
            if provider not in LOCAL_PROVIDERS:
                raise ValueError(f"{name} is not a local provider")
            url = ep["base_url"].rstrip("/")
            if not url.startswith("https://") and not allow_insecure:
                raise ValueError(f"{name}: base_url must be https:// (I5). Set ORCH_ALLOW_INSECURE_LOCAL=1 only for lab tests.")
            cfg.local_endpoints[provider] = LocalEndpoint(
                provider=provider, base_url=url, model=ep["model"],
                ca_file=ep.get("ca_file"), client_cert=ep.get("client_cert"), client_key=ep.get("client_key"),
            )
        cfg.anthropic_model = raw.get("anthropic_model", cfg.anthropic_model)
        cfg.privacy_floor = PrivacyLevel(raw.get("privacy_floor", "low"))
        cfg.high_allows_cloud_fallback = bool(raw.get("high_allows_cloud_fallback", False))
        extra = raw.get("privacy_keywords", {}) or {}
        for lvl, words in extra.items():
            # A bare string would be split into single characters and match almost everything.
            if lvl not in ("critical", "high", "medium") or not isinstance(words, list) \
                    or not all(isinstance(w, str) and w.strip() for w in words):
                raise ValueError(f"privacy_keywords.{lvl} must be a list of non-empty strings "
                                 "under critical|high|medium")
        cfg.extra_privacy_keywords = extra
        for k, v in (raw.get("limits") or {}).items():
            if k not in DEFAULT_LIMITS:
                raise ValueError(f"unknown limit {k!r}; valid: {sorted(DEFAULT_LIMITS)}")
            if isinstance(v, bool) or not isinstance(v, int) or v < 1:
                raise ValueError(f"limits.{k} must be a positive integer")
            cfg.limits[k] = v
        cfg.audit_log_file = raw.get("audit_log_file")
        cfg.workdir = raw.get("workdir")
        return cfg


# ============================================================================
# Privacy classification (can only raise the level — I2)
# ============================================================================

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

DEFAULT_KEYWORDS = {
    # accents are stripped before matching, so write them without accents
    "critical": [
        # EN
        "password", "passwd", "passphrase", "credential", "api key", "apikey", "access key",
        "secret", "private key", "ssh key", "seed phrase", "mnemonic", "2fa", "otp", "token",
        "security architecture", "vulnerability", "exploit", "proprietary", "confidential",
        "gdpr", "hipaa", "financial", "bank account", "credit card", "iban", "ssn",
        "health", "medical", "patient", "diagnosis", "prescription",
        # FR
        "mot de passe", "mdp", "identifiant", "cle api", "cle privee", "jeton", "confidentiel",
        "rgpd", "vulnerabilite", "architecture de securite", "carte bancaire", "compte bancaire",
        "securite sociale", "sante", "medical", "ordonnance", "diagnostic", "passeport",
        # PT / ES
        "senha", "credencial", "chave privada", "contrasena", "clave privada", "saude", "salud",
    ],
    "high": [
        "internal", "interne", "company", "entreprise", "infrastructure", "architecture",
        "deployment", "deploiement", "production", "database", "base de donnees", "compliance",
        "conformite", "client data", "donnees client", "salary", "salaire", "contract", "contrat",
    ],
    "medium": ["customer", "client", "user", "utilisateur", "personal", "personnel", "private", "prive", "sensitive", "sensible"],
}

# Content detectors: a single hit => CRITICAL, regardless of wording.
DETECTORS = {
    "anthropic_key": re.compile(r"sk-ant-[A-Za-z0-9_\-]{8,}"),
    "openai_key": re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*"),
    "pem_private_key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    "url_credentials": re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:[^\s@/]+@", re.I),
    "password_assignment": re.compile(r"\b(?:pass(?:word)?|pwd|mdp|senha|contrase[nñ]a)\s*[:=]\s*\S+", re.I),
}
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b")
_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _iban_ok(s: str) -> bool:
    s = s.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    moved = s[4:] + s[:4]
    digits = "".join(str(int(c, 36)) for c in moved)
    return int(digits) % 97 == 1


def _luhn_ok(s: str) -> bool:
    d = [int(c) for c in s if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total = 0
    for i, x in enumerate(reversed(d)):
        if i % 2:
            x *= 2
            x -= 9 if x > 9 else 0
        total += x
    return total % 10 == 0


def normalize(text: str) -> str:
    """NFKC (fullwidth/compat forms), drop format chars (zero-width…), casefold, strip accents."""
    t = unicodedata.normalize("NFKC", text)
    t = "".join(ch for ch in t if unicodedata.category(ch) != "Cf")
    t = t.casefold()
    t = unicodedata.normalize("NFKD", t)
    return "".join(ch for ch in t if not unicodedata.combining(ch))


def squash(norm: str) -> str:
    """Leet-decode and remove every non-alphanumeric char: 'p a s s w 0 r d' -> 'password'."""
    return re.sub(r"[^a-z0-9]", "", norm.translate(_LEET))


class PrivacyClassifier:
    def __init__(self, extra: dict):
        self.keywords = {lvl: [normalize(k) for k in DEFAULT_KEYWORDS.get(lvl, []) + list(extra.get(lvl, []))]
                         for lvl in ("critical", "high", "medium")}
        self.squashed_critical = [squash(k) for k in self.keywords["critical"] if len(squash(k)) >= 5]

    def classify(self, text: str) -> tuple[PrivacyLevel, list[str]]:
        reasons: list[str] = []
        nfkc = unicodedata.normalize("NFKC", text)
        for name, rx in DETECTORS.items():
            if rx.search(nfkc):
                reasons.append(f"detector:{name}")
        if any(_iban_ok(m.group()) for m in _IBAN.finditer(nfkc.upper())):
            reasons.append("detector:iban")
        if any(_luhn_ok(m.group()) for m in _CARD.finditer(nfkc)):
            reasons.append("detector:payment_card")
        norm = normalize(text)
        sq = squash(norm)
        for kw in self.keywords["critical"]:
            if kw in norm:
                reasons.append(f"kw:{kw}")
        for kw in self.squashed_critical:
            if kw in sq and f"kw:{kw}" not in reasons:
                reasons.append(f"kw~:{kw}")
        if reasons:
            return PrivacyLevel.CRITICAL, reasons[:10]
        for lvl, level in (("high", PrivacyLevel.HIGH), ("medium", PrivacyLevel.MEDIUM)):
            hits = [f"kw:{k}" for k in self.keywords[lvl] if k in norm]
            if hits:
                return level, hits[:10]
        return PrivacyLevel.LOW, []


# ============================================================================
# Task classification (quality routing only — never a security control)
# ============================================================================


def classify_task(text: str) -> TaskClassification:
    t = normalize(text)
    has = lambda *words: any(re.search(rf"\b{re.escape(w)}", t) for w in words)  # noqa: E731
    if has("security", "securite", "pentest", "threat model", "audit"):
        return TaskClassification.SECURITY_SENSITIVE
    if has("refactor", "fix", "debug", "bug", "error", "stack trace"):
        return TaskClassification.BUG_FIXING
    if has("image", "screenshot", "photo", "visual"):
        return TaskClassification.IMAGE_ANALYSIS
    if has("latest", "recent", "current", "today", "news", "real-time"):
        return TaskClassification.REAL_TIME_KNOWLEDGE
    if has("write", "blog", "article", "document", "essay", "redige"):
        return TaskClassification.TECHNICAL_WRITING
    if has("categorize", "classify", "process", "transform", "extract", "batch"):
        return TaskClassification.DATA_PROCESSING
    if has("code", "implement", "build", "create", "generate"):
        return TaskClassification.CODE_GENERATION
    return TaskClassification.ANALYSIS


# ============================================================================
# Routing
# ============================================================================

MODEL_MATRIX = {
    TaskClassification.CODE_GENERATION: [ModelProvider.CLAUDE_API, ModelProvider.OPENAI_API, ModelProvider.LOCAL_M5],
    TaskClassification.BUG_FIXING: [ModelProvider.CLAUDE_API, ModelProvider.OPENAI_API, ModelProvider.LOCAL_M5],
    TaskClassification.ANALYSIS: [ModelProvider.CLAUDE_API, ModelProvider.GEMINI_API, ModelProvider.LOCAL_M5],
    TaskClassification.IMAGE_ANALYSIS: [ModelProvider.GEMINI_API, ModelProvider.CLAUDE_API],
    TaskClassification.REAL_TIME_KNOWLEDGE: [ModelProvider.OPENAI_API, ModelProvider.GEMINI_API, ModelProvider.CLAUDE_API],
    TaskClassification.TECHNICAL_WRITING: [ModelProvider.CLAUDE_API, ModelProvider.LOCAL_M5],
    TaskClassification.DATA_PROCESSING: [ModelProvider.LOCAL_M970, ModelProvider.LOCAL_M5, ModelProvider.CLAUDE_API],
    TaskClassification.SECURITY_SENSITIVE: [ModelProvider.LOCAL_M5, ModelProvider.LOCAL_M970],
}
LOCAL_ONLY_CHAIN = [ModelProvider.LOCAL_M5, ModelProvider.LOCAL_M970]
LATENCY_ESTIMATES = {ModelProvider.CLAUDE_API: 1500, ModelProvider.OPENAI_API: 2000, ModelProvider.GEMINI_API: 2500,
                     ModelProvider.LOCAL_M970: 3000, ModelProvider.LOCAL_M5: 2500}
OVERRIDES = {"@local", "@private", "@claude", "@openai", "@gemini", "@fast", "@cheap"}
OVERRIDE_TARGET = {"@claude": ModelProvider.CLAUDE_API, "@openai": ModelProvider.OPENAI_API, "@gemini": ModelProvider.GEMINI_API}
MAX_CHAIN = 3


@dataclass
class RoutingDecision:
    decision_id: str
    timestamp: str
    task_sha256: str
    task_chars: int
    privacy_level: PrivacyLevel
    privacy_reasons: list
    classification: TaskClassification
    chain: list
    rationale: str

    def public(self) -> dict:
        # I4: no task text, ever.
        return {
            "decision_id": self.decision_id, "timestamp": self.timestamp,
            "task_sha256": self.task_sha256[:16], "task_chars": self.task_chars,
            "privacy_level": self.privacy_level.value, "privacy_reasons": self.privacy_reasons,
            "classification": self.classification.value,
            "primary_route": self.chain[0].value, "fallback_routes": [p.value for p in self.chain[1:]],
            "rationale": self.rationale,
        }


class TaskRouter:
    def __init__(self, config: OrchestratorConfig, available: set):
        self.config = config
        self.available = available  # providers that are implemented AND configured
        self.classifier = PrivacyClassifier(config.extra_privacy_keywords)

    def _cloud_allowed(self, level: PrivacyLevel) -> bool:
        if level is PrivacyLevel.CRITICAL:
            return False
        if level is PrivacyLevel.HIGH:
            return self.config.high_allows_cloud_fallback
        return True

    def route(self, task: str, override: Optional[str] = None, declared: Optional[PrivacyLevel] = None) -> RoutingDecision:
        detected, reasons = self.classifier.classify(task)
        classification = classify_task(task)
        levels = [detected, self.config.privacy_floor]
        if declared:
            levels.append(declared)
            reasons = reasons + [f"declared:{declared.value}"]
        if classification is TaskClassification.SECURITY_SENSITIVE:
            levels.append(PrivacyLevel.HIGH)
            reasons = reasons + ["class:security_sensitive"]
        level = PrivacyLevel.max(*levels)
        cloud_ok = self._cloud_allowed(level)

        if level.rank >= PrivacyLevel.HIGH.rank:
            chain = list(LOCAL_ONLY_CHAIN) + ([ModelProvider.CLAUDE_API] if cloud_ok else [])
        else:
            chain = list(MODEL_MATRIX[classification])
        rationale = f"{classification.value} task, privacy={level.value}"

        if override:
            if override in ("@local", "@private"):
                chain = list(LOCAL_ONLY_CHAIN)  # local-only, no cloud fallback
            elif override in OVERRIDE_TARGET:
                target = OVERRIDE_TARGET[override]
                if not cloud_ok:
                    raise PolicyViolation(f"override {override} on {level.value} task",
                                          public=f"Override {override} refused: task classified {level.value} (local-only)")
                chain = [target] + [p for p in chain if p is not target]
            elif override == "@cheap":
                chain = [ModelProvider.LOCAL_M970, ModelProvider.LOCAL_M5] + [p for p in chain if p not in LOCAL_PROVIDERS]
            elif override == "@fast":
                chain = sorted(chain, key=lambda p: LATENCY_ESTIMATES[p])
            rationale += f", override={override}"

        # Enforce I1 last, whatever happened above.
        seen, final = set(), []
        for p in chain:
            if p in seen or p not in self.available:
                continue
            if p in CLOUD_PROVIDERS and not cloud_ok:
                continue
            seen.add(p)
            final.append(p)
        final = final[:MAX_CHAIN]
        if not final:
            raise NoRoute(f"no available provider for level={level.value} override={override}")

        return RoutingDecision(
            decision_id=str(uuid.uuid4()), timestamp=_utcnow(), task_sha256=_sha256(task), task_chars=len(task),
            privacy_level=level, privacy_reasons=reasons[:10], classification=classification,
            chain=final, rationale=rationale,
        )


# ============================================================================
# Execution
# ============================================================================


class ExecutionEngine:
    def __init__(self, config: OrchestratorConfig, anthropic_key: Optional[Secret]):
        self.config = config
        lim = config.limits
        self.timeout = httpx.Timeout(lim["request_timeout_s"], connect=5.0)
        self.anthropic = None
        if anthropic_key:
            import anthropic  # imported lazily so the router is testable without the SDK
            self.anthropic = anthropic.AsyncAnthropic(
                api_key=anthropic_key.reveal(), timeout=lim["request_timeout_s"], max_retries=1)
        self.local_clients: dict = {}
        for provider, ep in config.local_endpoints.items():
            # Explicit SSLContext: pinned private CA (not the public trust store) + client cert for mTLS.
            ctx = ssl.create_default_context(cafile=ep.ca_file) if ep.ca_file else ssl.create_default_context()
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if ep.client_cert:
                ctx.load_cert_chain(ep.client_cert, ep.client_key)
            self.local_clients[provider] = httpx.AsyncClient(
                base_url=ep.base_url, verify=ctx,
                trust_env=False,  # ignore HTTP(S)_PROXY: LAN traffic must never be sent to a proxy
                timeout=self.timeout, follow_redirects=False,
                limits=httpx.Limits(max_connections=lim["max_concurrency"]))

    def available(self) -> set:
        avail = set(self.local_clients)
        if self.anthropic:
            avail.add(ModelProvider.CLAUDE_API)
        # OPENAI_API / GEMINI_API: not implemented -> never routable (no fake success).
        return avail

    async def run(self, provider: ModelProvider, task: str) -> str:
        if provider is ModelProvider.CLAUDE_API:
            msg = await self.anthropic.messages.create(
                model=self.config.anthropic_model, max_tokens=self.config.limits["max_output_tokens"],
                messages=[{"role": "user", "content": task}])
            text = "".join(b.text for b in msg.content if getattr(b, "type", "text") == "text")
        elif provider in self.local_clients:
            ep = self.config.local_endpoints[provider]
            r = await self.local_clients[provider].post("/api/generate", json={
                "model": ep.model, "prompt": task, "stream": False,
                "options": {"num_predict": self.config.limits["max_output_tokens"]}})
            r.raise_for_status()
            text = r.json()["response"]
            if not isinstance(text, str):
                raise ValueError("malformed local response")
        else:
            raise NotImplementedError(provider.value)
        return text[: self.config.limits["max_response_chars"]]

    async def health(self, provider: ModelProvider) -> dict:
        try:
            r = await self.local_clients[provider].get("/api/version", timeout=5.0)
            r.raise_for_status()
            return {"available": True, "version": str(r.json().get("version", "?"))[:32]}
        except Exception as e:  # noqa: BLE001
            logger.warning("health check failed", extra={"audit": {"provider": provider.value, "error": type(e).__name__}})
            return {"available": False}


# ============================================================================
# Orchestrator core (transport-agnostic)
# ============================================================================


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


class Orchestrator:
    def __init__(self, config: OrchestratorConfig, anthropic_key: Optional[Secret]):
        self.config = config
        self.audit = AuditLog(config.audit_log_file)
        self.engine = ExecutionEngine(config, anthropic_key)
        self.router = TaskRouter(config, self.engine.available())
        lim = config.limits
        self.history: deque = deque(maxlen=lim["history_size"])
        self.sem = asyncio.Semaphore(lim["max_concurrency"])
        self.bucket = _TokenBucket(lim["rate_per_minute"])
        self.cloud_calls = 0
        self.audit.emit("startup", providers=sorted(p.value for p in self.router.available),
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
        self._record(d, executed_on=None, outcome="routed")
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
        self._record(d, executed_on=used, outcome="success", latency_ms=latency, response_chars=len(text))
        result = {"provider": used.value, "latency_ms": latency, "timestamp": _utcnow()}
        if output_file is not None:
            out = self._path(output_file, must_exist=False)
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(text)
            result.update(output_file=str(out), response_sha256=_sha256(text)[:16], response_chars=len(text))
        else:
            result["response"] = text
        return {"status": "success", "routing": d.public(), "execution": result}

    async def _run_chain(self, d: RoutingDecision, task: str):
        for provider in d.chain:  # finite, non-recursive (I6)
            if provider in CLOUD_PROVIDERS:
                # Defence in depth: re-check I1 at the last possible moment.
                if d.privacy_level is PrivacyLevel.CRITICAL or (
                        d.privacy_level is PrivacyLevel.HIGH and not self.config.high_allows_cloud_fallback):
                    raise PolicyViolation("cloud provider in chain for sensitive task")
                if self.cloud_calls >= self.config.limits["cloud_calls_per_process"]:
                    self.audit.emit("budget_exceeded", decision_id=d.decision_id)
                    continue
                self.cloud_calls += 1
            try:
                return await self.engine.run(provider, task), provider
            except Exception as e:  # noqa: BLE001
                self.audit.emit("provider_failure", decision_id=d.decision_id, provider=provider.value,
                                error=type(e).__name__, status=getattr(getattr(e, "response", None), "status_code", None))
        raise UpstreamFailure(f"chain exhausted: {[p.value for p in d.chain]}")

    async def tool_history(self, limit=10) -> dict:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= self.history.maxlen:
            raise InvalidInput("bad limit", public=f"'limit' must be an integer in 1..{self.history.maxlen}")
        return {"status": "success", "data": list(self.history)[-limit:]}

    async def tool_resources(self) -> dict:
        self._gate()
        data = {p.value: await self.engine.health(p) for p in self.engine.local_clients}
        return {"status": "success", "data": data}

    def _record(self, d: RoutingDecision, **extra):
        rec = {**d.public(), **extra, "executed_on": extra.get("executed_on").value if extra.get("executed_on") else None}
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


# ============================================================================
# MCP transport — stdio only (no listening socket => no network attack surface)
# ============================================================================


def build_mcp(core: Orchestrator):
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP("orchestrator", log_level="WARNING")

    @mcp.tool()
    async def route_task(task: str, override: Optional[str] = None, privacy: Optional[str] = None) -> dict:
        """Classify a task and return the routing decision (no execution). 'privacy' can only raise the level."""
        return await core.call("route_task", {"task": task, "override": override, "privacy": privacy})

    @mcp.tool()
    async def execute_task(task: Optional[str] = None, override: Optional[str] = None, privacy: Optional[str] = None,
                           input_file: Optional[str] = None, output_file: Optional[str] = None) -> dict:
        """Route and execute. For sensitive content prefer input_file/output_file (paths inside the workdir):
        the content then never transits through the calling model's context."""
        return await core.call("execute_task", {"task": task, "override": override, "privacy": privacy,
                                                "input_file": input_file, "output_file": output_file})

    @mcp.tool()
    async def get_routing_history(limit: int = 10) -> dict:
        """Recent routing decisions (metadata only, never task text)."""
        return await core.call("get_routing_history", {"limit": limit})

    @mcp.tool()
    async def check_resources() -> dict:
        """Health of local inference endpoints."""
        return await core.call("check_resources", {})

    return mcp


def main() -> None:
    ap = argparse.ArgumentParser(description="Orchestrator MCP server (stdio)")
    ap.add_argument("--config", default=None)
    args = ap.parse_args()
    config = OrchestratorConfig.load(args.config)
    core = Orchestrator(config, load_secret("anthropic_api_key"))
    build_mcp(core).run(transport="stdio")


if __name__ == "__main__":
    main()
