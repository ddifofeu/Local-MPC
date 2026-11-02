"""Non-secret configuration. Keys never live here (I3)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Optional

from .models import LOCAL_ENDPOINT_NAMES, ModelProvider, PrivacyLevel

DEFAULT_LIMITS = {
    "max_task_chars": 200_000,
    "max_response_chars": 400_000,
    "max_output_tokens": 4096,
    "max_concurrency": 4,
    "rate_per_minute": 30,
    "cloud_calls_per_process": 500,
    "request_timeout_s": 120,
    "history_size": 200,
    "provider_cooldown_s": 30,
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
            raise PermissionError(
                f"{path} contains 'api_keys'. Remove them and use secret files "
                "(/run/secrets/anthropic_api_key)."
            )
        cfg = cls()
        allow_insecure = os.getenv("ORCH_ALLOW_INSECURE_LOCAL") == "1"
        for name, ep in (raw.get("local_endpoints") or {}).items():
            provider = ModelProvider(name)  # raises on unknown names
            if provider not in LOCAL_ENDPOINT_NAMES:
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
