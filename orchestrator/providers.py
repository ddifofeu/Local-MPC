"""Model backends. `is_local` is what the privacy policy (I1) keys on."""

from __future__ import annotations

import ssl
from typing import Optional

import httpx

from .config import LocalEndpoint, OrchestratorConfig
from .log import logger
from .models import ModelProvider
from .secret import Secret


class Provider:
    id: ModelProvider
    is_local: bool

    async def generate(self, task: str) -> str:
        raise NotImplementedError

    async def health(self) -> dict:
        raise NotImplementedError


class AnthropicProvider(Provider):
    id = ModelProvider.CLAUDE_API
    is_local = False

    def __init__(self, key: Secret, model: str, max_tokens: int, timeout_s: int):
        import anthropic  # imported lazily so routing is testable without the SDK

        self.client = anthropic.AsyncAnthropic(api_key=key.reveal(), timeout=timeout_s, max_retries=1)
        self.model = model
        self.max_tokens = max_tokens

    async def generate(self, task: str) -> str:
        msg = await self.client.messages.create(
            model=self.model, max_tokens=self.max_tokens, messages=[{"role": "user", "content": task}])
        return "".join(b.text for b in msg.content if getattr(b, "type", "text") == "text")

    async def health(self) -> dict:
        return {"available": True}


class OllamaProvider(Provider):
    """Ollama behind an mTLS gateway (I5): pinned private CA, optional client cert, no proxies."""

    is_local = True

    def __init__(self, ep: LocalEndpoint, max_tokens: int, timeout_s: int, max_connections: int):
        self.id = ep.provider
        self.model = ep.model
        self.max_tokens = max_tokens
        ctx = ssl.create_default_context(cafile=ep.ca_file) if ep.ca_file else ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        if ep.client_cert:
            ctx.load_cert_chain(ep.client_cert, ep.client_key)
        self.client = httpx.AsyncClient(
            base_url=ep.base_url, verify=ctx,
            trust_env=False,  # ignore HTTP(S)_PROXY: LAN traffic must never be sent to a proxy
            timeout=httpx.Timeout(timeout_s, connect=5.0), follow_redirects=False,
            limits=httpx.Limits(max_connections=max_connections))

    async def generate(self, task: str) -> str:
        r = await self.client.post("/api/generate", json={
            "model": self.model, "prompt": task, "stream": False,
            "options": {"num_predict": self.max_tokens}})
        r.raise_for_status()
        text = r.json()["response"]
        if not isinstance(text, str):
            raise ValueError("malformed local response")
        return text

    async def health(self) -> dict:
        try:
            r = await self.client.get("/api/version", timeout=5.0)
            r.raise_for_status()
            return {"available": True, "version": str(r.json().get("version", "?"))[:32]}
        except Exception as e:  # noqa: BLE001
            logger.warning("health check failed", extra={"audit": {"provider": self.id.value, "error": type(e).__name__}})
            return {"available": False}


def build_providers(config: OrchestratorConfig, anthropic_key: Optional[Secret]) -> dict:
    """Only implemented AND configured providers are returned, so nothing else is ever routable."""
    lim = config.limits
    providers: dict = {}
    if anthropic_key:
        providers[ModelProvider.CLAUDE_API] = AnthropicProvider(
            anthropic_key, config.anthropic_model, lim["max_output_tokens"], lim["request_timeout_s"])
    for pid, ep in config.local_endpoints.items():
        providers[pid] = OllamaProvider(ep, lim["max_output_tokens"], lim["request_timeout_s"], lim["max_concurrency"])
    return providers
