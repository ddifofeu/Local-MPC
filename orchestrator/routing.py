from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional

from .config import OrchestratorConfig
from .errors import NoRoute, PolicyViolation
from .log import sha256, utcnow
from .models import ModelProvider, PrivacyLevel, TaskClassification
from .privacy import PrivacyClassifier, classify_task

CLAUDE, M5, M970 = ModelProvider.CLAUDE_API, ModelProvider.LOCAL_M5, ModelProvider.LOCAL_M970

MODEL_MATRIX = {
    TaskClassification.CODE_GENERATION: [CLAUDE, M5],
    TaskClassification.BUG_FIXING: [CLAUDE, M5],
    TaskClassification.ANALYSIS: [CLAUDE, M5],
    TaskClassification.IMAGE_ANALYSIS: [CLAUDE],
    TaskClassification.REAL_TIME_KNOWLEDGE: [CLAUDE],
    TaskClassification.TECHNICAL_WRITING: [CLAUDE, M5],
    TaskClassification.DATA_PROCESSING: [M970, M5, CLAUDE],
    TaskClassification.SECURITY_SENSITIVE: [M5, M970],
}
LOCAL_ONLY_CHAIN = [M5, M970]
CHEAP_CHAIN = [M970, M5]
LATENCY_ESTIMATES = {CLAUDE: 1500, M970: 3000, M5: 2500}
OVERRIDES = {"@local", "@private", "@claude", "@fast", "@cheap"}
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
    def __init__(self, config: OrchestratorConfig, providers: dict):
        self.config = config
        self.providers = providers  # implemented AND configured, keyed by ModelProvider
        self.classifier = PrivacyClassifier(config.extra_privacy_keywords)

    def cloud_allowed(self, level: PrivacyLevel) -> bool:
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
        cloud_ok = self.cloud_allowed(level)

        if level.rank >= PrivacyLevel.HIGH.rank:
            chain = list(LOCAL_ONLY_CHAIN) + ([CLAUDE] if cloud_ok else [])
        else:
            chain = list(MODEL_MATRIX[classification])
        rationale = f"{classification.value} task, privacy={level.value}"

        if override:
            if override in ("@local", "@private"):
                chain = list(LOCAL_ONLY_CHAIN)  # local-only, no cloud fallback
            elif override == "@claude":
                if not cloud_ok:
                    raise PolicyViolation(f"override {override} on {level.value} task",
                                          public=f"Override {override} refused: task classified {level.value} (local-only)")
                chain = [CLAUDE] + chain
            elif override == "@cheap":
                chain = CHEAP_CHAIN + chain
            elif override == "@fast":
                chain = sorted(chain, key=lambda p: LATENCY_ESTIMATES[p])
            rationale += f", override={override}"

        # Enforce I1 last, whatever happened above.
        final = []
        for p in chain:
            provider = self.providers.get(p)
            if provider is None or p in final:
                continue
            if not provider.is_local and not cloud_ok:
                continue
            final.append(p)
        final = final[:MAX_CHAIN]
        if not final:
            raise NoRoute(f"no available provider for level={level.value} override={override}")

        return RoutingDecision(
            decision_id=str(uuid.uuid4()), timestamp=utcnow(), task_sha256=sha256(task), task_chars=len(task),
            privacy_level=level, privacy_reasons=reasons[:10], classification=classification,
            chain=final, rationale=rationale,
        )
