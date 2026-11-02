from __future__ import annotations

from enum import Enum


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
    """Values are config keys and audit-log fields: do not rename."""

    CLAUDE_API = "claude_api"
    LOCAL_M970 = "local_m970"
    LOCAL_M5 = "local_m5"


LOCAL_ENDPOINT_NAMES = frozenset({ModelProvider.LOCAL_M970, ModelProvider.LOCAL_M5})
