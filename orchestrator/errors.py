from __future__ import annotations

from typing import Optional


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
