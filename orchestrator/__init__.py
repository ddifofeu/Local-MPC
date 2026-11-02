"""Claude Orchestrator MCP server (hardened).

Routes tasks across the Anthropic API and local inference (M970 / M5).

Security invariants (each one is enforced in code and covered by tests):
  I1  HIGH/CRITICAL tasks never reach a cloud provider — not by default routing,
      not by fallback, not by override. No route => error (fail closed).       routing.py, core.py
  I2  Privacy detection can only RAISE the level.                              privacy.py, routing.py
  I3  API keys come from secret files, never config.json, logs, errors, repr.  secret.py, config.py
  I4  Prompts and responses are never logged or kept in history.               routing.py, core.py
  I5  Local inference is reached over HTTPS with a pinned CA (+ optional mTLS). providers.py
  I6  Inputs are type/size-checked; concurrency, rate and cloud budget are
      bounded; fallback chains are finite and non-recursive.                   core.py
  I7  stdout is reserved for MCP stdio; logs go to stderr and a hash-chained
      JSONL audit file.                                                        log.py, audit.py
"""

from .log import JsonFormatter, logger  # first: installs the stderr-only log handler (I7)
from .config import OrchestratorConfig
from .core import Orchestrator
from .models import ModelProvider, PrivacyLevel, TaskClassification
from .privacy import PrivacyClassifier
from .secret import Secret, load_secret

__all__ = [
    "JsonFormatter", "logger", "OrchestratorConfig", "Orchestrator", "ModelProvider", "PrivacyLevel",
    "TaskClassification", "PrivacyClassifier", "Secret", "load_secret",
]
