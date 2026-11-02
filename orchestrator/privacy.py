"""Privacy classification. Detection can only RAISE the level (I2)."""

from __future__ import annotations

import re
import unicodedata

from .models import PrivacyLevel, TaskClassification

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


# Task classification: quality routing only, never a security control.


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
