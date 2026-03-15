"""Redact sensitive-looking strings from API output."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

_PATTERNS = [
    # API keys / tokens (generic long hex/base64 strings).
    (re.compile(r"(?:api[_-]?key|token|secret|password|bearer)\s*[:=]\s*['\"]?([A-Za-z0-9_\-/.+=]{16,})['\"]?", re.IGNORECASE), r"[REDACTED]"),
    # sk-... style keys (OpenAI).
    (re.compile(r"\b(sk-[A-Za-z0-9]{20,})\b"), r"[REDACTED]"),
    # GitHub tokens (ghp_, gho_, ghs_, ghr_).
    (re.compile(r"\b(gh[posr]_[A-Za-z0-9]{20,})\b"), r"[REDACTED]"),
    # Google API keys.
    (re.compile(r"\b(AIza[A-Za-z0-9_-]{30,})\b"), r"[REDACTED]"),
    # AWS access keys (AKIA / ASIA prefix).
    (re.compile(r"\b((?:AKIA|ASIA)[A-Z0-9]{12,})\b"), r"[REDACTED]"),
    # JWT tokens (eyJ... pattern).
    (re.compile(r"(?:eyJ[A-Za-z0-9_-]{10,}\.){1,2}[A-Za-z0-9_-]+"), r"[REDACTED]"),
    # Bearer / Basic auth headers with long tokens.
    (re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9+/=_-]{20,}\b"), r"[REDACTED]"),
    # Generic long hex/base64 secrets after common key names.
    (re.compile(r"(?:(?:access|auth|refresh|session)[_-]?(?:key|token|secret))\s*[:=]\s*['\"]?\S{16,}['\"]?", re.IGNORECASE), r"[REDACTED]"),
    # Email addresses.
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"), r"[REDACTED_EMAIL]"),
    # SSN-like patterns (###-##-####).
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), r"[REDACTED_ID]"),
    # Phone-like patterns (10+ digit sequences with optional dashes/spaces/parens).
    (re.compile(r"(?:\+?\d[\d\s\-().]{8,}\d)"), r"[REDACTED_PHONE]"),
]


def redact_string(text: Optional[str]) -> Optional[str]:
    """Apply all redaction patterns to a string."""
    if not text:
        return text
    result = text
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_finding_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Redact sensitive fields in a finding dict (for API/export output)."""
    out = dict(d)
    for key in ("llm_response", "notes", "attack_prompt"):
        if key in out and isinstance(out[key], str):
            out[key] = redact_string(out[key])
    return out


def redact_finding_list(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [redact_finding_dict(d) for d in items]
