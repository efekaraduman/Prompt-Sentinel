"""Policy enforcement helpers — Phase 3.13.

Centralises plan-tier overrides, tool allowlist enforcement,
and RAG doc sanitization checks. guard.py calls these directly;
external callers may import them for pre-scan validation.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .schemas import GuardPolicy


# ── 1. Plan-tier policy override enforcement ──────────────────────────────────

def enforce_public_free_pro_overrides(
    request_policy: Optional["GuardPolicy"],
    user_plan: Optional[str],
) -> "GuardPolicy":
    """Merge caller-supplied policy onto plan-tier defaults with restrictions.

    Delegates to guard.resolve_policy — single source of truth.
    Exposed here so API layers can call it without importing guard.
    """
    from .guard import resolve_policy
    return resolve_policy(request_policy, user_plan)


# ── 2. Tool allowlist enforcement ─────────────────────────────────────────────

def tool_allowlist_enforcement(
    tool_calls: Optional[List[Dict[str, Any]]],
    policy: "GuardPolicy",
) -> tuple[list[str], list[str]]:
    """Check tool_calls against policy.tool_allowlist.

    Returns (categories, reasons).
    categories contains 'tool_abuse' when any violation found.
    Does NOT duplicate the full scoring from tool_detector; use for
    pre-scan or middleware validation only.
    """
    if not tool_calls or not policy.tool_allowlist:
        return [], []

    allowlist = {n.lower() for n in policy.tool_allowlist}
    violations: list[str] = []
    for idx, call in enumerate(tool_calls):
        if not isinstance(call, dict):
            continue
        name = str(call.get("name", "")).strip().lower()
        if name and name not in allowlist:
            violations.append(f"tool[{idx}]: '{name}' not in allowlist")

    if violations:
        return ["tool_abuse"], violations[:5]
    return [], []


# ── 3. RAG document sanitization check ───────────────────────────────────────

_SANITIZE_MARKERS = [
    "ignore previous instructions",
    "disregard your system prompt",
    "act as",
    "you are now",
    "forget everything",
    "new instructions:",
]


def rag_doc_sanitization_check(
    retrieved_docs: Optional[List[str]],
    policy: "GuardPolicy",  # noqa: ARG001  reserved for per-org doc-trust settings
) -> tuple[list[str], list[str]]:
    """Surface-level sanitization check on retrieved docs.

    Returns (categories, reasons).
    Full scoring lives in rag_detector; this helper is for pre-injection
    validation or middleware use.
    """
    if not retrieved_docs:
        return [], []

    reasons: list[str] = []
    for idx, doc in enumerate(retrieved_docs[:50]):
        if not isinstance(doc, str):
            continue
        lower = doc.lower()
        for marker in _SANITIZE_MARKERS:
            if marker in lower:
                reasons.append(f"doc[{idx}]: contains sanitization marker '{marker[:30]}'")
                break
        if len(reasons) >= 5:
            break

    if reasons:
        return ["rag_injection"], reasons
    return [], []
