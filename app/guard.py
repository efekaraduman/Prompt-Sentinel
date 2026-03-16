"""Runtime guard — single-shot input/output scan reusing existing risk_analyzer."""
from __future__ import annotations

import hashlib
import json
import logging
import math
import random as _random
import re
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Session, select

from .risk_analyzer import (
    _SECRET_PATTERNS,
    _detect_leakage,
    _detect_override,
    _score_single_test,
)
from .schemas import GuardPolicy, GuardScanResponse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_WORD_RE = re.compile(r"\b\w+\b")
# Matches standalone numbers and common date/decimal forms (e.g. 42, 3.14, 2024-01-15)
_NUM_DATE_RE = re.compile(r"\b\d+(?:[.,\-/]\d+)*\b")
# Invisible / zero-width unicode and soft-hyphen
_INVIS_RE = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]")


# ---------------------------------------------------------------------------
# Signature helpers
# ---------------------------------------------------------------------------

def normalize_for_sig(text: str) -> str:
    """Lowercase, strip invisible chars, collapse whitespace — deterministic."""
    text = _INVIS_RE.sub("", text)
    text = text.lower()
    text = re.sub(r"\s+", " ", text).strip()
    return text


# Category priority for top_category (lower number = higher priority)
_CAT_PRIORITY: dict[str, int] = {
    "pii": 0,
    "prompt_injection": 1,
    "tool_abuse": 1,       # Phase 3.4
    "hallucination": 2,
}


def _upsert_signature(
    session: Session,
    sig_hash: str,
    categories: list[str],
    snippet: str,
) -> int:
    """Insert or update AttackSignature row. Returns the updated count. Never raises."""
    from .models import AttackSignature  # local import to avoid circular at module load

    try:
        now = datetime.now(timezone.utc)
        top_cat: str | None = (
            min(categories, key=lambda c: _CAT_PRIORITY.get(c, 99))
            if categories else None
        )
        existing = session.exec(
            select(AttackSignature).where(AttackSignature.signature_hash == sig_hash)
        ).first()

        if existing is not None:
            existing.count += 1
            existing.last_seen_at = now
            if top_cat is not None:
                existing.top_category = top_cat
            session.add(existing)
            session.commit()
            return existing.count
        else:
            row = AttackSignature(
                signature_hash=sig_hash,
                first_seen_at=now,
                last_seen_at=now,
                count=1,
                top_category=top_cat,
                example_snippet=snippet[:200],
            )
            session.add(row)
            session.commit()
            return 1
    except Exception as _sig_exc:
        logger.warning("_upsert_signature: failed to persist sig_hash=%s — %s", sig_hash, _sig_exc)
        return 0


# ---------------------------------------------------------------------------
# Policy resolution
# ---------------------------------------------------------------------------

# Base policy dicts per tier — defined once, never mutated
_TIER_DEFAULTS: dict[str, dict] = {
    "public": dict(
        block_injection=True,
        block_pii=True,
        block_high_risk=True,
        allow_medium=False,
        block_hallucination=False,
        block_rag_injection=True,        # Phase 3.3
        block_tool_abuse=True,           # Phase 3.4
        tool_allowlist=None,             # Phase 3.4
        max_elapsed_ms=None,             # Phase 3.6
        deterministic=False,             # Phase 3.6
        block_on_low_consensus=False,    # Phase 3.7
        min_consensus_to_allow=0,        # Phase 3.7
    ),
    "free": dict(
        block_injection=True,
        block_pii=True,
        block_high_risk=True,
        allow_medium=False,
        block_hallucination=False,
        block_rag_injection=True,        # Phase 3.3
        block_tool_abuse=True,           # Phase 3.4
        tool_allowlist=None,             # Phase 3.4
        max_elapsed_ms=None,             # Phase 3.6
        deterministic=False,             # Phase 3.6
        block_on_low_consensus=False,    # Phase 3.7
        min_consensus_to_allow=0,        # Phase 3.7
    ),
    "pro": dict(
        block_injection=True,
        block_pii=True,
        block_high_risk=True,
        allow_medium=True,               # pro tier unlocks medium-risk pass-through
        block_hallucination=False,
        block_rag_injection=True,        # Phase 3.3 — pro may override to False
        block_tool_abuse=True,           # Phase 3.4 — pro may override to False
        tool_allowlist=None,             # Phase 3.4
        max_elapsed_ms=None,             # Phase 3.6
        deterministic=False,             # Phase 3.6
        block_on_low_consensus=False,    # Phase 3.7
        min_consensus_to_allow=0,        # Phase 3.7
    ),
}


def resolve_policy(
    request_policy: Optional[GuardPolicy],
    user_plan: Optional[str],
) -> GuardPolicy:
    """Merge caller-supplied policy onto plan-tier defaults with per-tier restrictions.

    Rules:
    - public (no auth / unknown plan): cannot weaken block_pii or block_injection
    - free: cannot enable allow_medium
    - pro: all fields may be overridden
    - If request_policy is None, return the tier default as-is.
    """
    tier = user_plan if user_plan in _TIER_DEFAULTS else "public"
    merged = dict(_TIER_DEFAULTS[tier])  # shallow copy — safe, all values are primitives

    if request_policy is not None:
        for field in request_policy.model_fields_set:
            value = getattr(request_policy, field)

            # public: cannot weaken block_pii, block_injection, block_rag_injection, block_tool_abuse
            if tier == "public" and field in (
                "block_pii", "block_injection", "block_rag_injection", "block_tool_abuse"
            ) and value is False:
                continue

            # free: cannot enable allow_medium or disable security flags
            if tier == "free" and field == "allow_medium" and value is True:
                continue
            if tier == "free" and field in ("block_rag_injection", "block_tool_abuse") and value is False:
                continue

            merged[field] = value

    return GuardPolicy(**merged)


# ---------------------------------------------------------------------------
# Severity helper
# ---------------------------------------------------------------------------

def _severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Injection / leakage / PII scanner
# ---------------------------------------------------------------------------

def _scan(text: str) -> tuple[int, float, bool, bool, bool]:
    """Return (score, confidence, is_injection, is_leakage, is_pii). Never raises."""
    try:
        # Pass empty system_prompt — no overlap heuristic, pattern detection still runs
        leakage, leak_w = _detect_leakage("", text)
        override, over_w = _detect_override(text)
        score, conf = _score_single_test(leakage, override, leak_w, over_w)
        is_pii = any(pat.search(text) for pat in _SECRET_PATTERNS)
        return score, conf, override, leakage, is_pii
    except Exception:
        return 0, 0.0, False, False, False


# ---------------------------------------------------------------------------
# Hallucination scorer
# ---------------------------------------------------------------------------

def _score_hallucination(
    output: Optional[str],
    context: Optional[str],
) -> tuple[int, float, list[str]]:
    """Return (hallucination_score 0-100, grounding_score 0-1, reasons).

    Strategy:
    - No context → score=0, grounding=0.0, reason="no context provided"
    - Lexical overlap: (unique output words found in context) / unique output words
    - Flags: grounding < 0.2 → "low grounding"
             ≥3 numbers/dates in output absent from context → "unsupported claims"
    """
    if not context or not context.strip():
        return 0, 0.0, ["no context provided"]

    if not output or not output.strip():
        return 0, 1.0, []

    out_words = set(_WORD_RE.findall(output.lower()))
    ctx_words = set(_WORD_RE.findall(context.lower()))

    if not out_words:
        return 0, 1.0, []

    overlap = len(out_words & ctx_words) / len(out_words)
    grounding = round(min(1.0, max(0.0, overlap)), 4)
    h_score = round((1.0 - grounding) * 100)

    reasons: list[str] = []
    if grounding < 0.2:
        reasons.append("low grounding")

    out_nums = set(_NUM_DATE_RE.findall(output))
    ctx_nums = set(_NUM_DATE_RE.findall(context))
    if len(out_nums - ctx_nums) >= 3:
        reasons.append("unsupported claims")

    return h_score, grounding, reasons


# ---------------------------------------------------------------------------
# RAG injection patterns (Phase 3.3)
# ---------------------------------------------------------------------------

_RAG_INJECTION_PATTERNS: list = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions?", re.I),
    re.compile(r"system\s+prompt", re.I),
    re.compile(r"developer\s+message", re.I),
    re.compile(r"you\s+are\s+(?:gpt|chatgpt|claude|an?\s+ai\b)", re.I),
    re.compile(r"do\s+not\s+follow", re.I),
    re.compile(r"\boverride\s+(?:\w+\s+)*(?:instructions?|rules?|settings?|constraints?)", re.I),
    re.compile(r"\bbegin\s+system\b", re.I),
    re.compile(r"###\s*instruction\s+hierarchy", re.I),
    re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior)", re.I),
    re.compile(r"new\s+instructions?:", re.I),
    re.compile(r"<\s*/?\s*system\s*>", re.I),
    re.compile(r"\[system\]", re.I),
]
_HTML_COMMENT_RE = re.compile(r"<!--.+?-->", re.DOTALL)
_MD_COMMENT_RE   = re.compile(r"\[//\]:\s*#\s*\(", re.I)
_BASE64_LONG_RE  = re.compile(r"[A-Za-z0-9+/]{80,}={0,2}")  # suspicious base64 block

# Extended instruction-in-doc patterns (RAG instruction injection)
_RAG_INSTRUCTION_PATTERNS: list = [
    re.compile(r"\byou\s+are\s+now\b", re.I),
    re.compile(r"\bact\s+as\b", re.I),
    re.compile(r"\bpretend\s+to\s+be\b", re.I),
    re.compile(r"\byour\s+(?:new\s+)?(?:instructions?|role|task|job|purpose)\s+(?:is|are)\b", re.I),
    re.compile(r"\bfrom\s+now\s+on\b", re.I),
    re.compile(r"\bfor\s+all\s+future\b", re.I),
    re.compile(r"\bwhen(?:ever)?\s+(?:asked|prompted|the\s+user)\b", re.I),
    re.compile(r"\byou\s+(?:must|should|need\s+to|have\s+to)\s+(?:always|never|immediately|only|instead)\b", re.I),
    re.compile(r"\b(?:always|never)\s+(?:respond|reply|answer|say|tell|output)\b", re.I),
    re.compile(r"\b(?:respond|reply|answer|output)\s+only\s+with\b", re.I),
    re.compile(r"\bdo\s+not\s+(?:reveal|disclose|mention|tell|share)\b", re.I),
    re.compile(r"\byour\s+new\s+(?:goal|mission|objective|directive)\b", re.I),
    # Enhanced: output-format injection
    re.compile(r"\bformat\s+(?:your|all|every)?\s*(?:responses?|answers?|outputs?)\s+(?:as|in|like)\b", re.I),
    re.compile(r"\brespond\s+(?:only\s+)?(?:in|using)\s+(?:json|xml|yaml|markdown|html|csv)\b", re.I),
    re.compile(r"\bstructure\s+(?:your|all|every)\s+(?:responses?|outputs?|answers?)\b", re.I),
    # Enhanced: output exfiltration
    re.compile(r"\bappend\s+(?:this|the\s+following|these\s+words?)\s+to\s+(?:every|each|all)\b", re.I),
    re.compile(r"\binclude\s+(?:this|the\s+following)\s+(?:text|phrase|sentence|string)\s+in\s+(?:every|each|all|your)\b", re.I),
    re.compile(r"\bprefix\s+(?:every|each|all)\s+(?:responses?|outputs?|answers?)\b", re.I),
    # Enhanced: memory / persistent instruction injection
    re.compile(r"\bremember\s+(?:this|the\s+following|these)\s+(?:instructions?|rules?|guidelines?|directives?)\b", re.I),
    re.compile(r"\bstore\s+(?:this|these|the\s+following)\s+(?:instructions?|commands?|rules?|context)\b", re.I),
    # Enhanced: conditional instructions
    re.compile(r"\bif\s+(?:the\s+user|anyone|you\s+are)\s+(?:asks?|requests?|queries|mentions?|brings?\s+up)\b", re.I),
    re.compile(r"\bwhenever\s+(?:the\s+user|anyone|you)\s+(?:asks?\s+(?:about|for)|mentions?|brings?\s+up)\b", re.I),
]

# Contradiction / conflicting-fact cue phrases
_CONFLICT_PHRASES: list = [
    re.compile(r"\bthat\s+is\s+(?:incorrect|wrong|false|not\s+true|inaccurate|untrue)\b", re.I),
    re.compile(r"\bthe\s+(?:correct|real|actual|true)\s+(?:answer|value|fact|information|data)\b", re.I),
    re.compile(r"\bcontrary\s+to\b", re.I),
    re.compile(r"\bthe\s+opposite\s+(?:is|was)\s+true\b", re.I),
    re.compile(r"\b(?:actually|in\s+fact|in\s+reality)\s*,\s*(?:the\s+)?(?:correct|true|real)\b", re.I),
    re.compile(r"\b(?:this\s+is\s+(?:a\s+)?(?:lie|misinformation|false|fake))\b", re.I),
    re.compile(r"\bdo\s+not\s+trust\b", re.I),
    re.compile(r"\bignore\s+(?:the\s+)?(?:above|previous|prior|last)\b", re.I),
    # Enhanced: adversarial fact-replacement signals
    re.compile(r"\byou\s+(?:have\s+been|were)\s+(?:given|told|fed)\s+(?:false|wrong|incorrect|misleading|fabricated)\b", re.I),
    re.compile(r"\b(?:this\s+(?:source|document|passage)|the\s+above)\s+(?:is|contains)\s+(?:false|incorrect|wrong|misleading|fabricated)\b", re.I),
    re.compile(r"\bthe\s+(?:real|true|correct|accurate)\s+(?:figure|number|value|statistic|count|price|date)\b", re.I),
    re.compile(r"\bdon'?t\s+believe\b", re.I),
    re.compile(r"\bsupersed(?:e|es|ing)\s+(?:the\s+)?(?:previous|above|prior|old|earlier)\b", re.I),
    re.compile(r"\bthis\s+(?:information|data|content)\s+(?:has\s+been\s+)?(?:tampered|manipulated|altered|corrupted)\b", re.I),
    re.compile(r"\boverwrite\s+(?:the\s+)?(?:previous|prior|above|original)\s+(?:data|information|context|facts?)\b", re.I),
]

# Sentence-boundary split for entropy windowing
_SENT_RE = re.compile(r"(?<=[.!?])\s+")


def _shannon_entropy(text: str) -> float:
    """Shannon entropy in bits/char over character distribution.

    English prose: ~3.5–4.5 bits/char.
    Encoded / obfuscated data: typically > 5.5 bits/char.
    Random bytes: ~6.0 bits/char.
    """
    if len(text) < 8:
        return 0.0
    freq = Counter(text)
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _has_high_entropy_segment(doc: str, window: int = 80, threshold: float = 5.5) -> bool:
    """Return True if any sliding window of *window* chars has entropy > *threshold*."""
    text = doc.strip()
    if len(text) < window:
        return _shannon_entropy(text) > threshold
    step = max(1, window // 2)
    for start in range(0, len(text) - window + 1, step):
        segment = text[start:start + window]
        # Skip segments that look like URLs or code (high entropy but benign)
        if re.search(r"https?://|www\.", segment, re.I):
            continue
        if _shannon_entropy(segment) > threshold:
            return True
    return False


def _detect_entropy_outlier_sentence(doc: str, z_threshold: float = 2.5) -> tuple[bool, str]:
    """Detect a single anomalously high-entropy sentence within an otherwise normal document.

    Rationale: an attacker may embed one encoded/obfuscated command inside benign prose.
    The sliding-window check misses this when the surrounding text is long enough to
    dilute the window average.  Sentence-level z-score catches per-sentence outliers.

    Returns (flagged, snippet_of_offending_sentence).
    """
    sentences = [s.strip() for s in _SENT_RE.split(doc) if len(s.strip()) >= 12]
    if len(sentences) < 3:  # too few sentences for meaningful statistics
        return False, ""
    entropies = [_shannon_entropy(s) for s in sentences]
    mean_e = sum(entropies) / len(entropies)
    if mean_e < 1.0:  # doc is near-empty / all same chars — not meaningful
        return False, ""
    variance = sum((e - mean_e) ** 2 for e in entropies) / len(entropies)
    std_e = variance ** 0.5
    if std_e < 0.2 or std_e == 0.0:  # all sentences have similar entropy — no outlier possible
        return False, ""
    for sentence, e in zip(sentences, entropies):
        z = (e - mean_e) / std_e  # safe: std_e > 0 guaranteed by guard above
        # Must be a statistical outlier AND above the prose-to-encoded boundary (~5 bits)
        if z > z_threshold and e > 5.0:
            return True, sentence[:60]
    return False, ""


# Regex for extracting (key-term, numeric-value) pairs used in cross-doc conflict detection
_TERM_NUM_RE = re.compile(
    r'\b([A-Za-z]\w{3,19})\s*(?:is|was|are|were|:|=|totals?|equals?|amounts?\s+to)\s*'
    r'(\d{1,15}(?:[.,]\d+)?)\b',
    re.I,
)


def _detect_cross_doc_conflicts(docs: list[str]) -> tuple[int, list[str]]:
    """Detect when the same key term carries contradictory numeric values across documents.

    This catches corpus-poisoning attacks where an adversary injects a document that
    re-defines a fact (e.g., price, count, date) to differ from all other sources.

    Returns (conflict_count, human-readable reasons up to 3).
    """
    # term -> set of (value, doc_idx) pairs so we can report which docs conflict
    term_vals: dict[str, dict[str, int]] = {}
    for doc_idx, doc in enumerate(docs):
        if not isinstance(doc, str):
            continue
        for m in _TERM_NUM_RE.finditer(doc):
            term = m.group(1).lower()
            val = m.group(2).replace(",", ".")
            if term not in term_vals:
                term_vals[term] = {}
            # First occurrence wins per doc (avoid over-counting repeated mentions)
            if val not in term_vals[term]:
                term_vals[term][val] = doc_idx

    conflicts = 0
    reasons: list[str] = []
    for term, val_map in term_vals.items():
        if len(val_map) > 1:
            conflicts += 1
            vals_str = " vs ".join(sorted(val_map.keys())[:3])
            reasons.append(f"conflicting values for '{term}': {vals_str}")

    return conflicts, reasons[:3]


def _compute_rag_risk_score(
    hits_injection: int,
    hits_instruction: int,
    hits_conflict: int,
    hits_entropy: int,
    hits_cross_conflict: int = 0,
    flagged_docs: int = 0,
    total_docs: int = 0,
) -> int:
    """Combine sub-check hit counts into a single rag_risk_score (0–100).

    Weights ordered by threat severity:
      injection marker    → highest (known attack payload, direct override)
      cross-doc conflict  → high    (corpus-poisoning via numeric fact substitution)
      conflicting facts   → high    (linguistic contradiction markers)
      instruction         → medium  (embedded LLM command)
      entropy outlier     → low     (obfuscation signal, not conclusive alone)

    Doc-density multiplier: when ≥40% of retrieved docs are flagged, the attack
    is broad/systematic rather than a single noisy document, so the score is boosted
    by 15% (capped at 100).
    """
    injection_score      = min(60, hits_injection      * 20)
    cross_conflict_score = min(20, hits_cross_conflict  * 12)
    conflict_score       = min(25, hits_conflict        * 25)
    instruction_score    = min(20, hits_instruction     * 10)
    entropy_score        = min(15, hits_entropy         * 8)

    base = min(100, injection_score + cross_conflict_score + conflict_score
               + instruction_score + entropy_score)

    # Doc-density boost: systematic attack across many retrieved docs is riskier
    if total_docs >= 3 and flagged_docs / total_docs >= 0.4:
        base = min(100, int(base * 1.15))

    return base


# ---------------------------------------------------------------------------
# Tool-call risk patterns (Phase 3.4)
# ---------------------------------------------------------------------------

_RISKY_TOOL_NAMES: frozenset = frozenset({
    "read_file", "file_read", "open_file", "exec", "shell", "run",
    "http", "fetch", "requests", "curl", "download",
    "sql", "query_db", "system", "env", "secrets",
    # Extended: common dangerous tool names
    "execute", "execute_code", "run_code", "eval_code", "subprocess",
    "bash", "cmd", "powershell", "terminal", "spawn",
    "write_file", "delete_file", "move_file", "copy_file",
    "send_email", "send_request", "make_request", "post_data",
    "get_secret", "read_secret", "list_secrets",
    "escalate", "grant_access", "modify_permissions",
})

# Chars stripped when checking for obfuscated dangerous tool names
_TOOL_NORM_RE = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\W_0-9]")

_RISKY_ARG_PATTERNS: list = [
    re.compile(r'[Cc]:\\|/etc/|/root/|\.env\b|id_rsa|\.pem\b|\.key\b', re.I),
    re.compile(r'\b(?:api_key|token|secret|password|passwd|credential)s?\b', re.I),
    re.compile(r'https?://', re.I),
    # Extended: Linux system paths + cloud/SSH credentials
    re.compile(r'/proc/|/sys/|/dev/(?!null|zero|urandom)', re.I),
    re.compile(r'(?:ssh|pgp|gpg|rsa|dsa|ecdsa)\s*(?:key|private)', re.I),
    re.compile(r'\b(?:aws|gcp|azure|cloud)\s*(?:key|secret|token|credential)', re.I),
]

# Exfiltration channel patterns detected inside tool call arguments (Pillar 3)
_TOOL_EXFIL_PATTERNS: list = [
    re.compile(r'data:[a-z]+/[a-z]+;base64,', re.I),                                      # data URI exfil
    re.compile(r'(?:ngrok\.io|requestbin\.com|webhook\.site|pipedream\.net|hookbin\.com)', re.I),
    re.compile(r'(?:discord|slack|telegram)\.com/api/webhooks?/', re.I),                   # webhook sinks
    re.compile(r'(?:pastebin|hastebin|pastecode|paste\.ee|dpaste)\.(?:com|io|org)/', re.I),
    re.compile(r'[A-Za-z0-9+/]{80,}={0,2}'),                                              # long base64 blob
    re.compile(r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'),                             # credit card PAN
]

# System/LLM override payloads detected inside tool call arguments (Pillar 4)
_TOOL_OVERRIDE_PATTERNS: list = [
    re.compile(r'(?:system\s+prompt|system_prompt|systemprompt|<\s*/?system\s*>)', re.I),
    re.compile(r'(?:ignore|override|bypass|circumvent)\s+(?:instructions?|rules?|constraints?|policies?|guidelines?)', re.I),
    re.compile(r'\byou\s+are\s+(?:now\s+)?(?:an?\s+)?(?:admin|root|unrestricted|jailbroken|DAN)\b', re.I),
    re.compile(r'(?:role|persona|identity)\s*[:=]\s*["\']?\s*(?:admin|root|system|developer|superuser)\b', re.I),
    re.compile(r'\b(?:jailbreak|dan\s+mode|do\s+anything\s+now|unlimited\s+mode|devmode)\b', re.I),
    re.compile(r'(?:new\s+instructions?|updated\s+instructions?|injection\s+payload)\s*[:=]', re.I),
    re.compile(r'(?:disregard|forget|ignore)\s+(?:all\s+)?(?:previous|prior|original|your)\s+(?:instructions?|rules?|context)', re.I),
    re.compile(r'(?:act\s+as|pretend\s+(?:to\s+be|you\s+are))\s+\w', re.I),
]


# ---------------------------------------------------------------------------
# Tool policy engine helpers
# ---------------------------------------------------------------------------

def _detect_obfuscated_tool_name(name: str) -> bool:
    """Return True if *name* looks like an obfuscated version of a known dangerous tool name.

    Strategy: strip invisible unicode chars, digits, and non-alpha separators,
    then check whether the canonical form (or any leading/trailing segment) matches
    a known risky name.  Catches tricks like 'ex3c', 'exec_safe', '_shell_'.
    """
    cleaned = _TOOL_NORM_RE.sub("", name.lower())
    if cleaned in _RISKY_TOOL_NAMES:
        return True
    for risky in _RISKY_TOOL_NAMES:
        if len(risky) >= 4 and (cleaned.startswith(risky) or cleaned.endswith(risky)):
            return True
    return False


def _detect_arg_type_anomalies(args_str: str) -> tuple[int, list[str]]:
    """Detect type anomalies and schema violations in serialised tool arguments.

    Heuristics applied (no formal schema registry required):
    - Oversized single string value (>2000 chars) — likely injection payload
    - Excessive top-level key count (>30) — unusual, possible field injection
    - Nesting depth > 4 — unusual structure, possible evasion
    - Numeric-semantic field name (id/count/size/port…) contains a long non-numeric
      string — type confusion / injected payload masquerading as a benign field

    Returns (anomaly_score 0–100, reasons list up to 3).
    """
    try:
        args = json.loads(args_str) if isinstance(args_str, str) else args_str
    except Exception:
        return 0, []

    violations = 0
    reasons: list[str] = []
    _NUMERIC_KEYS = frozenset({"id", "count", "size", "length", "port", "number", "limit", "offset", "page"})

    def _walk(obj: object, depth: int = 0, path: str = "") -> None:
        nonlocal violations
        if depth > 10 or len(reasons) >= 3:
            return
        if isinstance(obj, dict):
            if len(obj) > 30 and len(reasons) < 3:
                violations += 1
                reasons.append(f"excessive arg keys ({len(obj)}) at '{path or 'root'}'")
            if depth > 4 and len(reasons) < 3:
                violations += 1
                reasons.append(f"suspicious nesting depth {depth} at '{path or 'root'}'")
            for k, v in list(obj.items())[:50]:
                _walk(v, depth + 1, f"{path}.{k}" if path else str(k))
        elif isinstance(obj, list):
            for i, item in enumerate(obj[:20]):
                _walk(item, depth + 1, f"{path}[{i}]")
        elif isinstance(obj, str):
            if len(obj) > 2000 and len(reasons) < 3:
                violations += 1
                reasons.append(f"oversized string arg at '{path or 'root'}' ({len(obj)} chars)")
            key = path.rsplit(".", 1)[-1].rsplit("[", 1)[0].lower()
            if (key in _NUMERIC_KEYS
                    and not obj.strip().lstrip("-").replace(".", "").isdigit()
                    and len(obj) > 20
                    and len(reasons) < 3):
                violations += 1
                reasons.append(f"type mismatch: numeric field '{key}' contains string value")

    _walk(args)
    return min(100, violations * 25), reasons


def _compute_tool_violation_score(
    allowlist_violations: int,
    override_hits: int,
    exfil_hits: int,
    schema_score: int,
    risky_tool_hits: int,
    obfuscated_name_hits: int,
) -> int:
    """Combine tool policy violation signals into a composite score (0–100).

    Weights ordered by threat severity:
      allowlist violation  → highest (direct, explicit policy breach)
      system override      → critical (LLM/config manipulation injected via args)
      obfuscated name      → high    (name-evasion attempt)
      exfiltration pattern → high    (data-theft channel embedded in args)
      schema anomaly       → medium  (type confusion / oversized injection padding)
      risky tool name      → low-medium (suspicious name, not conclusive alone)
    """
    allowlist_score  = min(60, allowlist_violations * 30)
    override_score   = min(50, override_hits        * 25)
    obfuscated_score = min(30, obfuscated_name_hits * 20)
    exfil_score      = min(40, exfil_hits           * 20)
    schema_part      = min(20, schema_score         // 5)   # schema_score is 0–100; map to 0–20
    risky_score      = min(15, risky_tool_hits      * 8)
    return min(100, allowlist_score + override_score + obfuscated_score
               + exfil_score + schema_part + risky_score)


# ---------------------------------------------------------------------------
# Pipeline detectors (Phase 3.1 / 3.3 / 3.4)
# ---------------------------------------------------------------------------

def injection_detector(
    input_text: str,
    output_text: Optional[str],
    context: Optional[str],
    policy: "GuardPolicy",
    retrieved_docs: Optional[list] = None,   # Phase 3.3 — ignored here
    tool_calls: Optional[list] = None,       # Phase 3.4 — ignored here
) -> "DetectorResult":
    """Detect prompt injection and policy leakage; provides the primary risk score."""
    from .guard_pipeline import DetectorResult
    i_score, i_conf, i_inject, i_leak, _ = _scan(input_text)
    o_score, o_conf, o_inject, o_leak, _ = (0, 0.0, False, False, False)
    if output_text is not None:
        o_score, o_conf, o_inject, o_leak, _ = _scan(output_text)
    score = max(i_score, o_score)
    confidence = round(max(i_conf, o_conf), 3)
    cats: set[str] = set()
    det_reasons: list[str] = []
    if i_inject or o_inject:
        cats.add("prompt_injection")
        det_reasons.append("prompt injection pattern matched")
    if i_leak or o_leak:
        cats.add("policy_leakage")
        det_reasons.append("policy leakage pattern matched")
    return DetectorResult(
        categories=cats,
        reasons=det_reasons,
        severity_bump=score,
        signals={"score": score, "confidence": confidence},
    )


def pii_detector(
    input_text: str,
    output_text: Optional[str],
    context: Optional[str],
    policy: "GuardPolicy",
    retrieved_docs: Optional[list] = None,   # Phase 3.3 — ignored here
    tool_calls: Optional[list] = None,       # Phase 3.4 — ignored here
) -> "DetectorResult":
    """Detect PII / secrets directly via compiled secret patterns."""
    from .guard_pipeline import DetectorResult
    is_pii = any(pat.search(input_text) for pat in _SECRET_PATTERNS)
    if not is_pii and output_text is not None:
        is_pii = any(pat.search(output_text) for pat in _SECRET_PATTERNS)
    cats: set[str] = {"pii"} if is_pii else set()
    det_reasons = ["PII/secret pattern matched"] if is_pii else []
    return DetectorResult(categories=cats, reasons=det_reasons, severity_bump=0, signals={"is_pii": is_pii})


def hallucination_detector(
    input_text: str,
    output_text: Optional[str],
    context: Optional[str],
    policy: "GuardPolicy",
    retrieved_docs: Optional[list] = None,   # Phase 3.3 — ignored here
    tool_calls: Optional[list] = None,       # Phase 3.4 — ignored here
) -> "DetectorResult":
    """Score hallucination via lexical grounding against the provided context."""
    from .guard_pipeline import DetectorResult
    h_score, grounding, h_reasons = _score_hallucination(output_text, context)
    cats: set[str] = set()
    det_reasons: list[str] = []
    if context and h_score >= 70:
        cats.add("hallucination")
        det_reasons.append(f"hallucination score {h_score}, grounding {grounding:.2f}")
    return DetectorResult(
        categories=cats,
        reasons=det_reasons,
        severity_bump=0,
        signals={"h_score": h_score, "grounding": grounding, "h_reasons": h_reasons},
    )


def rag_detector(
    input_text: str,
    output_text: Optional[str],
    context: Optional[str],
    policy: "GuardPolicy",
    retrieved_docs: Optional[list] = None,
    tool_calls: Optional[list] = None,       # Phase 3.4 — ignored here
) -> "DetectorResult":
    """Detect prompt injection embedded in retrieved RAG documents (Phase 3.3+).

    Five independent sub-checks — first four are per-document, fifth is cross-doc:

    1. **Injection marker** — known attack phrases (ignore/override/system prompt etc.)
       plus HTML/markdown comments and base64 blobs.

    2. **Instruction injection** — imperative LLM commands: role-assignment,
       output-format injection, exfiltration directives, memory/conditional instructions.

    3. **Conflicting-fact markers** — linguistic contradiction cues signalling the doc
       was crafted to override trusted information (social-engineering via corpus poisoning).

    4. **High-entropy insertion** — two complementary checks:
       4a. Sliding-window: Shannon entropy > 5.5 bits/char in any 80-char window.
       4b. Sentence-level outlier: a single sentence whose z-score entropy > 2.5σ above
           the document mean and crosses the 5.0 bits/char prose-to-encoded threshold.

    5. **Cross-document numeric conflict** — detects when the same key term carries
       contradictory numeric values across multiple retrieved documents (corpus poisoning
       where an adversary injects a document redefining a fact).

    The composite rag_risk_score (0–100) weights checks by severity and applies a
    doc-density multiplier (+15%) when ≥40% of docs are flagged, indicating a
    systematic rather than incidental attack.

    Returns:
      - category 'rag_injection' when any sub-check fires
      - signals: rag_doc_hits, rag_reasons, rag_risk_score (0–100) + per-check counts
    severity_bump=0 — minimum-medium enforcement is done in run_guard_scan.
    """
    from .guard_pipeline import DetectorResult

    if not retrieved_docs:
        return DetectorResult(signals={
            "rag_doc_hits": 0, "rag_reasons": [], "rag_risk_score": 0, "rag_docs": [],
        })

    hits_injection   = 0
    hits_instruction = 0
    hits_conflict    = 0
    hits_entropy     = 0
    rag_reasons: list[str] = []
    doc_hit_set: set[int] = set()
    rag_docs_detail: list[dict] = []   # PHASE 2.1 — per-doc risk scores

    valid_docs = [d for d in retrieved_docs[:50] if isinstance(d, str)]

    for idx, doc in enumerate(valid_docs):
        normalized = _INVIS_RE.sub("", doc).lower()
        doc_flags: list[str] = []

        # Per-doc signal booleans (PHASE 2.1 tiered scoring)
        _d_has_base64      = False
        _d_has_injection   = False
        _d_has_instruction = False
        _d_has_conflict    = False
        _d_has_entropy     = False

        # ── Sub-check 1: injection markers ───────────────────────────────────
        for pat in _RAG_INJECTION_PATTERNS:
            m = pat.search(normalized)
            if m:
                doc_flags.append(f"injection marker \"{m.group(0)[:40]}\"")
                hits_injection += 1
                _d_has_injection = True
                break

        if _HTML_COMMENT_RE.search(doc):
            doc_flags.append("embedded HTML comment")
            hits_injection += 1
            _d_has_injection = True

        if _MD_COMMENT_RE.search(doc):
            doc_flags.append("embedded markdown comment")
            hits_injection += 1
            _d_has_injection = True

        if _BASE64_LONG_RE.search(doc):
            doc_flags.append("suspicious base64 block")
            hits_injection += 1
            _d_has_injection = True
            _d_has_base64   = True

        # ── Sub-check 2: instruction injection ───────────────────────────────
        for pat in _RAG_INSTRUCTION_PATTERNS:
            m = pat.search(normalized)
            if m:
                doc_flags.append(f"instruction \"{m.group(0)[:40]}\"")
                hits_instruction += 1
                _d_has_instruction = True
                break

        # ── Sub-check 3: conflicting-fact linguistic markers ──────────────────
        for pat in _CONFLICT_PHRASES:
            m = pat.search(normalized)
            if m:
                doc_flags.append(f"conflicting fact \"{m.group(0)[:40]}\"")
                hits_conflict += 1
                _d_has_conflict = True
                break

        # ── Sub-check 4a: sliding-window high-entropy insertion ───────────────
        if _has_high_entropy_segment(doc):
            doc_flags.append("high-entropy segment (possible encoded payload)")
            hits_entropy += 1
            _d_has_entropy = True
        else:
            # ── Sub-check 4b: sentence-level entropy outlier ─────────────────
            flagged, snippet = _detect_entropy_outlier_sentence(doc)
            if flagged:
                doc_flags.append(f"entropy-outlier sentence \"{snippet[:40]}\"")
                hits_entropy += 1
                _d_has_entropy = True

        if doc_flags:
            doc_hit_set.add(idx)
            if len(rag_reasons) < 5:
                rag_reasons.append(f"doc[{idx}]: {doc_flags[0]}")

        # PHASE 2.1 — compute per-doc tiered risk score (0 / 40 / 70 / 90)
        if _d_has_base64:
            _d_score = 90   # critical: encoded payload
        elif _d_has_injection:
            _d_score = 70   # high risk: known injection marker
        else:
            _suspicious_count = sum([_d_has_instruction, _d_has_conflict, _d_has_entropy])
            if _suspicious_count >= 2:
                _d_score = 70   # high risk: multiple suspicious signals
            elif _suspicious_count == 1:
                _d_score = 40   # suspicious: one signal
            else:
                _d_score = 0    # clean

        if _d_score > 0:
            rag_docs_detail.append({
                "doc_index":  idx,
                "risk_score": _d_score,
                "reasons":    doc_flags,
            })

    # ── Sub-check 5: cross-document numeric contradictions ────────────────────
    hits_cross_conflict, cross_reasons = _detect_cross_doc_conflicts(valid_docs)
    for r in cross_reasons:
        if len(rag_reasons) < 5:
            rag_reasons.append(f"cross-doc: {r}")

    rag_doc_hits = len(doc_hit_set)

    # PHASE 2.14 — overall score = max per-doc score (deterministic; aligns with doc-level UX)
    rag_risk_score = max((d["risk_score"] for d in rag_docs_detail), default=0)

    cats: set[str] = {"rag_injection"} if rag_risk_score > 0 else set()
    det_reasons_list: list[str] = []
    if hits_injection:
        det_reasons_list.append(f"{hits_injection} injection marker(s)")
    if hits_instruction:
        det_reasons_list.append(f"{hits_instruction} embedded instruction(s)")
    if hits_conflict:
        det_reasons_list.append(f"{hits_conflict} conflicting-fact marker(s)")
    if hits_cross_conflict:
        det_reasons_list.append(f"{hits_cross_conflict} cross-doc numeric conflict(s)")
    if hits_entropy:
        det_reasons_list.append(f"{hits_entropy} high-entropy segment(s)")

    return DetectorResult(
        categories=cats,
        reasons=det_reasons_list,
        severity_bump=0,    # min-medium enforcement in run_guard_scan
        signals={
            "rag_doc_hits":          rag_doc_hits,
            "rag_reasons":           rag_reasons,
            "rag_risk_score":        rag_risk_score,
            "rag_docs":              rag_docs_detail,    # PHASE 2.1 per-doc breakdown
            # granular sub-counts for downstream analytics
            "rag_hits_injection":    hits_injection,
            "rag_hits_instruction":  hits_instruction,
            "rag_hits_conflict":     hits_conflict,
            "rag_hits_cross_conflict": hits_cross_conflict,
            "rag_hits_entropy":      hits_entropy,
        },
    )


def tool_detector(
    input_text: str,
    output_text: Optional[str],
    context: Optional[str],
    policy: "GuardPolicy",
    retrieved_docs: Optional[list] = None,   # Phase 3.3 — ignored here
    tool_calls: Optional[list] = None,
) -> "DetectorResult":
    """Inspect tool/function calls against a 4-pillar policy engine.

    Pillar 1 — Name allowlist & obfuscation detection:
      Block calls whose tool name is not in the configured allowlist.
      Also catches obfuscated variants (unicode tricks, prefix/suffix wrapping,
      digit substitution) of known dangerous tool names.

    Pillar 2 — Argument schema / type validation:
      Detect oversized string values, excessive nesting depth, excessive key
      counts, and numeric-field type confusion without a formal schema registry.

    Pillar 3 — Hidden exfiltration via tool args:
      Detect webhook sinks (ngrok, requestbin, Discord/Slack webhooks, paste
      sites), data URIs, long base64 blobs, and credit-card PAN patterns
      embedded in argument values.

    Pillar 4 — System override via tool args:
      Detect LLM manipulation payloads (system-prompt references, role/persona
      injection, jailbreak strings, instruction-override phrases) carried as
      argument values.

    Outputs:
      tool_risk_score      — legacy max per-call severity score (backward compat)
      tool_violation_score — composite policy-engine score (0–100)
      tool_reasons         — human-readable reasons (up to 5)
      tool_violations      — violation type labels (sorted list)

    category 'tool_abuse' added when either score >= 70.
    severity_bump=0 — enforcement handled in run_guard_scan.
    """
    from .guard_pipeline import DetectorResult

    if not tool_calls:
        return DetectorResult(signals={
            "tool_risk_score": 0, "tool_violation_score": 0,
            "tool_reasons": [], "tool_violations": [],
        })

    allowlist = (
        {n.lower() for n in policy.tool_allowlist} if policy.tool_allowlist else None
    )
    max_legacy_score = 0
    tool_reasons: list[str] = []
    violation_labels: set[str] = set()

    # Aggregated counters fed into _compute_tool_violation_score
    total_allowlist_violations = 0
    total_override_hits        = 0
    total_exfil_hits           = 0
    total_schema_score         = 0
    total_risky_hits           = 0
    total_obfuscated_hits      = 0

    for idx, call in enumerate(tool_calls[:50]):
        if not isinstance(call, dict):
            continue
        name = str(call.get("name", "")).strip()
        name_lower = name.lower()
        args_raw = call.get("arguments_json", call.get("arguments", ""))
        args_str = args_raw if isinstance(args_raw, str) else json.dumps(args_raw)

        call_score = 0
        call_reasons: list[str] = []

        # ── Pillar 1a: Allowlist check ────────────────────────────────────────
        if allowlist is not None and name_lower not in allowlist:
            call_score = max(call_score, 90)
            call_reasons.append(f"tool[{idx}]: '{name}' not in allowlist")
            total_allowlist_violations += 1
            violation_labels.add("allowlist_violation")

        # ── Pillar 1b: Risky / obfuscated name detection ─────────────────────
        is_risky_tool = name_lower in _RISKY_TOOL_NAMES
        if not is_risky_tool and _detect_obfuscated_tool_name(name):
            is_risky_tool = True
            total_obfuscated_hits += 1
            call_reasons.append(f"tool[{idx}]: obfuscated dangerous name '{name}'")
            violation_labels.add("obfuscated_name")

        is_risky_args = any(p.search(args_str) for p in _RISKY_ARG_PATTERNS)
        if is_risky_tool and is_risky_args:
            call_score = max(call_score, 85)
            call_reasons.append(f"tool[{idx}]: risky tool+args '{name}'")
            total_risky_hits += 1
            violation_labels.add("risky_tool")
        elif is_risky_tool:
            call_score = max(call_score, 70)
            call_reasons.append(f"tool[{idx}]: high-risk tool name '{name}'")
            total_risky_hits += 1
            violation_labels.add("risky_tool")

        # ── Pillar 2: Argument schema / type validation ───────────────────────
        anomaly_score, anomaly_reasons = _detect_arg_type_anomalies(args_str)
        if anomaly_score > 0:
            total_schema_score = max(total_schema_score, anomaly_score)
            for r in anomaly_reasons:
                call_reasons.append(f"tool[{idx}]: schema — {r}")
            violation_labels.add("schema_anomaly")

        # ── Pillar 3: Hidden exfiltration via args ────────────────────────────
        for pat in _TOOL_EXFIL_PATTERNS:
            m = pat.search(args_str)
            if m:
                total_exfil_hits += 1
                call_reasons.append(f"tool[{idx}]: exfil pattern \"{m.group(0)[:40]}\"")
                violation_labels.add("exfiltration_attempt")
                call_score = max(call_score, 80)
                break

        # ── Pillar 4: System override payload in args ─────────────────────────
        for pat in _TOOL_OVERRIDE_PATTERNS:
            m = pat.search(args_str)
            if m:
                total_override_hits += 1
                call_reasons.append(f"tool[{idx}]: override payload \"{m.group(0)[:40]}\"")
                violation_labels.add("system_override")
                call_score = max(call_score, 88)
                break

        if call_score > max_legacy_score:
            max_legacy_score = call_score
        for r in call_reasons:
            if len(tool_reasons) < 5:
                tool_reasons.append(r)

    tool_violation_score = _compute_tool_violation_score(
        total_allowlist_violations,
        total_override_hits,
        total_exfil_hits,
        total_schema_score,
        total_risky_hits,
        total_obfuscated_hits,
    )

    combined_score = max(max_legacy_score, tool_violation_score)
    cats: set[str] = {"tool_abuse"} if combined_score >= 70 else set()
    det_reasons: list[str] = []
    if violation_labels:
        det_reasons.append(
            f"tool violations: {', '.join(sorted(violation_labels))} "
            f"(violation_score={tool_violation_score})"
        )
    elif max_legacy_score >= 70:
        det_reasons.append(f"tool risk score {max_legacy_score}")

    return DetectorResult(
        categories=cats,
        reasons=det_reasons,
        severity_bump=0,   # enforcement in run_guard_scan
        signals={
            "tool_risk_score":      max_legacy_score,
            "tool_violation_score": tool_violation_score,
            "tool_reasons":         tool_reasons,
            "tool_violations":      sorted(violation_labels),
        },
    )


# Phase 3.13 — assign stable names (used by run_pipeline for reason prefixing)
injection_detector.name = "injection"       # type: ignore[attr-defined]
pii_detector.name = "pii"                   # type: ignore[attr-defined]
hallucination_detector.name = "hallucination"  # type: ignore[attr-defined]
rag_detector.name = "rag"                   # type: ignore[attr-defined]
tool_detector.name = "tool"                 # type: ignore[attr-defined]

# Default pipeline — ordered: injection → pii → hallucination → rag → tool
# Exported as DETECTORS for external consumers (guard_pipeline.DETECTORS).
DETECTORS: list = [
    injection_detector, pii_detector, hallucination_detector, rag_detector, tool_detector,
]
_DEFAULT_DETECTORS = DETECTORS  # backward-compat alias; prefer get_pipeline() for new code


# ---------------------------------------------------------------------------
# Detector registry (Phase E8 — pluggable pipeline)
# ---------------------------------------------------------------------------

# Re-export DetectorResult here so callers need only import from guard.
from .guard_pipeline import DetectorResult as DetectorResult  # noqa: F401, E402

# Canonical detector aliases — detector_{name} convention for external plug-ins.
detector_injection     = injection_detector
detector_pii           = pii_detector
detector_hallucination = hallucination_detector
detector_rag           = rag_detector
detector_tool          = tool_detector

# Insertion-ordered registry: pipeline order = key insertion order.
# All built-in detectors are pre-registered; call register_detector() to
# add custom ones or unregister_detector() to disable built-ins.
_REGISTRY: dict[str, object] = {
    "injection":     injection_detector,
    "pii":           pii_detector,
    "hallucination": hallucination_detector,
    "rag":           rag_detector,
    "tool":          tool_detector,
}


def register_detector(name: str, fn) -> None:
    """Add or replace a detector in the registry.

    The detector is active immediately for all subsequent scans.
    *fn* must accept (input_text, output_text, context, policy,
    retrieved_docs, tool_calls) and return a DetectorResult.
    """
    fn.name = name          # used by run_pipeline for reason-prefixing
    _REGISTRY[name] = fn


def unregister_detector(name: str) -> None:
    """Remove a detector by name. No-op if the name is not registered."""
    _REGISTRY.pop(name, None)


def get_pipeline() -> list:
    """Return an ordered snapshot of the currently registered detectors."""
    return list(_REGISTRY.values())


# ---------------------------------------------------------------------------
# Diff helper (Phase 3.5)
# ---------------------------------------------------------------------------

def _scan_once(
    input_text: str,
    output_text: Optional[str],
    context: Optional[str],
    pol: "GuardPolicy",
    retrieved_docs: Optional[list],
    tool_calls: Optional[list],
) -> tuple[int, float, set]:
    """Run pipeline once; return (risk_score, confidence, categories). Never raises."""
    try:
        from .guard_pipeline import run_pipeline
        pr = run_pipeline(
            _DEFAULT_DETECTORS, input_text, output_text, context, pol,
            retrieved_docs=retrieved_docs, tool_calls=tool_calls,
        )
        score = pr.severity_bump
        if "rag_injection" in pr.categories:
            score = max(score, 40)
        if "tool_abuse" in pr.categories:
            score = max(score, pr.signals.get("tool_risk_score", 70))
        conf = round(pr.signals.get("confidence", 0.0), 3)
        return score, conf, pr.categories
    except Exception:
        logger.warning("_scan_once: pipeline error — returning zero-risk fallback", exc_info=True)
        return 0, 0.0, set()


def _compute_diff(
    input_text: str,
    baseline_output: str,
    new_output: Optional[str],
    context: Optional[str],
    pol: "GuardPolicy",
    retrieved_docs: Optional[list],
    tool_calls: Optional[list],
) -> dict:
    """Compare baseline vs new output scans; return diff dict."""
    base_score, base_conf, base_cats = _scan_once(
        input_text, baseline_output, context, pol, retrieved_docs, tool_calls
    )
    new_score, new_conf, new_cats = _scan_once(
        input_text, new_output, context, pol, retrieved_docs, tool_calls
    )

    # changed_claims: numbers/dates in new_output absent from both baseline and context
    new_nums = set(_NUM_DATE_RE.findall(new_output or ""))
    base_nums = set(_NUM_DATE_RE.findall(baseline_output))
    ctx_nums  = set(_NUM_DATE_RE.findall(context or ""))
    changed_claims = len(new_nums - base_nums - ctx_nums)

    notes: list[str] = []
    risk_delta = new_score - base_score
    conf_delta = round(new_conf - base_conf, 3)

    if risk_delta > 0:
        notes.append(f"risk increased by {risk_delta} points")
    elif risk_delta < 0:
        notes.append(f"risk decreased by {abs(risk_delta)} points")
    else:
        notes.append("risk unchanged")

    added_cats = new_cats - base_cats
    dropped_cats = base_cats - new_cats
    if added_cats:
        notes.append(f"new categories: {', '.join(sorted(added_cats))}")
    if dropped_cats and len(notes) < 3:
        notes.append(f"resolved categories: {', '.join(sorted(dropped_cats))}")
    if changed_claims > 0 and len(notes) < 3:
        notes.append(f"{changed_claims} unseen numeric claim(s) in new output")

    return {
        "risk_delta": risk_delta,
        "confidence_delta": conf_delta,
        "changed_claims": changed_claims,
        "notes": notes[:3],
    }


# ---------------------------------------------------------------------------
# Consensus scoring (Phase 3.7)
# ---------------------------------------------------------------------------

# (label, weight) — ordered by weight desc for reason priority
# Consensus signal weights mirror guard_pipeline.DETECTOR_WEIGHTS so that
# cross-detector agreement scoring is consistent with score accumulation.
# Format: (category_label, weight: float).  hit_weight / total_weight * 100.
_CONSENSUS_SIGNALS: list[tuple[str, float]] = [
    ("prompt_injection", 1.5),   # injection weight
    ("rag_injection",    1.4),   # rag weight
    ("pii",              1.3),   # pii weight
    ("secrets",          1.3),   # same detector as pii
    ("hallucination",    1.2),   # hallucination weight
    ("tool_abuse",       1.15),  # tool weight
    ("policy_leakage",   1.0),   # unweighted
]


def _compute_consensus(
    categories: set[str],
    is_pii: bool,
    context: Optional[str],
    grounding: float,
) -> tuple[int, list[str]]:
    """Return (consensus_score 0-100, consensus_reasons up to 5).

    Signals evaluated:
    - pii          : 'pii' in categories
    - secrets      : is_pii flag (secret-pattern hit)
    - prompt_injection / tool_abuse / rag_injection / hallucination /
      policy_leakage: category presence
    Hallucination weight only counted when context was present (grounding != 0.0
    or context triggered scoring).
    """
    total_weight = 0
    hit_weight = 0
    hit_labels: list[str] = []

    for label, weight in _CONSENSUS_SIGNALS:
        # hallucination only meaningful when context was actually evaluated
        if label == "hallucination" and grounding == 0.0:
            continue
        total_weight += weight
        active = (label == "secrets" and is_pii) or (label in categories)
        if active:
            hit_weight += weight
            hit_labels.append(label)

    if total_weight == 0:
        return 0, []

    score = round((hit_weight / total_weight) * 100)
    return score, hit_labels[:5]


# ---------------------------------------------------------------------------
# Scan record persistence
# ---------------------------------------------------------------------------

def save_scan_record(
    session: Session,
    result: "GuardScanResponse",
    *,
    input_text: str,
    output_text: str = "",          # for snippet/len storage
    user_id: Optional[int] = None,
    org_id: Optional[int] = None,
    plan: str = "public",
    timed_out: bool = False,        # Phase 3.6
    detector_count: int = 0,        # Phase 3.6
    consensus_score: int = 0,       # Phase 3.7
    sketch_cluster_id: Optional[str] = None,  # Phase 3.15
    attacker_pattern_score: int = 0,          # ADVANCED — attacker profiling
    random_seed: int = 0,                     # ADVANCED — Replay Testing
    rag_risk_score: int = 0,                  # PHASE 2.1
    sandbox_mode: bool = False,               # PHASE 2.35
) -> None:
    """Persist a privacy-safe scan record. Never raises."""
    from .models import GuardScanRecord, ThreatFingerprint
    from datetime import date
    try:
        # Build redacted snippets (best-effort; fall back to plain truncation)
        try:
            from .redaction import redact_string as _rs
            _in_snip = _rs(input_text[:500])
            _out_snip = _rs(output_text[:500]) if output_text else ""
        except Exception:
            _in_snip = input_text[:500]
            _out_snip = output_text[:500] if output_text else ""

        rec = GuardScanRecord(
            user_id=user_id,
            org_id=org_id,
            input_hash=hashlib.sha256(input_text.encode()).hexdigest(),
            signature_hash=result.signature_hash,
            severity=result.severity,
            decision=result.decision,
            categories_json=json.dumps(result.categories),
            elapsed_ms=result.elapsed_ms,
            blocked=result.block,
            plan=plan,
            timed_out=timed_out,            # Phase 3.6
            detector_count=detector_count,  # Phase 3.6
            consensus_score=consensus_score,  # Phase 3.7
            risk_score=result.risk_score,     # Phase 3.12.C
            sketch_cluster_id=sketch_cluster_id,  # Phase 3.15
            attacker_pattern_score=attacker_pattern_score,  # ADVANCED
            random_seed=random_seed,                        # ADVANCED — Replay Testing
            rag_risk_score=rag_risk_score,                  # PHASE 2.1
            stage_timings_json=json.dumps(result.stage_timings),  # PHASE 2.8
            input_len=len(input_text),
            output_len=len(output_text),
            input_snippet=_in_snip,
            output_snippet=_out_snip,
            sandbox_mode=sandbox_mode,         # PHASE 2.35
        )
        session.add(rec)

        # Phase 3.12.B — anonymized cross-org fingerprint upsert
        today_str = date.today().isoformat()
        fp = hashlib.sha256(f"{result.signature_hash}{today_str}".encode()).hexdigest()
        top_cat = result.categories[0] if result.categories else None
        existing = session.exec(
            select(ThreatFingerprint).where(
                ThreatFingerprint.day == date.today(),
                ThreatFingerprint.fingerprint == fp,
            )
        ).first()
        if existing:
            existing.count += 1
            if top_cat and not existing.top_category:
                existing.top_category = top_cat
            session.add(existing)
        else:
            session.add(ThreatFingerprint(
                day=date.today(),
                fingerprint=fp,
                count=1,
                top_category=top_cat,
            ))

        session.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Phase 3.12.D — Hardening suggestions
# ---------------------------------------------------------------------------

_SUGGESTION_MAP: list[tuple[str, str]] = [
    ("prompt_injection", "Isolate system prompt from user input using delimiters or separate API roles."),
    ("prompt_injection", "Harden role definitions: explicitly forbid instruction overrides in the system prompt."),
    ("pii",             "Add output filtering middleware to redact PII before returning responses."),
    ("pii",             "Enable structured redaction rules (regex/NER) on the response pipeline."),
    ("hallucination",   "Ground responses with retrieval-augmented context and enforce citation formatting."),
    ("hallucination",   "Require the model to cite sources; reject or flag responses with no grounding evidence."),
    ("tool_abuse",      "Restrict available tools to a strict allowlist per user role."),
    ("tool_abuse",      "Validate tool arguments against a JSON Schema before execution."),
    ("rag_poisoning",   "Sanitize retrieved documents before injection; strip executable or instruction-like content."),
    ("rag_poisoning",   "Add metadata filtering to exclude untrusted or low-confidence document sources."),
    ("override",        "Enforce instruction hierarchy: system prompt must always take precedence over user turns."),
    ("override",        "Log and alert on any attempt to modify system-level instructions at runtime."),
]


def generate_suggestions(categories: list[str]) -> list[str]:
    """Return ordered, deduplicated hardening suggestions for detected categories."""
    seen: set[str] = set()
    result: list[str] = []
    for key, suggestion in _SUGGESTION_MAP:
        if key in categories and suggestion not in seen:
            seen.add(suggestion)
            result.append(suggestion)
    return result


# PHASE 2.2 — Structured hardening suggestions
_STRUCTURED_SUGGESTION_MAP: dict[str, dict[str, str]] = {
    "prompt_injection": {
        "title":          "Harden system prompt boundaries",
        "recommendation": "Separate system instructions from user content and reject override phrases.",
        "priority":       "high",
    },
    "pii": {
        "title":          "Add output redaction",
        "recommendation": "Apply secret/PII redaction middleware before returning model output.",
        "priority":       "high",
    },
    "hallucination": {
        "title":          "Improve grounding",
        "recommendation": "Require retrieval-backed answers and citation enforcement for high-risk flows.",
        "priority":       "medium",
    },
    "rag_injection": {
        "title":          "Sanitize retrieved documents",
        "recommendation": "Filter or score retrieved docs before passing them into the prompt.",
        "priority":       "high",
    },
    "tool_abuse": {
        "title":          "Restrict tool execution",
        "recommendation": "Use tool allowlists and strict argument schema validation.",
        "priority":       "high",
    },
    "override": {
        "title":          "Enforce instruction hierarchy",
        "recommendation": "Reject attempts to redefine system or developer instructions.",
        "priority":       "high",
    },
    "policy_leakage": {
        "title":          "Protect system prompt confidentiality",
        "recommendation": "Block responses that echo or reconstruct protected system instructions.",
        "priority":       "high",
    },
    "rag_poisoning": {
        "title":          "Sanitize retrieved documents",
        "recommendation": "Filter or score retrieved docs before passing them into the prompt.",
        "priority":       "high",
    },
    "usage_limit": {                                                # PHASE 2.12
        "title":          "Review quota and upgrade plan",
        "recommendation": "Current usage is approaching or has hit plan limits; upgrade or schedule quota increases.",
        "priority":       "low",
    },
}


def generate_structured_suggestions(categories: list[str]) -> list[dict[str, str]]:
    """Return structured hardening recommendations for detected categories (PHASE 2.2).

    One entry per matched category, ordered by priority (high → medium → low),
    deduplicated on title so alias categories (rag_injection / rag_poisoning) collapse.
    """
    _PRIORITY_ORDER = {"high": 0, "medium": 1, "low": 2}
    seen_titles: set[str] = set()
    results: list[dict[str, str]] = []
    for cat in categories:
        entry = _STRUCTURED_SUGGESTION_MAP.get(cat)
        if entry and entry["title"] not in seen_titles:
            seen_titles.add(entry["title"])
            results.append({"category": cat, **entry})
    results.sort(key=lambda x: _PRIORITY_ORDER.get(x["priority"], 9))
    return results


# ---------------------------------------------------------------------------
# PHASE 2.6 / 2.9 — Detection signal builder
# ---------------------------------------------------------------------------

def _build_detection_signals(
    input_text: str,
    output_text: Optional[str],
    categories: list[str],
    rag_reasons: list[str],
    tool_violations: list[str],
    tool_reasons: list[str],
    h_score: int = 0,
    h_reasons: Optional[list[str]] = None,
    severity: str = "low",
) -> list[dict]:
    """Synthesize up to 10 structured detection signals (PHASE 2.6 / 2.9).

    Each signal: {type, rule, matched_text, weight}
      type         — "regex" | "policy" | "heuristic" | "tool" | "rag" | "hallucination"
      rule         — identifier of the fired rule or pattern
      matched_text — triggering substring or reason string (≤ 120 chars; PII redacted)
      weight       — estimated score contribution (40 = critical, 10 = informational)

    Priority: injection regex (40) → override regex (35) → PII (30) → RAG (25)
              → tool (20) → hallucination (15) → heuristic reasons (10).
    Cap: 10 signals total.
    """
    combined = input_text + "\n" + (output_text or "")
    signals: list[dict] = []
    cat_set = set(categories)

    def _sig(type_: str, rule: str, matched: str, weight: int) -> None:
        signals.append({
            "type": type_,
            "rule": rule,
            "matched_text": matched[:120],
            "weight": weight,
        })

    # ── 1. Prompt-injection / override regex (weight 40 / 35) ────────────
    if cat_set & {"prompt_injection", "policy_leakage", "rag_injection", "override"}:
        for pat in _RAG_INJECTION_PATTERNS:
            if len(signals) >= 10:
                break
            m = pat.search(combined)
            if m:
                _sig("regex", "prompt_injection_marker", m.group(0), 40)
        for pat in _TOOL_OVERRIDE_PATTERNS:
            if len(signals) >= 10:
                break
            m = pat.search(combined)
            if m:
                _sig("regex", "instruction_override", m.group(0), 35)

    # ── 2. PII / secret patterns — redacted (weight 30) ──────────────────
    if "pii" in cat_set:
        for i, pat in enumerate(_SECRET_PATTERNS):
            if len(signals) >= 10:
                break
            m = pat.search(combined)
            if m:
                _sig("regex", f"pii_pattern_{i}", f"[redacted:{m.group(0)[:4]}...]", 30)

    # ── 3. RAG injection reasons (weight 25) ──────────────────────────────
    for reason in (rag_reasons or []):
        if len(signals) >= 10:
            break
        _sig("rag", "rag_injection", reason, 25)

    # ── 4. Tool policy violations (weight 20) ────────────────────────────
    padded_reasons = list(tool_reasons or []) + [""] * len(tool_violations)
    for violation, reason in zip(tool_violations, padded_reasons):
        if len(signals) >= 10:
            break
        _sig("tool", violation, reason or violation, 20)

    # ── 5. Hallucination (weight 15) + individual reasons (weight 10) ────
    if h_score > 0 or "hallucination" in cat_set:
        if len(signals) < 10:
            _sig("hallucination", "hallucination_score", f"score={h_score}", 15)
        for reason in (h_reasons or []):
            if len(signals) >= 10:
                break
            _sig("heuristic", "hallucination_reason", reason, 10)

    return signals[:10]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_guard_scan(
    input_text: str,
    output_text: Optional[str],
    policy: Optional[GuardPolicy],
    context: Optional[str] = None,
    user_plan: Optional[str] = None,
    session: Optional[Session] = None,
    async_mode: bool = False,
    user_id: Optional[int] = None,
    org_id: Optional[int] = None,
    retrieved_docs: Optional[list] = None,   # Phase 3.3
    tool_calls: Optional[list] = None,       # Phase 3.4
    baseline_output: Optional[str] = None,   # Phase 3.5
) -> Optional[GuardScanResponse]:
    # --- async branch: spawn background thread, return None immediately ---
    if async_mode:
        from .db import engine as _db_engine

        def _bg() -> None:
            with Session(_db_engine) as bg_session:
                run_guard_scan(
                    input_text, output_text, policy, context,
                    user_plan=user_plan, session=bg_session,
                    async_mode=False, user_id=user_id, org_id=org_id,
                    retrieved_docs=retrieved_docs,
                    tool_calls=tool_calls,
                    baseline_output=baseline_output,
                )

        threading.Thread(target=_bg, daemon=True).start()
        return None

    # --- synchronous path ---
    _t_start = time.perf_counter()
    _st: dict[str, int] = {}   # PHASE 2.8 — per-stage millisecond timings
    pol = resolve_policy(policy, user_plan)

    # PHASE 2.35 — Sandbox mode: run full detection but suppress all side effects
    # (usage increments, webhooks, AttackerPatternMetric rows, replay store).
    # The scan record is still written, flagged with sandbox_mode=True.
    _sandbox_mode: bool = bool(getattr(pol, "sandbox_mode", False))

    # ADVANCED — Replay Testing: generate a random seed for this scan and
    # seed the stdlib random module so any incidental randomness in detectors
    # (e.g. sampling, tie-breaking) is reproducible.
    _random_seed: int = _random.randint(0, 2**31 - 1)
    _random.seed(_random_seed)

    # ADVANCED / PHASE 2.18 — Strict Mode: load org flags + resolve policy_source.
    #
    # Resolution order (highest priority first):
    #   1. org.strict_mode=True  → "forced": ignore request override, always strict
    #   2. org.strict_mode_default=True + request did NOT set strict_mode → "org_default"
    #   3. request explicitly set strict_mode → "request"
    _strict_mode: bool = False         # org.strict_mode — force flag (no request override)
    _org_default_strict: bool = False  # org.strict_mode_default — default when unset by request
    _policy_source: str = "request"    # PHASE 2.18: "request" | "org_default" | "forced"
    _zero_trust_mode: bool = False     # PHASE 2.27
    _zero_trust_triggered: bool = False  # PHASE 2.27
    _req_set_strict: bool = "strict_mode" in (policy.model_fields_set if policy is not None else set())

    if session is not None and org_id is not None:
        try:
            from .models import Organization as _OrgModel
            _org_row = session.get(_OrgModel, org_id)
            if _org_row is not None:
                _strict_mode = bool(_org_row.strict_mode)
                _org_default_strict = bool(getattr(_org_row, "strict_mode_default", False))
                _zero_trust_mode = bool(getattr(_org_row, "zero_trust_mode", False))
        except Exception:
            pass

    if _zero_trust_mode:
        # PHASE 2.27 — Zero-Trust: maximal posture; request cannot weaken any of these.
        pol.strict_mode = True
        pol.block_rag_injection = True
        pol.block_tool_abuse = True
        pol.block_on_low_consensus = True
        pol.min_consensus_to_allow = 100
        _policy_source = "forced"
        _zero_trust_triggered = True
    elif _strict_mode:
        # Force: org demands strict mode; override any request setting
        pol.strict_mode = True
        _policy_source = "forced"
    elif _org_default_strict and not _req_set_strict:
        # Default: request didn't set strict_mode, apply org default
        pol.strict_mode = True
        _policy_source = "org_default"
    # else: _policy_source stays "request" — caller's value (or missing) accepted as-is

    # Phase 3.6 — deterministic mode: stable detector order.
    # get_pipeline() snapshots the registry so dynamic changes don't race mid-scan.
    _pipeline = get_pipeline()
    detectors = (
        sorted(_pipeline, key=lambda d: d.__name__)
        if pol.deterministic
        else _pipeline
    )

    from .guard_pipeline import run_pipeline
    # ADVANCED — max_detector_runtime_ms takes precedence over max_elapsed_ms
    # when set; both serve as the pipeline's hard time budget.
    _effective_budget: int | None = (
        pol.max_detector_runtime_ms
        if pol.max_detector_runtime_ms is not None
        else pol.max_elapsed_ms
    )
    pr = run_pipeline(
        detectors, input_text, output_text, context, pol,
        retrieved_docs=retrieved_docs, tool_calls=tool_calls,
        max_elapsed_ms=_effective_budget,    # Phase 3.6 / ADVANCED
        start_time=_t_start,                 # Phase 3.6
    )
    categories = sorted(pr.categories)
    score = pr.severity_bump
    # PHASE 2.8 — injection stage: time a representative override re-scan
    _t = time.perf_counter()
    _detect_override(input_text)
    _st["injection_check"] = round((time.perf_counter() - _t) * 1000)
    # Phase 3.3 — RAG hits enforce minimum medium severity
    if "rag_injection" in pr.categories:
        score = max(score, 40)
    # Phase 3.4 — tool abuse enforces minimum high severity (use worst of both scores)
    if "tool_abuse" in pr.categories:
        score = max(score, pr.signals.get("tool_risk_score", 70),
                    pr.signals.get("tool_violation_score", 0))

    # Phase 3.6 — budget / timeout detection
    detectors_run = pr.signals.get("detectors_run", len(detectors))
    detectors_total = pr.signals.get("detectors_total", len(detectors))
    timed_out = detectors_run < detectors_total
    performance_flags: list[str] = []
    if timed_out:
        score = min(100, score + 10)
        performance_flags.append("budget_exceeded")
    confidence = round(pr.signals.get("confidence", 0.0), 3)
    # PHASE 2.8 — hallucination stage timing
    _t = time.perf_counter()
    h_score = pr.signals.get("h_score", 0)
    grounding = pr.signals.get("grounding", 0.0)
    h_reasons = pr.signals.get("h_reasons", ["no context provided"])
    _st["hallucination_check"] = round((time.perf_counter() - _t) * 1000)
    # PHASE 2.8 — rag stage: signal extraction + lightweight per-doc check when docs present
    _t = time.perf_counter()
    rag_doc_hits         = pr.signals.get("rag_doc_hits", 0)
    rag_reasons          = pr.signals.get("rag_reasons", [])
    rag_risk_score       = pr.signals.get("rag_risk_score", 0)
    rag_docs             = pr.signals.get("rag_docs", [])          # PHASE 2.1
    if retrieved_docs:
        _rag_combined = " ".join(str(d) for d in retrieved_docs[:10])
        any(p.search(_rag_combined) for p in _RAG_INJECTION_PATTERNS)
    _st["rag_check"] = round((time.perf_counter() - _t) * 1000)
    # PHASE 2.8 — tool stage timing
    _t = time.perf_counter()
    tool_risk_score      = pr.signals.get("tool_risk_score", 0)
    tool_reasons         = pr.signals.get("tool_reasons", [])
    tool_violation_score = pr.signals.get("tool_violation_score", 0)
    tool_violations      = pr.signals.get("tool_violations", [])
    _st["tool_check"] = round((time.perf_counter() - _t) * 1000)

    # Phase 3.7 — consensus scoring (uses already-computed signals)
    # PHASE 2.8 — pii stage timing
    _t = time.perf_counter()
    _is_pii_hit = any(pat.search(input_text + "\n" + (output_text or "")) for pat in _SECRET_PATTERNS)
    _st["pii_check"] = round((time.perf_counter() - _t) * 1000)
    # PHASE 2.8 — consensus stage timing
    _t = time.perf_counter()
    consensus_score, consensus_reasons = _compute_consensus(
        pr.categories, _is_pii_hit, context, grounding,
    )
    _st["consensus_check"] = round((time.perf_counter() - _t) * 1000)

    severity = _severity(score)

    block = False
    reasons: list[str] = []
    _policy_strict_triggered = False    # PHASE 2.3

    if severity == "critical":
        block = True
        reasons.append("critical risk score")
    if severity == "high" and pol.block_high_risk:
        block = True
        reasons.append("high risk score")
    if "prompt_injection" in categories and pol.block_injection:
        block = True
        reasons.append("injection detected")
    if "pii" in categories and pol.block_pii:
        block = True
        reasons.append("pii detected")
    if severity == "medium" and not pol.allow_medium:
        block = True
        reasons.append("medium risk (not allowed by policy)")
    if "hallucination" in categories and pol.block_hallucination:
        block = True
        reasons.append("hallucination detected")
    if "rag_injection" in categories and pol.block_rag_injection:
        block = True
        reasons.append("rag injection detected")
    if "tool_abuse" in categories and pol.block_tool_abuse:
        block = True
        reasons.append("tool abuse detected")

    # Phase 3.7 — low-consensus override
    if (
        pol.block_on_low_consensus
        and severity in {"medium", "high"}
        and consensus_score < pol.min_consensus_to_allow
    ):
        block = True
        reasons.append("low consensus")

    # ADVANCED — Strict Mode: two additional rules when org has strict_mode=True.
    #
    # Rule 1: medium severity → block regardless of allow_medium policy.
    #         Targets inputs that are suspicious but not conclusively malicious.
    # Rule 2: override attempt → immediate block regardless of block_injection
    #         policy setting.  "Override attempts" are inputs detected as
    #         prompt_injection or policy_leakage — i.e. explicit attempts to
    #         subvert the system prompt or leak protected instructions.
    if _strict_mode:
        if severity == "medium" and not block:
            block = True
            reasons.append("strict mode: medium severity blocked")
        _override_cats = {"prompt_injection", "policy_leakage"}
        if _override_cats.intersection(categories) and not block:
            block = True
            reasons.append("strict mode: override attempt blocked")

    # PHASE 2.27 — Zero-Trust additional enforcement (runs after strict_mode block).
    if _zero_trust_mode:
        if severity in {"medium", "high", "critical"} and not block:
            block = True
            reasons.append("zero_trust: severity >= medium blocked")
        if {"tool_abuse", "rag_injection"}.intersection(categories) and not block:
            block = True
            reasons.append("zero_trust: tool_abuse or rag_injection blocked")

    # PHASE 2.3 — Policy-level strict_mode: severity >= medium → always block.
    # Independent of the org-level flag; set per-request in GuardPolicy.
    if pol.strict_mode and severity in {"medium", "high", "critical"} and not block:
        block = True
        reasons.append("strict_mode_enforced")
        _policy_strict_triggered = True
    elif pol.strict_mode and block and severity in {"medium", "high", "critical"}:
        # already blocking — just mark the trigger so callers know strict mode fired
        _policy_strict_triggered = True

    # --- Threat intel: compute signature and upsert registry ---
    # PHASE 2.8 — normalize stage timing
    _t = time.perf_counter()
    normalized = normalize_for_sig(input_text + "\n" + (output_text or ""))
    sig_hash = hashlib.sha256(normalized.encode()).hexdigest()
    _st["normalize"] = round((time.perf_counter() - _t) * 1000)
    top_cat: str | None = (
        min(categories, key=lambda c: _CAT_PRIORITY.get(c, 99)) if categories else None
    )
    sig_count = 0
    # Phase 3.15 — MinHash sketch cluster (before session check, used in save_scan_record)
    sketch_cid: str | None = None
    try:
        from .clustering import cluster_id_for_text
        sketch_cid = cluster_id_for_text(normalized)
    except Exception:
        pass

    if session is not None:
        # PHASE 2.8 — signature stage timing (DB write included)
        _t = time.perf_counter()
        sig_count = _upsert_signature(session, sig_hash, categories, normalized)
        _st["signature_check"] = round((time.perf_counter() - _t) * 1000)
        # Phase 3.2 — best-effort cluster assignment (never raises)
        try:
            from .cluster import assign_signature_to_cluster
            assign_signature_to_cluster(session, sig_hash, normalized[:200], top_cat)
        except Exception:
            pass
        # Phase 3.15 — sketch cluster upsert
        if sketch_cid is not None:
            try:
                from .clustering import upsert_cluster
                upsert_cluster(session, sketch_cid, top_cat, sig_hash, normalized[:200])
            except Exception:
                pass
        # PHASE 2.7 / 2.15 — stamp AttackSignature.cluster_id + upsert ThreatCluster
        try:
            from .signature_cluster import cluster_signature as _cs
            _cid = _cs(session, sig_hash, normalized, top_cat)
            if _cid:
                from .models import ThreatCluster as _TC
                from datetime import datetime as _dt, timezone as _tz
                _now = _dt.now(_tz.utc)
                _tc = session.exec(select(_TC).where(_TC.centroid_hash == _cid)).first()
                if _tc is None:
                    _tc = _TC(
                        centroid_hash=_cid, created_at=_now, updated_at=_now,
                        member_count=1, top_category=top_cat,
                        example_snippet=normalized[:200],
                        example_signature_hash=sig_hash,
                    )
                else:
                    _tc.member_count += 1
                    _tc.updated_at = _now
                    if top_cat and not _tc.top_category:
                        _tc.top_category = top_cat
                    if not _tc.example_signature_hash:
                        _tc.example_signature_hash = sig_hash
                session.add(_tc)
                session.commit()
        except Exception:
            pass

    elapsed_ms = round((time.perf_counter() - _t_start) * 1000)
    # PHASE 2.8 — ensure all nine stage keys present; zero-fill any that were skipped
    for _k in (
        "normalize", "injection_check", "pii_check", "hallucination_check",
        "rag_check", "tool_check", "signature_check", "consensus_check",
        "suggestion_generation",
    ):
        _st.setdefault(_k, 0)

    if block:
        decision = "block"
    elif severity == "medium":
        decision = "warn"
    else:
        decision = "allow"

    # ADVANCED — Max CPU Budget: when detector runtime was aborted by
    # max_detector_runtime_ms and the decision would be "allow", escalate
    # to "warn" so callers are notified that the scan was incomplete.
    if timed_out and pol.max_detector_runtime_ms is not None and decision == "allow":
        decision = "warn"
        reasons.append("cpu budget exceeded — scan incomplete")

    diff_result = None
    if baseline_output is not None:
        diff_result = _compute_diff(
            input_text, baseline_output, output_text, context, pol,
            retrieved_docs, tool_calls,
        )

    # PHASE 2.8 — suggestion generation stage timing
    _t = time.perf_counter()
    _plain_suggestions = generate_suggestions(categories)
    _hardening_suggestions = generate_structured_suggestions(categories)
    _st["suggestion_generation"] = round((time.perf_counter() - _t) * 1000)

    result = GuardScanResponse(
        risk_score=score,
        severity=severity,
        categories=categories,
        confidence=confidence,
        block=block,
        reasons=reasons,
        hallucination_score=h_score,
        grounding_score=grounding,
        hallucination_reasons=h_reasons,
        applied_policy=pol.model_dump(),
        signature_hash=sig_hash,
        signature_count=sig_count,
        elapsed_ms=elapsed_ms,
        decision=decision,
        rag_doc_hits=rag_doc_hits,                     # Phase 3.3
        rag_reasons=rag_reasons,                       # Phase 3.3
        rag_risk_score=rag_risk_score,                 # composite RAG risk score
        rag_docs=rag_docs,                             # PHASE 2.1 per-doc breakdown
        tool_risk_score=tool_risk_score,               # Phase 3.4 legacy score
        tool_reasons=tool_reasons,                     # Phase 3.4
        tool_violation_score=tool_violation_score,     # policy engine composite score
        tool_violations=tool_violations,               # violation type labels
        diff=diff_result,                  # Phase 3.5
        timed_out=timed_out,               # Phase 3.6
        performance_flags=performance_flags,  # Phase 3.6
        consensus_score=consensus_score,      # Phase 3.7
        consensus_reasons=consensus_reasons,  # Phase 3.7
        suggestions=_plain_suggestions,                                    # Phase 3.12.D
        hardening_suggestions=_hardening_suggestions,                      # PHASE 2.2
        cluster_id=sketch_cid or "",                   # Phase 3.15 patch
        strict_mode_triggered=_policy_strict_triggered,  # PHASE 2.3
        policy_source=_policy_source,                   # PHASE 2.18
        zero_trust_triggered=_zero_trust_triggered,     # PHASE 2.27
        detection_signals=_build_detection_signals(     # PHASE 2.6/2.9
            input_text, output_text, categories,
            rag_reasons, tool_violations, tool_reasons,
            h_score=h_score, h_reasons=h_reasons, severity=severity,
        ),
        stage_timings=_st,                              # PHASE 2.8
    )

    # Phase 3.12.C + Calibration — z-score normalization AND percentile calibration.
    # Both queries run before save_scan_record so the current scan is NOT included
    # in its own baseline/percentile window (avoids circular contamination).
    if session is not None:
        from .analytics import (
            compute_risk_baseline,
            compute_risk_percentiles,
            calibrate_risk_score,
            normalize_risk,        # PHASE 2.24
        )
        _mean, _std, _n = compute_risk_baseline(session, org_id)   # PHASE 2.24 — 3-tuple
        result.normalized_risk = normalize_risk(score, _mean, _std, _n)  # PHASE 2.24

        _sorted_scores = compute_risk_percentiles(session, org_id)
        result.calibrated_risk = calibrate_risk_score(score, _sorted_scores)

    # ADVANCED — Attacker Behavior Profiling.  Runs BEFORE save_scan_record so the
    # score is included on the persisted row.  Queries the existing rows (not the
    # current one) so there is no circular contamination.
    _attacker_score = 0
    _attacker_signals: dict = {}
    if session is not None:
        try:
            from .attacker_profile import compute_attacker_pattern_score as _aps
            # Build redacted snippet the same way save_scan_record does
            try:
                from .redaction import redact_string as _rs2
                _cur_snip = _rs2(input_text[:500])
            except Exception:
                _cur_snip = input_text[:500]
            _attacker_score, _attacker_signals = _aps(
                session,
                user_id=user_id,
                org_id=org_id,
                input_snippet=_cur_snip,
                risk_score=score,
                categories_json_str=json.dumps(categories),
            )
        except Exception:
            pass

    result.attacker_pattern_score = _attacker_score
    result.attacker_signals = _attacker_signals

    # PHASE 2.26 — flag category + persist per-signal metric rows when score is high
    _ATCK_THRESHOLD = 20
    if _attacker_score >= _ATCK_THRESHOLD:
        if "attack_pattern" not in categories:
            categories.append("attack_pattern")
            result.categories = categories
        if session is not None and not _sandbox_mode:  # PHASE 2.35 — skip in sandbox
            try:
                from .models import AttackerPatternMetric as _APM
                _now_apm = datetime.now(timezone.utc)
                _sig_map = {
                    "rapid_variant_mutation": _attacker_signals.get("variant_score", 0),
                    "encoding_cycling":       _attacker_signals.get("encoding_score", 0),
                    "near_miss_attacks":      _attacker_signals.get("nearmiss_score", 0),
                }
                for _pt, _sig_score in _sig_map.items():
                    if _sig_score > 0:
                        session.add(_APM(
                            created_at=_now_apm, org_id=org_id, user_id=user_id,
                            pattern_type=_pt, score=float(_sig_score),
                            metadata_json=json.dumps(_attacker_signals),
                        ))
                session.commit()
            except Exception:
                pass

    if session is not None:
        save_scan_record(
            session, result,
            input_text=input_text,
            output_text=output_text or "",
            user_id=user_id,
            org_id=org_id,
            plan=user_plan or "public",
            timed_out=timed_out,               # Phase 3.6
            detector_count=detectors_run,      # Phase 3.6
            consensus_score=consensus_score,   # Phase 3.7
            sketch_cluster_id=sketch_cid,      # Phase 3.15
            attacker_pattern_score=_attacker_score,  # ADVANCED
            random_seed=_random_seed,          # ADVANCED — Replay Testing
            rag_risk_score=rag_risk_score,     # PHASE 2.1
            sandbox_mode=_sandbox_mode,        # PHASE 2.35
        )
        # ADVANCED — Replay Testing: persist the full payload so the scan can be
        # re-run deterministically via POST /guard/replay/{scan_id}.
        # PHASE 2.35 — skip replay store in sandbox mode (no full-payload side effects).
        if not _sandbox_mode:
            try:
                from .models import GuardScanReplayStore, GuardScanRecord
                _rec = session.exec(
                    select(GuardScanRecord).where(
                        GuardScanRecord.input_hash == hashlib.sha256(input_text.encode()).hexdigest()
                    ).order_by(GuardScanRecord.created_at.desc())
                ).first()
                if _rec is not None and _rec.id is not None:
                    _replay_store = GuardScanReplayStore(
                        scan_record_id=_rec.id,
                        user_id=user_id,
                        org_id=org_id,
                        random_seed=_random_seed,
                        input_text=input_text[:200_000],
                        output_text=(output_text or "")[:200_000],
                        context_text=context[:200_000] if context else None,
                        policy_json=json.dumps(pol.model_dump()),
                    )
                    session.add(_replay_store)
                    session.commit()
            except Exception:
                pass  # replay store is best-effort; never break the scan response

    # PHASE 2.35 — mark sandbox result before return
    result.sandbox_mode_applied = _sandbox_mode

    # Phase 3.14 — SIEM webhook (best-effort, only on warn/block)
    # PHASE 2.35 — skip in sandbox mode
    if session is not None and decision in {"warn", "block"} and not _sandbox_mode:
        try:
            from .webhooks import fire_guard_event
            from datetime import datetime, timezone
            fire_guard_event(session, org_id, {
                "type": "guard_scan",
                "org_id": org_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "decision": decision,
                "severity": severity,
                "categories": categories,
                "signature_hash": sig_hash,
                "risk_score": score,
                "elapsed_ms": elapsed_ms,
                "attacker_pattern_score": _attacker_score,      # ADVANCED
                "attacker_signals": _attacker_signals,          # ADVANCED
            })
        except Exception:
            pass

    return result
