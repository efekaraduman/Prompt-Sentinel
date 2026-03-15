"""Attacker Behavior Profiling — ADVANCED.

Detects persistent adversarial patterns across scans from the same identity
(user_id or org_id) and returns a composite ``attacker_pattern_score`` (0–100).

Three behavioural signals are measured:

1. **Rapid variant mutation** (0–40 pts)
   Same source fires ≥5 scans in 10 minutes, sustaining a mean risk score ≥ 40
   AND probing ≥2 distinct category combinations — characteristic of an automated
   fuzzer cycling through payload variants.

2. **Encoding cycling** (0–35 pts)
   Recent inputs from the same source contain ≥2 distinct encoding types
   (base64 blobs, \\uXXXX / \\xXX escapes, URL %-encoding, hex 0x literals, or
   invisible/zero-width characters).  Legitimate users rarely mix encodings.

3. **Repeated near-miss attacks** (0–25 pts)
   ≥3 scans with risk_score ∈ [50, 99] (high-risk but not yet blocked) within
   15 minutes — the hallmark of an adversary probing just below the block
   threshold to avoid triggering an alert.

Entry point
-----------
``compute_attacker_pattern_score(session, user_id, org_id, input_snippet,
    risk_score, categories_json_str) -> tuple[int, dict]``

Returns ``(score_0_100, signals_dict)`` where ``signals_dict`` exposes the
per-signal contributions and evidence for downstream logging.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlmodel import Session, select


# ---------------------------------------------------------------------------
# Encoding-detection patterns
# ---------------------------------------------------------------------------

# Simple presence-based patterns (one match sufficient)
_SINGLE_PATTERNS: list[tuple[str, re.Pattern]] = [
    # base64: run of 20+ base64 chars (possibly with = padding)
    ("base64",        re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")),
    # unicode escapes: \uXXXX inside the text (literal backslash-u from JSON/payloads)
    ("unicode_escape", re.compile(r"\\u[0-9a-fA-F]{4}")),
    # hex byte escapes: \xXX
    ("hex_escape",    re.compile(r"\\x[0-9a-fA-F]{2}")),
    # hex literals: 0x followed by ≥4 hex digits
    ("hex_literal",   re.compile(r"0x[0-9a-fA-F]{4,}")),
    # invisible / zero-width chars
    ("invisible_chars", re.compile(
        r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad]"
    )),
]

# Count-based patterns (need ≥N non-overlapping matches)
_COUNT_PATTERNS: list[tuple[str, re.Pattern, int]] = [
    # URL percent-encoding: ≥3 %XX sequences anywhere in the text
    ("url_encode", re.compile(r"%[0-9A-Fa-f]{2}"), 3),
]


def _detect_encoding_types(text: str) -> set[str]:
    """Return the set of encoding type names detected in *text*."""
    found: set[str] = set()
    for name, pat in _SINGLE_PATTERNS:
        if pat.search(text):
            found.add(name)
    for name, pat, min_count in _COUNT_PATTERNS:
        if len(pat.findall(text)) >= min_count:
            found.add(name)
    return found


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def compute_attacker_pattern_score(
    session: Session,
    user_id: Optional[int],
    org_id: Optional[int],
    input_snippet: str,
    risk_score: int,
    categories_json_str: str = "[]",
) -> tuple[int, dict]:
    """Compute the attacker pattern score for a single incoming scan.

    Parameters
    ----------
    session:
        Active DB session.  Must not be None — call only from the synchronous
        scan path where a session exists.
    user_id, org_id:
        Caller identity.  At least one must be non-None; if both are None
        (anonymous public scan) the score is 0.
    input_snippet:
        First ≤500 chars of the redacted scan input, already stored on the
        current record.
    risk_score:
        Raw risk score (0–100) for the current scan.
    categories_json_str:
        JSON-encoded list of detected categories for the current scan.

    Returns
    -------
    tuple[int, dict]
        ``(attacker_pattern_score, signals)`` where ``signals`` is a dict
        with keys:
          variant_score, variant_count, variant_mean_risk, variant_cat_sets,
          encoding_score, encoding_types,
          nearmiss_score, nearmiss_count,
          total_score
    """
    signals: dict = {
        "variant_score": 0,
        "variant_count": 0,
        "variant_mean_risk": 0,
        "variant_cat_sets": 0,
        "encoding_score": 0,
        "encoding_types": [],
        "nearmiss_score": 0,
        "nearmiss_count": 0,
        "total_score": 0,
    }

    # Anonymous scans — nothing to profile
    if user_id is None and org_id is None:
        return 0, signals

    from .models import GuardScanRecord  # local to avoid circular import

    now = datetime.now(timezone.utc)

    # -----------------------------------------------------------------------
    # Fetch recent records for this identity (30-minute look-back window)
    # -----------------------------------------------------------------------
    # Build a filter clause based on available identity
    window_30 = now - timedelta(minutes=30)

    stmt = select(GuardScanRecord).where(
        GuardScanRecord.created_at >= window_30  # type: ignore[arg-type]
    )
    if user_id is not None:
        stmt = stmt.where(GuardScanRecord.user_id == user_id)
    elif org_id is not None:
        stmt = stmt.where(GuardScanRecord.org_id == org_id)

    # Limit look-back to 200 rows — sufficient for signal computation
    stmt = stmt.order_by(GuardScanRecord.created_at.desc()).limit(200)  # type: ignore[union-attr]
    recent: list[GuardScanRecord] = list(session.exec(stmt).all())

    if not recent:
        return 0, signals

    # -----------------------------------------------------------------------
    # Signal 1 — Rapid variant mutation (0–40 pts)
    # -----------------------------------------------------------------------
    window_10 = now - timedelta(minutes=10)
    burst = [r for r in recent if r.created_at >= window_10 or (
        # naive datetime fallback (SQLite may store without tz)
        r.created_at.tzinfo is None
        and r.created_at >= window_10.replace(tzinfo=None)
    )]

    variant_score = 0
    if len(burst) >= 5:
        mean_risk = sum(r.risk_score for r in burst) / len(burst)
        cat_sets: set[str] = set()
        for r in burst:
            try:
                cats = tuple(sorted(json.loads(r.categories_json or "[]")))
            except Exception:
                cats = ()
            cat_sets.add(cats)  # type: ignore[arg-type]

        signals["variant_count"] = len(burst)
        signals["variant_mean_risk"] = round(mean_risk, 1)
        signals["variant_cat_sets"] = len(cat_sets)

        if mean_risk >= 40 and len(cat_sets) >= 2:
            # Scale: 5 scans → 20 pts, 10 scans → 40 pts (capped)
            variant_score = min(40, 20 + (len(burst) - 5) * 4)
    signals["variant_score"] = variant_score

    # -----------------------------------------------------------------------
    # Signal 2 — Encoding cycling (0–35 pts)
    # -----------------------------------------------------------------------
    encoding_score = 0
    # Collect encoding types seen across last ≤10 scan snippets (including current)
    snippets_to_check = [input_snippet] + [r.input_snippet for r in recent[:9]]
    all_enc_types: set[str] = set()
    for snip in snippets_to_check:
        if snip:
            all_enc_types |= _detect_encoding_types(snip)

    signals["encoding_types"] = sorted(all_enc_types)
    if len(all_enc_types) >= 2:
        # 2 types → 15 pts, 3 types → 25 pts, 4+ types → 35 pts
        encoding_score = min(35, 15 + (len(all_enc_types) - 2) * 10)
    signals["encoding_score"] = encoding_score

    # -----------------------------------------------------------------------
    # Signal 3 — Repeated near-miss attacks (0–25 pts)
    # -----------------------------------------------------------------------
    nearmiss_score = 0
    window_15 = now - timedelta(minutes=15)
    near_miss_rows = [
        r for r in recent
        if (
            50 <= r.risk_score <= 99
            and not r.blocked
            and (
                r.created_at >= window_15
                or (r.created_at.tzinfo is None and r.created_at >= window_15.replace(tzinfo=None))
            )
        )
    ]
    # Include the current scan if it qualifies
    current_is_nearmiss = (50 <= risk_score <= 99)
    near_miss_count = len(near_miss_rows) + (1 if current_is_nearmiss else 0)

    signals["nearmiss_count"] = near_miss_count
    if near_miss_count >= 3:
        # 3 → 15 pts, 5+ → 25 pts
        nearmiss_score = min(25, 15 + (near_miss_count - 3) * 5)
    signals["nearmiss_score"] = nearmiss_score

    # -----------------------------------------------------------------------
    # Composite score
    # -----------------------------------------------------------------------
    total = min(100, variant_score + encoding_score + nearmiss_score)
    signals["total_score"] = total
    return total, signals
