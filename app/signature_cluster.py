"""PHASE 2.7 / 2.15 — Token-shingle MinHash fingerprinting + AttackSignature cluster assignment.

Algorithm (fingerprint):
  1. Lowercase-tokenise text into alphanumeric tokens.
  2. Build word trigrams (fallback: bigrams for 2-token texts).  PHASE 2.15 upgrade.
  3. FNV-32 hash each trigram.
  4. Take the K smallest hashes (MinHash sketch).
  5. cluster_id = sha256(sketch vector) as hex.

Similar texts share many trigrams → near-identical sketches → same cluster_id.
No ML deps. Fully deterministic. Never raises.
"""
from __future__ import annotations

import hashlib
import re
from typing import Optional

from sqlmodel import Session, select

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_K = 16   # MinHash sketch width (K smallest hashes)
_JACCARD_THRESHOLD = 0.5  # are_signatures_similar default


# ── hash primitive ────────────────────────────────────────────────────────────

def _fnv32(s: str) -> int:
    """FNV-1a 32-bit — fast inline, no crypto overhead."""
    h = 0x811C9DC5
    for ch in s.encode():
        h ^= ch
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


# ── public API ────────────────────────────────────────────────────────────────

def fingerprint(text: str) -> str:
    """Return a deterministic cluster_id hex string for *text*.

    PHASE 2.15: uses word-trigram MinHash sketching (bigram fallback for 2-token
    texts, full-text hash for single-token).  Trigrams give better discrimination
    than bigrams: fewer false-positive cluster merges for unrelated short payloads.
    """
    tokens = _TOKEN_RE.findall(text.lower())
    if len(tokens) < 2:
        # Too short to shingle — full-text hash → own cluster
        return hashlib.sha256(text.lower().encode()).hexdigest()

    if len(tokens) >= 3:
        shingles = [f"{tokens[i]} {tokens[i+1]} {tokens[i+2]}" for i in range(len(tokens) - 2)]
    else:
        shingles = [f"{tokens[0]} {tokens[1]}"]   # bigram fallback (exactly 2 tokens)

    hashes = sorted(_fnv32(s) for s in shingles)
    sketch = hashes[:_K] if len(hashes) >= _K else hashes
    raw = "|".join(str(h) for h in sketch)
    return hashlib.sha256(raw.encode()).hexdigest()


def are_signatures_similar(text_a: str, text_b: str, threshold: float = _JACCARD_THRESHOLD) -> bool:
    """Return True if text_a and text_b are similar via Jaccard on token sets.

    Uses the same tokenisation as fingerprint() so results are consistent with
    cluster assignment.  Always returns bool; never raises.
    """
    try:
        toks_a = set(_TOKEN_RE.findall(text_a.lower()))
        toks_b = set(_TOKEN_RE.findall(text_b.lower()))
        if not toks_a and not toks_b:
            return True
        union = toks_a | toks_b
        return (len(toks_a & toks_b) / len(union)) >= threshold if union else False
    except Exception:
        return False


def cluster_signature(
    session: Session,
    sig_hash: str,
    normalized_text: str,
    category: Optional[str] = None,
) -> Optional[str]:
    """Compute fingerprint and stamp AttackSignature.cluster_id if not already set.

    Returns the cluster_id string, or None on any error.
    Never raises — all exceptions are swallowed.
    """
    try:
        from .models import AttackSignature

        cid = fingerprint(normalized_text)
        row = session.exec(
            select(AttackSignature).where(AttackSignature.signature_hash == sig_hash)
        ).first()
        if row is not None and row.cluster_id is None:
            row.cluster_id = cid
            session.add(row)
            session.commit()
        return cid
    except Exception:
        return None
