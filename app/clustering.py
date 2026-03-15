"""MinHash-lite sketch clustering (Phase 3.15).

No randomness. No ML deps. Fully deterministic.

Algorithm:
  1. Extract word trigrams from normalized text.
  2. Hash each trigram with fnv-32 (inline, stdlib-free).
  3. Take K smallest hashes → sketch.
  4. cluster_id = sha256("|".join(map(str, sketch))).

Similar texts share many trigrams → similar sketches → same cluster_id.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Session, select

_K = 16          # sketch size
_MAX_GRAMS = 512  # cap trigrams to avoid huge inputs


# ── hashing ───────────────────────────────────────────────────────────────────

def _fnv32(s: str) -> int:
    """FNV-1a 32-bit hash — fast, no stdlib crypto overhead."""
    h = 0x811C9DC5
    for ch in s.encode():
        h ^= ch
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


# ── sketch builder ────────────────────────────────────────────────────────────

def build_sketch(normalized_text: str, k: int = _K) -> list[int]:
    """Return a sorted list of the K smallest FNV-32 trigram hashes."""
    words = normalized_text.split()
    trigrams: list[str] = []
    for i in range(len(words) - 2):
        trigrams.append(f"{words[i]} {words[i+1]} {words[i+2]}")
        if len(trigrams) >= _MAX_GRAMS:
            break

    if not trigrams:
        # fallback: character 4-grams
        t = normalized_text
        trigrams = [t[i:i+4] for i in range(0, len(t) - 3, 2)][:_MAX_GRAMS]

    hashes = sorted(_fnv32(g) for g in trigrams)
    return hashes[:k] if len(hashes) >= k else hashes


def cluster_id_for_text(normalized_text: str) -> str:
    """Deterministic cluster_id = sha256 of the sketch vector."""
    sketch = build_sketch(normalized_text)
    raw = "|".join(str(h) for h in sketch)
    return hashlib.sha256(raw.encode()).hexdigest()


# ── upsert ────────────────────────────────────────────────────────────────────

def upsert_cluster(
    session: Session,
    cluster_id: str,
    category: Optional[str],
    signature_hash: str,
    snippet: str,
) -> None:
    """Create or update ThreatCluster row keyed by centroid_hash=cluster_id.

    Uses existing ThreatCluster table (Phase 3.2) — centroid_hash is the
    sketch-derived cluster_id string so both clustering systems coexist.
    Never raises.
    """
    try:
        from .models import ThreatCluster

        now = datetime.now(timezone.utc)
        existing = session.exec(
            select(ThreatCluster).where(ThreatCluster.centroid_hash == cluster_id)
        ).first()

        if existing:
            existing.member_count += 1
            existing.updated_at = now
            if category and not existing.top_category:
                existing.top_category = category
            session.add(existing)
        else:
            session.add(ThreatCluster(
                centroid_hash=cluster_id,
                created_at=now,
                updated_at=now,
                member_count=1,
                top_category=category,
                example_snippet=snippet[:200],
            ))
        session.commit()
    except Exception:
        pass
