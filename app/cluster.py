"""Lightweight signature clustering — token shingles + Jaccard similarity (Phase 3.2).

No ML dependencies.  Best-effort: every public function silently swallows
all exceptions so caller behaviour is never disrupted.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Session, select

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_MIN_TOKEN_LEN = 3
_SIMILARITY_THRESHOLD = 0.55
_CANDIDATE_LIMIT = 50


# ---------------------------------------------------------------------------
# Core primitives
# ---------------------------------------------------------------------------

def tokenize(text: str) -> set[str]:
    """Lowercase alphanumeric tokens; drop tokens shorter than _MIN_TOKEN_LEN."""
    return {t for t in _TOKEN_RE.findall(text.lower()) if len(t) >= _MIN_TOKEN_LEN}


def jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard similarity in [0, 1].  Both empty → 1.0."""
    if not a and not b:
        return 1.0
    union = a | b
    return len(a & b) / len(union) if union else 0.0


# ---------------------------------------------------------------------------
# Assignment
# ---------------------------------------------------------------------------

def assign_signature_to_cluster(
    session: Session,
    signature_hash: str,
    example_snippet: str,
    top_category: Optional[str],
) -> None:
    """Assign *signature_hash* to the best-matching cluster or create a new one.

    Rules:
    - If already a member of any cluster → no-op.
    - Fetch up to _CANDIDATE_LIMIT clusters ordered by updated_at desc.
    - Compare snippet tokens to each centroid's stored example_snippet via Jaccard.
    - best_sim >= _SIMILARITY_THRESHOLD → add as member, bump member_count + updated_at.
    - Otherwise → new cluster (centroid_hash = signature_hash).

    Never raises.
    """
    try:
        from .models import ThreatCluster, ThreatClusterMember

        # Already assigned?
        if session.exec(
            select(ThreatClusterMember).where(
                ThreatClusterMember.signature_hash == signature_hash
            )
        ).first() is not None:
            return

        sig_tokens = tokenize(example_snippet)
        now = datetime.now(timezone.utc)

        candidates = session.exec(
            select(ThreatCluster)
            .order_by(ThreatCluster.updated_at.desc())
            .limit(_CANDIDATE_LIMIT)
        ).all()

        best_cluster: Optional[ThreatCluster] = None
        best_sim = 0.0
        for cluster in candidates:
            sim = jaccard(sig_tokens, tokenize(cluster.example_snippet))
            if sim > best_sim:
                best_sim = sim
                best_cluster = cluster

        if best_cluster is not None and best_sim >= _SIMILARITY_THRESHOLD:
            # Join existing cluster
            session.add(
                ThreatClusterMember(
                    cluster_id=best_cluster.id,
                    signature_hash=signature_hash,
                )
            )
            best_cluster.member_count += 1
            best_cluster.updated_at = now
            session.add(best_cluster)
            session.commit()
        else:
            # New cluster — this signature is the centroid
            cluster = ThreatCluster(
                created_at=now,
                updated_at=now,
                centroid_hash=signature_hash,
                member_count=1,
                top_category=top_category,
                example_snippet=example_snippet[:200],
            )
            session.add(cluster)
            session.flush()  # populate cluster.id before FK insert
            session.add(
                ThreatClusterMember(
                    cluster_id=cluster.id,
                    signature_hash=signature_hash,
                )
            )
            session.commit()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Graph builder — Phase ADVANCED: Signature Graph Mapping
# ---------------------------------------------------------------------------

#: Default similarity threshold for graph edges.
#: Lower than _SIMILARITY_THRESHOLD (0.55) so we capture *related* clusters
#: that share vocabulary without being close enough to merge.
_GRAPH_THRESHOLD = 0.30


def build_cluster_graph(
    clusters: list,
    threshold: float = _GRAPH_THRESHOLD,
) -> tuple[list[dict], list[dict]]:
    """Build an adjacency-list graph from a list of ThreatCluster ORM objects.

    Algorithm
    ---------
    1. Tokenize each cluster's ``example_snippet`` with :func:`tokenize`.
    2. Compute pairwise Jaccard similarity — O(n²) over the cluster list.
    3. Emit an undirected edge for every pair whose similarity >= *threshold*.

    Returns
    -------
    (nodes, edges) where

    nodes — list of dicts:
        id, centroid_hash, member_count, top_category, example_snippet

    edges — list of dicts:
        source (cluster id), target (cluster id), similarity (rounded to 4dp)

    Performance note
    ----------------
    With the default ``limit=100`` the worst case is 4 950 Jaccard comparisons
    over token sets that are typically 10–40 tokens — well under 1 ms in CPython.
    At ``limit=500`` (API max) it is 124 750 pairs, still comfortably sub-second.
    """
    nodes: list[dict] = [
        {
            "id": c.id,
            "centroid_hash": c.centroid_hash,
            "member_count": c.member_count,
            "top_category": c.top_category,
            "example_snippet": c.example_snippet,
        }
        for c in clusters
    ]

    # Pre-tokenize once per cluster — avoids repeated tokenize() calls in O(n²)
    token_sets: list[tuple[int, set[str]]] = [
        (c.id, tokenize(c.example_snippet)) for c in clusters
    ]

    edges: list[dict] = []
    n = len(token_sets)
    for i in range(n):
        id_a, tok_a = token_sets[i]
        for j in range(i + 1, n):
            id_b, tok_b = token_sets[j]
            sim = jaccard(tok_a, tok_b)
            if sim >= threshold:
                edges.append({
                    "source": id_a,
                    "target": id_b,
                    "similarity": round(sim, 4),
                })

    return nodes, edges
