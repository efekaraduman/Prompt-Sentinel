"""Running-average model risk profile updater (PHASE 2.0).

Called after every guard scan and campaign completion to maintain an
org-scoped per-model risk summary in ModelRiskProfile.

update_model_profile() never raises — profile updates must not abort requests.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import List, Optional

from sqlmodel import Session, select

logger = logging.getLogger(__name__)


def update_model_risk(
    session: Session,
    model_name: str,
    risk_score: int,
    blocked: bool,
) -> None:
    """Deprecated shim — forwards to update_model_profile with org_id=None."""
    update_model_profile(
        session, None, model_name, risk_score, 0,
        "block" if blocked else "allow",
    )


# ── PHASE 2.0 — org-scoped profile ───────────────────────────────────────────

def update_model_profile(
    session: Session,
    org_id: Optional[int],
    model_name: str,
    risk_score: int,
    consensus_score: int,
    decision: str,
) -> None:
    """Upsert ModelRiskProfile for (org_id, model_name) using incremental running averages.

    Uses the formula: new_mean = (old_mean * n + new_value) / (n + 1)
    Never raises — profile updates must not abort the calling request.
    """
    try:
        from .models import ModelRiskProfile

        name    = (model_name or "unknown").strip() or "unknown"
        blocked = decision == "block"
        warned  = decision == "warn"

        row = session.exec(
            select(ModelRiskProfile)
            .where(ModelRiskProfile.org_id == org_id)
            .where(ModelRiskProfile.model_name == name)
        ).first()

        if row is None:
            row = ModelRiskProfile(
                org_id=org_id,
                model_name=name,
                avg_risk_score=float(risk_score),
                avg_consensus_score=float(consensus_score),
                block_rate=1.0 if blocked else 0.0,
                warn_rate=1.0 if warned else 0.0,
                sample_count=1,
                updated_at=datetime.utcnow(),
            )
        else:
            n = row.sample_count
            row.avg_risk_score      = (row.avg_risk_score      * n + risk_score)              / (n + 1)
            row.avg_consensus_score = (row.avg_consensus_score * n + consensus_score)          / (n + 1)
            row.block_rate          = (row.block_rate          * n + (1.0 if blocked else 0.0)) / (n + 1)
            row.warn_rate           = (row.warn_rate           * n + (1.0 if warned  else 0.0)) / (n + 1)
            row.sample_count        = n + 1
            row.updated_at          = datetime.utcnow()

        session.add(row)
        session.commit()
    except Exception as exc:
        logger.warning("update_model_profile failed org=%s model=%s: %s", org_id, model_name, exc)


def list_model_profiles(session: Session, org_id: Optional[int]) -> List:
    """Return ModelRiskProfile rows for org_id sorted by sample_count DESC."""
    from .models import ModelRiskProfile

    rows = session.exec(
        select(ModelRiskProfile).where(ModelRiskProfile.org_id == org_id)
    ).all()
    return sorted(rows, key=lambda r: r.sample_count, reverse=True)
