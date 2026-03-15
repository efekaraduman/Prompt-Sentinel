from __future__ import annotations

import asyncio
import json
from typing import Dict, List, Optional

from sqlalchemy import func, update
from sqlmodel import Session, select

from .db import engine
from .models import Campaign, Finding
from .red_agent import ATTACK_CATEGORIES, RedAgent
from .runner import run_single_attack


REQUIRED_METRIC_KEYS: Dict[str, object] = {
    "max_risk": 0,
    "avg_risk": 0.0,
    "success_rate": 0.0,
    "high_risk_count": 0,
    "leakage_count": 0,
    "override_count": 0,
    "category_counts": {},
    # Richer metrics (D).
    "category_avg_risk": {},
    "category_success_rates": {},
    "transform_counts": {},
    "avg_confidence": 0.0,
}


def ensure_metrics(metrics: Dict[str, object] | None) -> Dict[str, object]:
    """
    Ensure metrics always contains a consistent set of keys + safe defaults.
    Keeps internal accumulators (sum_risk/total_findings) in DB, but callers
    can use public_metrics() to strip them for API responses.
    """
    base: Dict[str, object] = {}
    if isinstance(metrics, dict):
        base.update(metrics)

    # internal accumulators (safe to persist, not required to expose)
    base.setdefault("total_findings", 0)
    base.setdefault("sum_risk", 0.0)

    # required public keys
    for key, default in REQUIRED_METRIC_KEYS.items():
        if key not in base or base[key] is None:
            base[key] = {} if isinstance(default, dict) else default

    # type normalization
    base["total_findings"] = int(base.get("total_findings", 0) or 0)
    base["sum_risk"] = float(base.get("sum_risk", 0.0) or 0.0)
    base["max_risk"] = int(base.get("max_risk", 0) or 0)
    base["high_risk_count"] = int(base.get("high_risk_count", 0) or 0)
    base["leakage_count"] = int(base.get("leakage_count", 0) or 0)
    base["override_count"] = int(base.get("override_count", 0) or 0)

    for dict_key in ("category_counts", "category_avg_risk", "category_success_rates", "transform_counts"):
        if not isinstance(base.get(dict_key), dict):
            base[dict_key] = {}

    base["sum_confidence"] = float(base.get("sum_confidence", 0.0) or 0.0)

    # derived fields
    total = int(base["total_findings"])
    sum_risk = float(base["sum_risk"])
    base["avg_risk"] = (sum_risk / total) if total else 0.0
    base["success_rate"] = (base["high_risk_count"] / total) if total else 0.0
    base["avg_confidence"] = (base["sum_confidence"] / total) if total else 0.0

    # Per-category derived averages.
    cat_counts: Dict = base["category_counts"]
    cat_sum_risk: Dict = dict(base.get("_cat_sum_risk", {}))
    cat_high: Dict = dict(base.get("_cat_high", {}))
    cat_avg: Dict = {}
    cat_success: Dict = {}
    for cat, cnt in cat_counts.items():
        cnt = int(cnt)
        if cnt:
            cat_avg[cat] = round(float(cat_sum_risk.get(cat, 0)) / cnt, 2)
            cat_success[cat] = round(int(cat_high.get(cat, 0)) / cnt, 3)
    base["category_avg_risk"] = cat_avg
    base["category_success_rates"] = cat_success

    return base


def public_metrics(metrics: Dict[str, object] | None) -> Dict[str, object]:
    data = ensure_metrics(metrics)
    for key in ("sum_risk", "total_findings", "sum_confidence", "_cat_sum_risk", "_cat_high"):
        data.pop(key, None)
    return data


def _update_metrics(metrics: Dict[str, object], finding: Finding) -> None:
    """Incrementally update aggregate campaign metrics given a new finding."""
    metrics.update(ensure_metrics(metrics))

    total = int(metrics.get("total_findings", 0)) + 1
    sum_risk = float(metrics.get("sum_risk", 0.0)) + float(finding.risk_score)
    max_risk = max(int(metrics.get("max_risk", 0)), int(finding.risk_score))

    leakage_count = int(metrics.get("leakage_count", 0))
    override_count = int(metrics.get("override_count", 0))
    if finding.leakage_detected:
        leakage_count += 1
    if finding.override_detected:
        override_count += 1

    high_risk_count = int(metrics.get("high_risk_count", 0))
    is_high = int(finding.risk_score) >= 70
    if is_high:
        high_risk_count += 1

    category_counts: Dict[str, int] = dict(metrics.get("category_counts", {}))
    category_counts[finding.category] = int(category_counts.get(finding.category, 0)) + 1

    # Per-category accumulators.
    cat_sum_risk: Dict[str, float] = dict(metrics.get("_cat_sum_risk", {}))
    cat_sum_risk[finding.category] = float(cat_sum_risk.get(finding.category, 0)) + float(finding.risk_score)
    cat_high: Dict[str, int] = dict(metrics.get("_cat_high", {}))
    if is_high:
        cat_high[finding.category] = int(cat_high.get(finding.category, 0)) + 1

    # Transform counts.
    transform_counts: Dict[str, int] = dict(metrics.get("transform_counts", {}))
    t_name = finding.transform_name or "none"
    transform_counts[t_name] = int(transform_counts.get(t_name, 0)) + 1

    # Confidence accumulator.
    sum_confidence = float(metrics.get("sum_confidence", 0.0)) + float(finding.confidence_score or 0.0)

    metrics.update(
        {
            "total_findings": total,
            "sum_risk": sum_risk,
            "max_risk": max_risk,
            "leakage_count": leakage_count,
            "override_count": override_count,
            "high_risk_count": high_risk_count,
            "category_counts": category_counts,
            "transform_counts": transform_counts,
            "sum_confidence": sum_confidence,
            "_cat_sum_risk": cat_sum_risk,
            "_cat_high": cat_high,
        }
    )


async def start_campaign(campaign_id: int, categories: Optional[List[str]] = None) -> None:
    """
    Public entrypoint to run a campaign in the background.

    This function is `async` but delegates the blocking work to a thread so that
    the FastAPI event loop is not held by database operations.
    """
    await asyncio.to_thread(_run_campaign_sync, campaign_id, categories)


def _run_campaign_sync(campaign_id: int, categories: Optional[List[str]] = None) -> None:
    """Blocking implementation of the campaign loop, executed in a worker thread."""
    with Session(engine) as session:
        # ── Distributed lock: serialise the queued→running CAS across workers ──
        from .locking import acquire_lock, release_lock

        lock_key = f"campaign:{campaign_id}"
        owner = acquire_lock(session, lock_key)
        if owner is None:
            # Another worker is starting this campaign; bail out.
            return

        try:
            # Atomic queued -> running transition; prevents double-start races.
            result = session.exec(
                update(Campaign)
                .where(Campaign.id == campaign_id, Campaign.status == "queued")
                .values(status="running")
            )
            session.commit()
            if result.rowcount == 0:  # type: ignore[union-attr]
                return  # already running / completed / failed / stopped
        finally:
            # Release BEFORE the long iteration loop — TTL would expire otherwise.
            release_lock(session, lock_key, owner)

        campaign = session.get(Campaign, campaign_id)
        if campaign is None:
            return

        allowed_categories = [c for c in (categories or ATTACK_CATEGORIES) if c in ATTACK_CATEGORIES]
        if not allowed_categories:
            allowed_categories = ATTACK_CATEGORIES.copy()

        # Cache immutable fields so session.expire() doesn't re-read them every iteration.
        sys_prompt = campaign.system_prompt
        model_name = campaign.model
        campaign_pk = campaign.id or 1

        agent = RedAgent(
            system_prompt=sys_prompt,
            model=model_name,
            categories=allowed_categories,
            seed=campaign_pk,
        )

        # Recover metrics if present, otherwise start fresh (always normalized).
        try:
            loaded = json.loads(campaign.metrics_json or "{}")
            metrics: Dict[str, object] = ensure_metrics(loaded if isinstance(loaded, dict) else {})
        except Exception:
            metrics = ensure_metrics({})

        try:
            for iteration in range(int(campaign.iterations_done) + 1, int(campaign.iterations_total) + 1):
                # Expire cached state so the next attribute access hits the DB.
                session.expire(campaign)
                if campaign.status == "stopped":
                    break

                category, attack_prompt = agent.next_attack()
                chain_strategy = agent.get_chain_strategy(iteration)
                result = run_single_attack(
                    system_prompt=sys_prompt,
                    model=model_name,
                    attack_prompt=attack_prompt,
                    category=category,
                    iteration=iteration,
                    seed=campaign_pk,
                    chain_strategy=chain_strategy,
                )

                finding = Finding(
                    campaign_id=campaign_pk,
                    iteration=iteration,
                    category=category,
                    attack_prompt=result["attack_prompt"],
                    llm_response=result["llm_response"],
                    leakage_detected=bool(result["leakage_detected"]),
                    override_detected=bool(result["override_detected"]),
                    risk_score=int(result["risk_score"]),
                    notes=result["notes"],
                    attack_chain_json=result.get("attack_chain_json"),
                    turn_count=result.get("turn_count"),
                    transform_name=result.get("transform_name"),
                    confidence_score=result.get("confidence_score"),
                )
                session.add(finding)

                _update_metrics(metrics, finding)

                # Persist campaign progress + metrics.
                campaign.iterations_done = iteration
                campaign.metrics_json = json.dumps(ensure_metrics(metrics))

                session.add(campaign)
                session.commit()

                agent.register_result(category, attack_prompt, finding.risk_score)

            # Final status update, unless already stopped/failed.
            session.expire(campaign)
            if campaign.status not in {"stopped", "failed"}:
                campaign.status = "completed"
                campaign.metrics_json = json.dumps(ensure_metrics(metrics))
                session.add(campaign)
                session.commit()
                # PHASE 2.0 — update model risk profile with campaign-level averages
                try:
                    from .model_risk import update_model_profile as _ump
                    _avg_risk  = int(metrics.get("avg_risk", 0) or 0)  # type: ignore[arg-type]
                    _org       = getattr(campaign, "org_id", None)
                    _ump(session, _org, campaign.model or "unknown",
                         _avg_risk, 0, "allow")
                except Exception:
                    pass

        except Exception as exc:  # pragma: no cover - defensive path
            session.rollback()
            session.expire(campaign)
            campaign.status = "failed"
            campaign.error_message = str(exc)
            campaign.metrics_json = json.dumps(ensure_metrics(metrics))
            session.add(campaign)
            session.commit()


def get_campaign_or_none(session: Session, campaign_id: int) -> Optional[Campaign]:
    """Small helper to load a campaign or return None."""
    return session.get(Campaign, campaign_id)


def get_findings_for_campaign(
    session: Session,
    campaign_id: int,
    page: int,
    page_size: int,
    min_risk: int,
    sort_desc: bool,
) -> Dict[str, object]:
    """Fetch paginated findings for a campaign."""
    base_stmt = select(Finding).where(
        Finding.campaign_id == campaign_id,
        Finding.risk_score >= min_risk,
    )

    if sort_desc:
        ordered_stmt = base_stmt.order_by(Finding.risk_score.desc(), Finding.iteration.asc())
    else:
        ordered_stmt = base_stmt.order_by(Finding.risk_score.asc(), Finding.iteration.asc())

    count_stmt = select(func.count()).select_from(base_stmt.subquery())
    total = int(session.exec(count_stmt).one())

    offset = (page - 1) * page_size
    results = session.exec(ordered_stmt.offset(offset).limit(page_size)).all()

    return {
        "items": results,
        "total": total,
    }


def get_all_findings_for_campaign(session: Session, campaign_id: int) -> List[Finding]:
    """Return every finding for a campaign, ordered by iteration ascending."""
    stmt = (
        select(Finding)
        .where(Finding.campaign_id == campaign_id)
        .order_by(Finding.iteration.asc())
    )
    return list(session.exec(stmt).all())