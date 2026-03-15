"""Usage metering: per-user monthly counters and quota enforcement."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Literal, NamedTuple, Optional

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from .models import UsageCounter


def current_period_ym() -> str:
    """Return the current UTC month as 'YYYY-MM'."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m")


# Alias used by Phase 1.2 metering.
current_period = current_period_ym


def get_or_create_counter(session: Session, user_id: int, period_ym: str) -> UsageCounter:
    """Fetch or atomically create the UsageCounter for (user_id, period_ym)."""
    row = session.exec(
        select(UsageCounter)
        .where(UsageCounter.user_id == user_id)
        .where(UsageCounter.period_ym == period_ym)
    ).first()
    if row is not None:
        return row
    row = UsageCounter(
        user_id=user_id,
        period_ym=period_ym,
        updated_at=datetime.utcnow(),
    )
    session.add(row)
    try:
        session.commit()
        session.refresh(row)
    except IntegrityError:
        # Race: another request already created the row; roll back and re-fetch.
        session.rollback()
        row = session.exec(
            select(UsageCounter)
            .where(UsageCounter.user_id == user_id)
            .where(UsageCounter.period_ym == period_ym)
        ).first()
    return row


class Quotas(NamedTuple):
    guard_scans: int
    campaign_iterations: int


def plan_quotas(plan: str) -> Quotas:
    """Return monthly limits for a given plan string."""
    if plan == "pro":
        return Quotas(guard_scans=20_000, campaign_iterations=20_000)
    if plan == "free":
        return Quotas(guard_scans=500, campaign_iterations=200)
    # "public" or any unknown plan
    return Quotas(guard_scans=50, campaign_iterations=0)


def incr_guard_scans(session: Session, user_id: int, n: int = 1) -> None:
    row = get_or_create_counter(session, user_id, current_period_ym())
    row.guard_scans += n
    row.updated_at = datetime.utcnow()
    session.add(row)
    session.commit()


def incr_campaign_iterations(session: Session, user_id: int, n: int) -> None:
    row = get_or_create_counter(session, user_id, current_period_ym())
    row.campaign_iterations += n
    row.updated_at = datetime.utcnow()
    session.add(row)
    session.commit()


def enforce_guard_scans(session: Session, user_id: int, plan: str) -> tuple[bool, int]:
    """Return (allowed, remaining). Does NOT increment."""
    row = get_or_create_counter(session, user_id, current_period_ym())
    limit = plan_quotas(plan).guard_scans
    remaining = max(0, limit - row.guard_scans)
    return remaining > 0, remaining


def enforce_campaign_iterations(
    session: Session, user_id: int, plan: str, requested: int
) -> tuple[bool, int]:
    """Return (allowed, remaining). Does NOT increment."""
    row = get_or_create_counter(session, user_id, current_period_ym())
    limit = plan_quotas(plan).campaign_iterations
    remaining = max(0, limit - row.campaign_iterations)
    return remaining >= requested, remaining


# ---------------------------------------------------------------------------
# Phase 1.2 — org-aware bump + read helpers
# ---------------------------------------------------------------------------

def read_usage(session: Session, period: str, user_id: int) -> tuple[int, int]:
    """Return (guard_scans, campaigns_started) for *user_id* in *period*."""
    from .models import MonthlyUsage
    row = session.exec(
        select(MonthlyUsage)
        .where(MonthlyUsage.period_yyyymm == period)
        .where(MonthlyUsage.user_id == user_id)
    ).first()
    return (row.guard_scans, row.campaigns_started) if row else (0, 0)


def org_total_usage(session: Session, period: str, org_id: int) -> tuple[int, int]:
    """Return (guard_scans_sum, campaigns_started_sum) across all org members in *period*."""
    from .models import MonthlyUsage
    rows = session.exec(
        select(MonthlyUsage)
        .where(MonthlyUsage.org_id == org_id)
        .where(MonthlyUsage.period_yyyymm == period)
    ).all()
    return (
        sum(r.guard_scans for r in rows),
        sum(r.campaigns_started for r in rows),
    )

def check_thresholds_and_notify(
    session: Session,
    *,
    period: str,
    org_id: Optional[int],
    user_id: int,
    plan: str,
    guard_scans: int,
    campaigns_started: int,
) -> None:
    """Insert UsageNotification rows at 80 % / 100 % thresholds (once per period).

    Only acts for limited plans (free/public).  Never raises.
    """
    from .limits import get_monthly_limits, resolve_plan as _resolve
    from .models import UsageNotification, User as _User
    from .notify import maybe_send_email

    resolved = _resolve(plan)
    if resolved not in ("free", "public"):
        return  # Pro is unlimited — nothing to notify

    guard_limit, camps_limit = get_monthly_limits(resolved)

    candidates: list[str] = []
    if guard_limit is not None and guard_limit > 0:
        pct = guard_scans / guard_limit
        if pct >= 1.0:
            candidates.append("usage_100_guard")
        elif pct >= 0.8:
            candidates.append("usage_80_guard")
    if camps_limit is not None and camps_limit > 0:
        pct = campaigns_started / camps_limit
        if pct >= 1.0:
            candidates.append("usage_100_campaigns")
        elif pct >= 0.8:
            candidates.append("usage_80_campaigns")

    if not candidates:
        return

    # Fetch user email once for SMTP (best-effort).
    user_email: Optional[str] = None
    try:
        u = session.exec(select(_User).where(_User.id == user_id)).first()
        if u:
            user_email = u.email
    except Exception:
        pass

    for kind in candidates:
        try:
            existing = session.exec(
                select(UsageNotification)
                .where(UsageNotification.period_yyyymm == period)
                .where(UsageNotification.user_id == user_id)
                .where(UsageNotification.kind == kind)
            ).first()
            if existing:
                continue

            notif = UsageNotification(
                period_yyyymm=period,
                org_id=org_id,
                user_id=user_id,
                kind=kind,
            )
            session.add(notif)
            try:
                session.flush()
            except Exception:
                session.rollback()
                continue

            session.commit()

            # Send best-effort email if SMTP is configured.
            if user_email:
                label = "guard scans" if "guard" in kind else "campaigns"
                pct_label = "100%" if "100" in kind else "80%"
                maybe_send_email(
                    to_email=user_email,
                    subject=f"[PromptSentinel] You've used {pct_label} of your {label} quota",
                    body=(
                        f"Hi,\n\n"
                        f"You have used {pct_label} of your monthly {label} quota "
                        f"for the period {period}.\n\n"
                        f"Upgrade to Pro for unlimited usage:\n"
                        f"https://app.promptsentinel.ai/pricing\n"
                    ),
                )
        except Exception:
            try:
                session.rollback()
            except Exception:
                pass


def org_enforce_guard_scans(session: Session, org_id: int, plan: str) -> tuple[bool, int]:
    """Org-level guard scan quota check via MonthlyUsage aggregate.

    Returns (allowed, remaining).  Does NOT increment.
    Falls back to per-user enforcement when org_id is 0 (public sentinel).
    """
    period = current_period_ym()
    used, _ = org_total_usage(session, period, org_id)
    limit = plan_quotas(plan).guard_scans
    remaining = max(0, limit - used)
    return remaining > 0, remaining


def org_enforce_campaign_iterations(
    session: Session, org_id: int, plan: str, requested: int
) -> tuple[bool, int]:
    """Org-level campaign quota check via MonthlyUsage aggregate.

    Returns (allowed, remaining).  Does NOT increment.
    """
    period = current_period_ym()
    _, used = org_total_usage(session, period, org_id)
    limit = plan_quotas(plan).campaign_iterations
    remaining = max(0, limit - used)
    return remaining >= requested, remaining


def bump_usage(
    session: Session,
    *,
    org_id: Optional[int],
    user_id: int,
    field: Literal["guard_scans", "campaigns_started"],
    amount: int = 1,
    plan: Optional[str] = None,
) -> None:
    """Upsert MonthlyUsage for (period, user_id) and add *amount* to *field*.

    Never raises — all errors are silently swallowed so a metering failure
    never aborts the caller's request.
    """
    from .models import MonthlyUsage

    try:
        period = current_period_ym()
        row = session.exec(
            select(MonthlyUsage)
            .where(MonthlyUsage.period_yyyymm == period)
            .where(MonthlyUsage.user_id == user_id)
        ).first()

        if row is None:
            row = MonthlyUsage(
                period_yyyymm=period,
                org_id=org_id,
                user_id=user_id,
                updated_at=datetime.utcnow(),
            )
            session.add(row)
            try:
                session.flush()
            except IntegrityError:
                # Concurrent insert — rollback and re-fetch.
                session.rollback()
                row = session.exec(
                    select(MonthlyUsage)
                    .where(MonthlyUsage.period_yyyymm == period)
                    .where(MonthlyUsage.user_id == user_id)
                ).first()
                if row is None:
                    return
        elif row.org_id is None and org_id is not None:
            # User was assigned to an org after this row was first created.
            row.org_id = org_id

        setattr(row, field, getattr(row, field) + amount)
        row.updated_at = datetime.utcnow()
        session.add(row)
        session.commit()

        # Phase 2.3 — threshold notifications (best-effort, only when plan provided)
        if plan is not None:
            try:
                check_thresholds_and_notify(
                    session,
                    period=period,
                    org_id=org_id,
                    user_id=user_id,
                    plan=plan,
                    guard_scans=row.guard_scans,
                    campaigns_started=row.campaigns_started,
                )
            except Exception:
                pass
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Phase E6 — Org-scoped monthly quota enforcement via OrgUsageMonth
# ---------------------------------------------------------------------------

#: Monthly limits per plan tier.  Campaigns = number of campaigns created
#: (not iterations).  Pro has a high cap rather than unlimited so the table
#: stays finite; adjust as needed.
def current_ym() -> str:
    """Return the current UTC month as 'YYYY-MM' (alias for current_period_ym)."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m")


def limits_for_plan(plan: str) -> Dict[str, int]:
    """Return {'guard_scans': N, 'campaigns': N} for *plan*.  -1 = unlimited."""
    from .plans import get_limits_for_plan as _gl, normalize_plan as _np
    lims = _gl(_np(plan))
    return {"guard_scans": lims.guard_scans_per_month, "campaigns": lims.campaigns_per_month}


def get_or_create_usage(session: Session, org_id: int, ym: str):
    """Fetch or create the OrgUsageMonth row for (org_id, ym).

    Handles concurrent inserts via IntegrityError retry.
    """
    from .models import OrgUsageMonth

    row = session.exec(
        select(OrgUsageMonth)
        .where(OrgUsageMonth.org_id == org_id)
        .where(OrgUsageMonth.ym == ym)
    ).first()
    if row is not None:
        return row

    row = OrgUsageMonth(org_id=org_id, ym=ym)
    session.add(row)
    try:
        session.commit()
        session.refresh(row)
    except IntegrityError:
        session.rollback()
        row = session.exec(
            select(OrgUsageMonth)
            .where(OrgUsageMonth.org_id == org_id)
            .where(OrgUsageMonth.ym == ym)
        ).first()
    if row is None:
        # Extremely rare: concurrent insert race where both writers lost; fail safe.
        raise HTTPException(
            status_code=503,
            detail={
                "code": "usage_unavailable",
                "message": "Usage record temporarily unavailable — please retry.",
            },
        )
    return row


def increment_guard(session: Session, org_id: int, plan: str, n: int = 1) -> None:
    """Check org guard-scan quota and increment by *n*.

    Raises HTTPException(402) when the monthly limit would be exceeded.
    Raises HTTPException(503) when the distributed lock cannot be acquired.
    Never called for public/anonymous requests (skip enforcement there).
    """
    from .locking import acquire_lock, release_lock

    lock_key = f"usage:org:{org_id}"
    owner = acquire_lock(session, lock_key)
    if owner is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "lock_unavailable",
                "message": "Service temporarily busy — please retry.",
            },
        )
    try:
        ym = current_ym()
        row = get_or_create_usage(session, org_id, ym)
        limit = limits_for_plan(plan)["guard_scans"]
        if limit != -1 and row.guard_scans + n > limit:
            try:
                from .audit_log import write_audit_log
                write_audit_log(
                    session,
                    action="limit.breach",
                    resource_type="quota",
                    resource_id=f"org:{org_id}",
                    org_id=org_id,
                    metadata={"quota": "guard_scans", "used": row.guard_scans,
                              "limit": limit, "plan": plan},
                )
            except Exception:
                pass
            raise HTTPException(
                status_code=402,
                detail={
                    "code": "guard_scan_limit",
                    "message": f"Monthly guard scan limit ({limit}) reached. Upgrade to expand quota.",
                    "remaining": 0,
                    "limit": limit,
                    "used": row.guard_scans,
                },
            )
        row.guard_scans += n
        row.updated_at = datetime.utcnow()
        session.add(row)
        session.commit()
    finally:
        release_lock(session, lock_key, owner)


def increment_campaign(session: Session, org_id: int, plan: str, n: int = 1) -> None:
    """Check org campaign quota and increment by *n*.

    Raises HTTPException(402) when the monthly limit would be exceeded.
    Raises HTTPException(503) when the distributed lock cannot be acquired.
    """
    from .locking import acquire_lock, release_lock

    lock_key = f"usage:org:{org_id}"
    owner = acquire_lock(session, lock_key)
    if owner is None:
        raise HTTPException(
            status_code=503,
            detail={
                "code": "lock_unavailable",
                "message": "Service temporarily busy — please retry.",
            },
        )
    try:
        ym = current_ym()
        row = get_or_create_usage(session, org_id, ym)
        limit = limits_for_plan(plan)["campaigns"]
        if limit != -1 and row.campaigns_created + n > limit:
            try:
                from .audit_log import write_audit_log
                write_audit_log(
                    session,
                    action="limit.breach",
                    resource_type="quota",
                    resource_id=f"org:{org_id}",
                    org_id=org_id,
                    metadata={"quota": "campaigns", "used": row.campaigns_created,
                              "limit": limit, "plan": plan},
                )
            except Exception:
                pass
            raise HTTPException(
                status_code=402,
                detail={
                    "code": "campaign_limit",
                    "message": f"Monthly campaign limit ({limit}) reached. Upgrade to expand quota.",
                    "remaining": 0,
                    "limit": limit,
                    "used": row.campaigns_created,
                },
            )
        row.campaigns_created += n
        row.updated_at = datetime.utcnow()
        session.add(row)
        session.commit()
    finally:
        release_lock(session, lock_key, owner)
