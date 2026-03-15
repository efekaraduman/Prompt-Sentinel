"""Phase 3.12.A — Deep Anomaly Detection Engine.

Stateless helpers; no DB models defined here.
"""
from __future__ import annotations

import bisect
import json
import math
from datetime import date, datetime, timedelta, timezone
from typing import Optional

from sqlmodel import Session, select

from .schemas import AnomalyItem

# ── thresholds ────────────────────────────────────────────────────────────────
_WARN = 2.5
_CRIT = 4.0
_BASELINE_DAYS = 14   # rolling window used to compute mean/std


# ── series builder ────────────────────────────────────────────────────────────

def compute_daily_series(
    session: Session,
    org_id: Optional[int],
    metric: str,
    days: int,
) -> dict[str, float]:
    """Return {YYYY-MM-DD: value} for the requested metric over *days* days.

    metric options:
        "scans"           – total scans per day
        "blocks"          – total blocked scans per day
        "block_rate"      – blocks / scans (0 when no scans)
        "category:<name>" – scans containing that category
        "cluster:<id>"    – scans whose signature_hash appears in cluster <id>
    """
    from .models import GuardScanRecord, ThreatClusterMember  # local import avoids circular

    total_days = days + _BASELINE_DAYS
    cutoff = datetime.now(timezone.utc) - timedelta(days=total_days)

    q = select(GuardScanRecord).where(GuardScanRecord.created_at >= cutoff)
    if org_id is not None:
        q = q.where(GuardScanRecord.org_id == org_id)
    rows = session.exec(q).all()

    today = datetime.now(timezone.utc).date()
    all_dates = [(today - timedelta(days=i)).isoformat() for i in range(total_days - 1, -1, -1)]

    # Pre-build cluster hash set if needed
    cluster_hashes: set[str] | None = None
    if metric.startswith("cluster:"):
        cluster_id = int(metric.split(":", 1)[1])
        members = session.exec(
            select(ThreatClusterMember).where(ThreatClusterMember.cluster_id == cluster_id)
        ).all()
        cluster_hashes = {m.signature_hash for m in members}

    cat_name: str | None = metric.split(":", 1)[1] if metric.startswith("category:") else None

    daily_scans: dict[str, int] = {d: 0 for d in all_dates}
    daily_blocks: dict[str, int] = {d: 0 for d in all_dates}
    daily_cat: dict[str, int] = {d: 0 for d in all_dates}
    daily_cluster: dict[str, int] = {d: 0 for d in all_dates}

    for r in rows:
        day = str(r.created_at)[:10]
        if day not in daily_scans:
            continue
        daily_scans[day] += 1
        if r.blocked:
            daily_blocks[day] += 1
        if cat_name:
            cats = json.loads(r.categories_json or "[]")
            if cat_name in cats:
                daily_cat[day] += 1
        if cluster_hashes is not None and r.signature_hash in cluster_hashes:
            daily_cluster[day] += 1

    series: dict[str, float] = {}
    for d in all_dates:
        if metric == "scans":
            series[d] = float(daily_scans[d])
        elif metric == "blocks":
            series[d] = float(daily_blocks[d])
        elif metric == "block_rate":
            series[d] = daily_blocks[d] / daily_scans[d] if daily_scans[d] > 0 else 0.0
        elif cat_name is not None:
            series[d] = float(daily_cat[d])
        elif cluster_hashes is not None:
            series[d] = float(daily_cluster[d])
        else:
            series[d] = 0.0

    return series


# ── stats helpers ─────────────────────────────────────────────────────────────

def rolling_stats(
    series: dict[str, float],
    target_date: str,
) -> tuple[float, float]:
    """Return (mean, std) of the _BASELINE_DAYS days *before* target_date."""
    d = date.fromisoformat(target_date)
    window = [
        series.get((d - timedelta(days=i)).isoformat(), 0.0)
        for i in range(1, _BASELINE_DAYS + 1)
    ]
    mean = sum(window) / len(window)
    variance = sum((v - mean) ** 2 for v in window) / len(window)
    std = math.sqrt(variance)
    return mean, std


# ── anomaly detector ──────────────────────────────────────────────────────────

def detect_anomalies(
    series: dict[str, float],
    metric: str,
    window_days: int,
) -> list[AnomalyItem]:
    """Scan the last *window_days* days and return AnomalyItem for each anomaly."""
    today = datetime.now(timezone.utc).date()
    results: list[AnomalyItem] = []

    for i in range(window_days - 1, -1, -1):
        d = (today - timedelta(days=i)).isoformat()
        value = series.get(d, 0.0)
        mean, std = rolling_stats(series, d)

        if std == 0:
            z = 0.0
        else:
            z = (value - mean) / std

        if z >= _CRIT:
            severity = "critical"
        elif z >= _WARN:
            severity = "warning"
        else:
            continue  # normal — skip

        results.append(AnomalyItem(
            metric=metric,
            date=d,
            value=round(value, 4),
            baseline_mean=round(mean, 4),
            baseline_std=round(std, 4),
            z_score=round(z, 4),
            severity=severity,
        ))

    return results


# ── top categories helper ─────────────────────────────────────────────────────

def top_categories_in_window(
    session: Session,
    org_id: Optional[int],
    days: int,
    top_n: int = 5,
) -> list[str]:
    """Return the top_n category names by scan count in the last *days* days."""
    from .models import GuardScanRecord

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    q = select(GuardScanRecord).where(GuardScanRecord.created_at >= cutoff)
    if org_id is not None:
        q = q.where(GuardScanRecord.org_id == org_id)
    rows = session.exec(q).all()

    counts: dict[str, int] = {}
    for r in rows:
        for cat in json.loads(r.categories_json or "[]"):
            counts[cat] = counts.get(cat, 0) + 1

    return [k for k, _ in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]]


# ── Phase 3.12.C — Risk baseline ──────────────────────────────────────────────

_RISK_BASELINE_DAYS = 30


def compute_risk_baseline(
    session: Session,
    org_id: Optional[int],
) -> tuple[float, float, int]:
    """Return (mean, std, n_samples) of risk_score over last 30 days for the org.

    std is clamped to minimum 1.0 to avoid division by zero.
    PHASE 2.24: now returns n_samples so callers can apply a minimum-data guard.
    """
    from .models import GuardScanRecord

    cutoff = datetime.now(timezone.utc) - timedelta(days=_RISK_BASELINE_DAYS)
    q = select(GuardScanRecord).where(GuardScanRecord.created_at >= cutoff)
    if org_id is not None:
        q = q.where(GuardScanRecord.org_id == org_id)
    rows = session.exec(q).all()

    if not rows:
        return 0.0, 1.0, 0

    scores = [float(r.risk_score) for r in rows]
    mean = sum(scores) / len(scores)
    variance = sum((s - mean) ** 2 for s in scores) / len(scores)
    std = max(math.sqrt(variance), 1.0)
    return mean, std, len(rows)


# ── PHASE 2.24 — normalize_risk ───────────────────────────────────────────────

_MIN_BASELINE_SAMPLES = 3   # need at least 3 prior scans for a meaningful z-score


def normalize_risk(
    current: float,
    mean: float,
    std: float,
    n_samples: int,
    min_samples: int = _MIN_BASELINE_SAMPLES,
) -> float:
    """Return z-score of current risk vs rolling 30-day baseline.

    Returns 0.0 when n_samples < min_samples (insufficient history).
    std is expected to already be clamped to ≥ 1.0 by compute_risk_baseline.
    """
    if n_samples < min_samples:
        return 0.0
    return round((current - mean) / std, 4)


# ── Risk Calibration ─────────────────────────────────────────────────────────
# Phase ADVANCED — rolling percentile calibration for time-comparable risk scores.
#
# Unlike the z-score (normalized_risk), the calibrated score is always 0–100 and
# answers: "Where does this scan rank relative to our own recent history?"
# This means:
#   - calibrated_risk = 50 → median threat level for this org this month
#   - calibrated_risk = 95 → worse than 95 % of scans in the rolling window
# When threat levels rise org-wide, a raw score of 70 that used to be "high"
# might now be "average" (calibrated_risk ≈ 50), making trends visible.

_CALIBRATION_DAYS = 30


def compute_risk_percentiles(
    session: Session,
    org_id: Optional[int],
    window_days: int = _CALIBRATION_DAYS,
) -> list[float]:
    """Return a sorted list of raw risk_score values from the rolling window.

    The list is used by calibrate_risk_score() to compute the percentile rank
    of the current scan's score within recent org history.

    Returns an empty list on cold start (no history yet for this org).
    The current scan is intentionally excluded because this is called before
    save_scan_record() writes the record to the database.
    """
    from .models import GuardScanRecord

    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    q = select(GuardScanRecord).where(GuardScanRecord.created_at >= cutoff)
    if org_id is not None:
        q = q.where(GuardScanRecord.org_id == org_id)
    rows = session.exec(q).all()
    return sorted(float(r.risk_score) for r in rows if r.risk_score is not None)


def calibrate_risk_score(raw_score: int, sorted_scores: list[float]) -> int:
    """Convert a raw risk score to a calibrated score (0–100) via percentile rank.

    The calibrated score represents where *raw_score* falls within the empirical
    distribution of historical scores in the rolling window — making scores
    comparable across time even as the absolute threat landscape shifts.

    Percentile semantics:
      0   → score is at or below the historical minimum
      50  → score equals the historical median
      100 → score exceeds the historical maximum

    Algorithm:
      Uses the midpoint method (Cleveland 1994) to handle ties without bias:
        percentile = (count_below + 0.5 × count_equal) / n × 100

      The sorted list allows O(log n) lookups via bisect, keeping calibration
      fast even for large rolling windows.

    Fallback:
      Returns *raw_score* unchanged when no history is available (cold start).
      This preserves the intuitive 0–100 interpretation on the first scan.
    """
    if not sorted_scores:
        return raw_score   # cold start: no history, return raw score as-is

    n = len(sorted_scores)
    v = float(raw_score)

    # bisect_left  → index of first element >= v  == count of elements strictly < v
    # bisect_right → index after last element == v == count of elements <= v
    below = bisect.bisect_left(sorted_scores, v)
    above = bisect.bisect_right(sorted_scores, v)
    equal = above - below

    # Midpoint percentile rank: avoids always rounding up or down for ties
    percentile = (below + 0.5 * equal) / n
    return min(100, round(percentile * 100))
