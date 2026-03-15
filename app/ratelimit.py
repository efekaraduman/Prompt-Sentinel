"""Org-scoped DB-backed sliding-window rate limiter.

Replaces the old in-memory / Redis approach with a single SQLite table so the
limit is enforced consistently across multiple workers without Redis.

Bucket mapping (stored in RateLimitEvent.org_id):
  org user            → org_id           (positive; shared across all org members)
  non-org auth user   → -user_id         (negative; individual limit)
  anonymous           → -(1_000_000 + ip_hash % 1_000_000)  (IP-scoped)

Per-plan limits per 60-second window (requests):
  pro:    300
  free:    60
  public:  30

Probabilistic cleanup (1 in CLEANUP_PROB requests) deletes rows older than
5 minutes so the table stays small without a dedicated cron job.

Exported for main.py compat:
  MULTI_WORKER, MULTI_WORKER_REASON  — always False/"" (DB is multi-worker safe)
  RateLimitError
  require_rate_limit
  require_rate_limit_campaigns
  require_rate_limit_guard
"""
from __future__ import annotations

import logging
import os
import random
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, Header, Request, Response
from sqlalchemy import delete as sa_delete, func
from sqlmodel import Session, select

from .config import get_settings
from .db import get_session

logger = logging.getLogger("promptsentinel.ratelimit")

# ---------------------------------------------------------------------------
# Optional Redis client (enabled when REDIS_URL is set)
# ---------------------------------------------------------------------------

try:
    import redis as _redis_lib

    def _init_redis():  # type: ignore[return]
        url = get_settings().get("redis_url", "")
        if not url:
            return None
        try:
            client = _redis_lib.from_url(url, socket_connect_timeout=2, socket_timeout=2)
            client.ping()
            return client
        except Exception as exc:
            logger.warning("Redis unavailable (%s); using DB rate limiter.", exc)
            return None

except ImportError:
    def _init_redis():
        return None

# Initialised once at import time; None when REDIS_URL is unset or unreachable.
_redis = _init_redis()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WINDOW_SECONDS = 60
CLEANUP_PROB = 50          # run cleanup on 1 in N requests (probabilistic)
CLEANUP_AGE_MINUTES = 5    # delete rows older than this

PLAN_LIMITS: dict[str, int] = {
    "pro":    300,
    "free":    60,
    "public":  30,
}

# ---------------------------------------------------------------------------
# Compat exports (main.py health endpoint reads these)
# ---------------------------------------------------------------------------

MULTI_WORKER: bool = False        # DB-backed: safe for any number of workers
MULTI_WORKER_REASON: str = ""


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------

class RateLimitError(Exception):
    def __init__(self, retry_after: int, limit: int) -> None:
        self.retry_after = retry_after
        self.limit = limit


# ---------------------------------------------------------------------------
# Bucket resolution
# ---------------------------------------------------------------------------

def _bucket_id(request: Request) -> int:
    """Map a request to a rate-limit bucket integer.

    Reads identity from request.state (populated by identity_middleware).
    Falls back gracefully when state is absent.
    """
    org_id: Optional[int] = getattr(request.state, "org_id", None)
    if org_id is not None:
        return org_id                              # org-scoped (positive)

    user_id: Optional[int] = getattr(request.state, "user_id", None)
    if user_id is not None:
        return -user_id                            # individual user, no org

    # Anonymous: derive from client IP to avoid a single global bucket
    ip = (request.client.host if request.client else "") or "0.0.0.0"
    return -(1_000_000 + abs(hash(ip)) % 1_000_000)


# ---------------------------------------------------------------------------
# Core DB check
# ---------------------------------------------------------------------------

def _check_rate_limit_redis(bucket_id: int, endpoint: str, limit_per_min: int) -> int:
    """Fixed-window rate check via Redis.

    Key: rl:{bucket_id}:{endpoint}:{window_ts}  (one bucket per 60-second slot)
    Returns remaining count.  Raises RateLimitError when over limit.
    """
    now = datetime.now(timezone.utc)
    window_ts = int(now.timestamp()) // WINDOW_SECONDS
    key = f"rl:{bucket_id}:{endpoint}:{window_ts}"

    count = _redis.incr(key)  # type: ignore[union-attr]
    if count == 1:
        # First hit in this window — set expiry with a small buffer
        _redis.expire(key, WINDOW_SECONDS + 10)  # type: ignore[union-attr]

    if count > limit_per_min:
        ttl = _redis.ttl(key) or WINDOW_SECONDS  # type: ignore[union-attr]
        raise RateLimitError(retry_after=max(1, ttl), limit=limit_per_min)

    return max(0, limit_per_min - count)


def check_rate_limit(
    session: Session,
    bucket_id: int,
    endpoint: str,
    limit_per_min: int,
) -> int:
    """Sliding-window rate check against the DB.

    Counts existing RateLimitEvent rows for (bucket_id, endpoint) within the
    last WINDOW_SECONDS seconds.  If at or above *limit_per_min*, raises
    RateLimitError.  Otherwise inserts a new event row and commits it.

    Returns the number of remaining requests after this one is counted.
    If REDIS_URL is configured, delegates to Redis for the counter instead.
    """
    # Redis fast-path — avoids DB writes entirely when available
    if _redis is not None:
        try:
            return _check_rate_limit_redis(bucket_id, endpoint, limit_per_min)
        except RateLimitError:
            raise
        except Exception as exc:
            logger.warning("Redis rate-limit error (%s); falling back to DB.", exc)
            # fall through to DB path

    from .models import RateLimitEvent

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=WINDOW_SECONDS)

    count: int = session.execute(
        select(func.count(RateLimitEvent.id)).where(
            RateLimitEvent.org_id == bucket_id,
            RateLimitEvent.endpoint == endpoint,
            RateLimitEvent.created_at >= window_start,
        )
    ).scalar_one()

    if count > limit_per_min:
        raise RateLimitError(retry_after=WINDOW_SECONDS, limit=limit_per_min)

    session.add(RateLimitEvent(org_id=bucket_id, endpoint=endpoint, created_at=now))
    try:
        session.commit()
    except Exception as exc:
        logger.warning("Rate limit event insert failed (%s); continuing.", exc)
        try:
            session.rollback()
        except Exception:
            pass

    # Probabilistic housekeeping — do not let it abort the request
    if random.randint(1, CLEANUP_PROB) == 1:
        try:
            cleanup_old_events(session)
        except Exception:
            pass

    return max(0, limit_per_min - count - 1)


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def cleanup_old_events(session: Session) -> None:
    """Delete RateLimitEvent rows older than CLEANUP_AGE_MINUTES.

    Called probabilistically from check_rate_limit; safe to call at any time.
    """
    from .models import RateLimitEvent

    cutoff = datetime.now(timezone.utc) - timedelta(minutes=CLEANUP_AGE_MINUTES)
    session.execute(
        sa_delete(RateLimitEvent).where(RateLimitEvent.created_at < cutoff)
    )
    session.commit()


# ---------------------------------------------------------------------------
# FastAPI dependency factory
# ---------------------------------------------------------------------------

def _make_dep(endpoint: str):
    """Return a FastAPI dependency that enforces rate limiting for *endpoint*.

    The limit is taken from PLAN_LIMITS keyed by request.state.user_plan
    (set by identity_middleware).  Failures are non-fatal — a DB error never
    blocks a legitimate request.
    """

    def dep(
        request: Request,
        response: Response,
        session: Session = Depends(get_session),
    ) -> None:
        plan: str = getattr(request.state, "user_plan", "public")
        limit = PLAN_LIMITS.get(plan, PLAN_LIMITS["public"])
        bucket = _bucket_id(request)

        try:
            remaining = check_rate_limit(session, bucket, endpoint, limit)
        except RateLimitError:
            raise                  # propagate → 429 handler in main.py
        except Exception as exc:
            logger.warning("Rate limit check error (%s); skipping.", exc)
            return

        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(remaining)

    dep.__name__ = f"require_rate_limit_{endpoint}"
    return dep


# ---------------------------------------------------------------------------
# Exported dependencies (drop-in replacements for old in-memory deps)
# ---------------------------------------------------------------------------

require_rate_limit           = _make_dep("general")
require_rate_limit_campaigns = _make_dep("campaigns")
require_rate_limit_guard     = _make_dep("guard")
