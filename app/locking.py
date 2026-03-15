"""DB-backed distributed locking via the DistributedLock table.

acquire_lock() tries to INSERT a lock row for *key*.  If the key is already
held (row exists and not expired) the INSERT fails with IntegrityError; the
call retries up to *max_retries* times with small linear back-off.

Stale locks (expires_at < now) are evicted before each INSERT attempt so
crashed workers never permanently block a key.

release_lock() deletes the row.  It is safe to call with a mismatched owner
or after the lock has already expired — it simply no-ops.
"""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

logger = logging.getLogger(__name__)

_DEFAULT_TTL: int = 10          # seconds a lock is held before considered stale
_DEFAULT_RETRIES: int = 3       # max acquire attempts (including the first)
_RETRY_BASE_DELAY: float = 0.05 # seconds; multiplied by (attempt + 1) for linear back-off


def _owner_token() -> str:
    """Unique token per acquire call — PID + object-id so it survives forks."""
    return f"{os.getpid()}-{id(object())}"


def acquire_lock(
    session: Session,
    key: str,
    ttl_seconds: int = _DEFAULT_TTL,
    max_retries: int = _DEFAULT_RETRIES,
) -> Optional[str]:
    """Try to acquire *key*.

    Returns the owner token string on success, or ``None`` after exhausting
    *max_retries* attempts.

    The caller MUST call ``release_lock(session, key, owner)`` when done,
    ideally inside a ``finally`` block.
    """
    from .models import DistributedLock

    owner = _owner_token()

    for attempt in range(max_retries):
        now = datetime.now(timezone.utc)

        # ── 1. Evict stale lock from a previous crashed holder ───────────────
        try:
            expired = session.exec(
                select(DistributedLock).where(
                    DistributedLock.key == key,
                    DistributedLock.expires_at < now,
                )
            ).first()
            if expired is not None:
                session.delete(expired)
                session.commit()
        except Exception:
            try:
                session.rollback()
            except Exception:
                pass

        # ── 2. Attempt INSERT ────────────────────────────────────────────────
        lock_row = DistributedLock(
            key=key,
            owner=owner,
            expires_at=now + timedelta(seconds=ttl_seconds),
        )
        session.add(lock_row)
        try:
            session.commit()
            return owner          # acquired
        except IntegrityError:
            # Another holder owns the lock; roll back and maybe retry.
            try:
                session.rollback()
            except Exception:
                pass

        if attempt < max_retries - 1:
            time.sleep(_RETRY_BASE_DELAY * (attempt + 1))

    logger.warning(
        "acquire_lock: could not acquire %r after %d attempt(s)", key, max_retries
    )
    return None


def release_lock(
    session: Session,
    key: str,
    owner: Optional[str] = None,
) -> None:
    """Delete the lock row for *key*.

    If *owner* is provided only the matching row is deleted (prevents a
    late-running worker from releasing a lock it no longer owns).
    Never raises.
    """
    from .models import DistributedLock

    try:
        q = select(DistributedLock).where(DistributedLock.key == key)
        if owner is not None:
            q = q.where(DistributedLock.owner == owner)
        row = session.exec(q).first()
        if row is not None:
            session.delete(row)
            session.commit()
    except Exception:
        try:
            session.rollback()
        except Exception:
            pass
