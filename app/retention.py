"""Data retention enforcement — Phase ENTERPRISE.

Deletes GuardScan, GuardScanRecord, AuditLog, and AuditEvent rows older than
an org's configured ``retention_days`` window.

Called by worker.py every ``_CLEANUP_EVERY`` poll cycles.  Safe to call
frequently — orgs without ``retention_days`` set are skipped (no-op).

Minimum enforced retention: 7 days (RETENTION_MIN_DAYS) to prevent
accidental mass-delete from misconfigured small values.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlmodel import Session, select

logger = logging.getLogger(__name__)

# Guard rail: never purge data less than 7 days old regardless of setting.
RETENTION_MIN_DAYS: int = 7

# Tables scoped by org_id that participate in retention cleanup.
_RETENTION_TABLES: list[str] = [
    "guardscan",
    "guardscanrecord",
    "guardscanreplaystore",  # ADVANCED — Replay Testing (full-payload store)
    "auditlog",
    "auditevent",
]


def run_retention_cleanup(session: Session) -> dict[str, int]:
    """Delete rows older than each org's ``retention_days`` setting.

    Iterates all orgs with a non-null ``retention_days``, computes the
    per-org cutoff timestamp, and issues DELETE statements per table.

    Returns a totals dict mapping table name → rows deleted across all orgs.
    Commits once after all deletes.
    """
    from .models import Organization

    orgs = session.exec(
        select(Organization).where(Organization.retention_days.is_not(None))  # type: ignore[union-attr]
    ).all()

    totals: dict[str, int] = {t: 0 for t in _RETENTION_TABLES}

    for org in orgs:
        days = org.retention_days
        if days is None or days < RETENTION_MIN_DAYS:
            continue

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_iso = cutoff.isoformat()

        for table in _RETENTION_TABLES:
            result = session.execute(
                text(
                    f"DELETE FROM {table}"  # noqa: S608 — table names are a controlled constant list
                    " WHERE org_id = :org_id AND created_at < :cutoff"
                ),
                {"org_id": org.id, "cutoff": cutoff_iso},
            )
            deleted = result.rowcount
            totals[table] += deleted
            if deleted:
                logger.info(
                    "retention: org=%d table=%s deleted=%d cutoff=%s",
                    org.id, table, deleted, cutoff.date(),
                )

    session.commit()
    return totals
