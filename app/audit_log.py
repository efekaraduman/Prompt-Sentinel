"""Structured audit-trail writer — appends rows to the AuditLog table.

Use ``write_audit_log`` anywhere in the codebase to record a security-
relevant action.  The function never raises so callers don't need try/except.

Action / resource_type vocabulary
----------------------------------
action                resource_type      when
-----------           ---------------    --------------------------------------
plan.changed          user               user plan upgraded / downgraded
plan.changed          organization       org plan upgraded / downgraded
webhook.received      webhook            Stripe event successfully dispatched
webhook.delivered     webhook            SIEM webhook delivery succeeded (E1)
webhook.dead_lettered webhook            SIEM webhook exhausted retries (E1)
member.added          org_member         user joined an org
member.updated        org_member         org member role changed
user.org_assigned     user               user's org_id / default_org_id set
limit.breach          quota              monthly quota exceeded (402 raised)
policy.override       guard_scan         caller supplied non-default policy fields
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from sqlmodel import Session

logger = logging.getLogger("promptsentinel.audit_log")


def write_audit_log(
    session: Session,
    *,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    org_id: Optional[int] = None,
    user_id: Optional[int] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Insert one AuditLog row.  Never raises — audit must not abort requests."""
    try:
        from .models import AuditLog

        try:
            meta_str = json.dumps(metadata or {}, default=str)
        except Exception:
            meta_str = "{}"

        row = AuditLog(
            org_id=org_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            metadata_json=meta_str,
        )
        session.add(row)
        session.commit()
    except Exception as exc:
        logger.warning("write_audit_log failed action=%s: %s", action, exc)
