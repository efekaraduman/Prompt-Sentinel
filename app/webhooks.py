"""SIEM/SOAR webhook delivery with exponential-backoff retry (E1).

Architecture
------------
fire_guard_event() — called inside the hot path (guard scan, campaign run).
  Writes one WebhookDelivery row (status='pending', next_retry_at=now) and
  returns immediately.  Never blocks the calling request.

process_pending_deliveries() — called by worker.py every poll cycle.
  Claims all WebhookDelivery rows due for attempt, groups by org, sends
  (batch-compressed when ≥ BATCH_THRESHOLD events per org), handles backoff
  on failure, and moves exhausted rows to WebhookDeadLetter.

Backoff schedule (retry_count is the number of attempts already made):
  attempt 0 → now (first try, queued by fire_guard_event)
  attempt 1 → +30 s
  attempt 2 → +2 min
  attempt 3 → +10 min
  attempt 4 → +1 h
  attempt 5 → +6 h
  attempt 6 → dead_lettered (DEAD_AFTER = 6 attempts)

Batch compression
-----------------
When an org has ≥ BATCH_THRESHOLD pending deliveries due at the same time,
they are sent as a single POST with payload:
  {"batch": true, "count": N, "events": [...]}
The X-PromptSentinel-Signature covers the full batch body.
If the batch POST succeeds, all N rows are marked success.
If it fails, they all share the same retry_count increment.

Audit log
---------
write_audit_log() is called on:
  - successful delivery   → action='webhook.delivered'
  - dead letter           → action='webhook.dead_lettered'
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import text
from sqlmodel import Session, select

log = logging.getLogger(__name__)

_TIMEOUT = 5           # seconds per HTTP call
_DEAD_AFTER = 6        # number of attempts before dead-lettering
_BATCH_THRESHOLD = 3   # deliver as batch when org has ≥ this many due events

# Delay (seconds) before retry attempt N (index = retry_count after failure)
_RETRY_DELAYS: list[int] = [30, 120, 600, 3600, 21600]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _next_retry_at(retry_count: int) -> datetime:
    """Return the datetime when the next attempt should be made."""
    idx = min(retry_count, len(_RETRY_DELAYS) - 1)
    return _now() + timedelta(seconds=_RETRY_DELAYS[idx])


def sign_payload(secret: str, body_bytes: bytes) -> str:
    """Return hex HMAC-SHA256 of body_bytes using secret."""
    return hmac.new(secret.encode(), body_bytes, hashlib.sha256).hexdigest()


def _post(url: str, secret: str, json_body: dict[str, Any]) -> None:
    """POST json_body to url with HMAC signature header.  Raises on failure."""
    body = json.dumps(json_body, default=str).encode()
    sig = sign_payload(secret, body)
    headers = {
        "Content-Type": "application/json",
        "X-PromptSentinel-Signature": sig,
    }
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
        _ = resp.read()  # drain


# ---------------------------------------------------------------------------
# Enqueue (hot-path — called from guard/campaign code)
# ---------------------------------------------------------------------------

def send_org_security_event(
    session: Session,
    org_id: Optional[int],
    payload: dict[str, Any],
) -> None:
    """Public API alias for fire_guard_event.  Never raises, never blocks."""
    fire_guard_event(session, org_id, payload)


def fire_guard_event(
    session: Session,
    org_id: Optional[int],
    event: dict[str, Any],
) -> None:
    """Queue one webhook delivery for org_id.  Never raises, never blocks."""
    if org_id is None:
        return
    try:
        from .models import OrgWebhook, WebhookDelivery

        hook: OrgWebhook | None = session.exec(
            select(OrgWebhook).where(
                OrgWebhook.org_id == org_id,
                OrgWebhook.is_active == True,  # noqa: E712
            )
        ).first()

        if hook is None:
            return

        delivery = WebhookDelivery(
            org_id=org_id,
            event_json=json.dumps(event, default=str),
            status="pending",
            retry_count=0,
            next_retry_at=_now(),  # attempt immediately on next worker cycle
        )
        session.add(delivery)
        session.commit()
    except Exception as exc:
        log.debug("fire_guard_event enqueue error: %s", exc)


# ---------------------------------------------------------------------------
# Claim pending deliveries (worker — one batch per poll cycle)
# ---------------------------------------------------------------------------

def _claim_due(session: Session) -> list[int]:
    """Mark all pending rows whose next_retry_at ≤ now as 'processing'.

    Uses per-row CAS to be multi-worker safe.  Returns list of claimed IDs.
    """
    from .models import WebhookDelivery

    now_iso = _now().isoformat()

    candidates: list[int] = list(
        session.exec(
            select(WebhookDelivery.id)  # type: ignore[call-overload]
            .where(
                WebhookDelivery.status == "pending",
                WebhookDelivery.next_retry_at <= _now(),
            )
            .order_by(WebhookDelivery.created_at)
            .limit(200)
        ).all()
    )

    claimed: list[int] = []
    for row_id in candidates:
        affected = session.execute(
            text(
                "UPDATE webhookdelivery"
                " SET status = 'processing'"
                " WHERE id = :id AND status = 'pending'"
            ),
            {"id": row_id},
        ).rowcount
        session.commit()
        if affected:
            claimed.append(row_id)

    return claimed


# ---------------------------------------------------------------------------
# Process one delivery or batch
# ---------------------------------------------------------------------------

def _mark_success(session: Session, ids: list[int]) -> None:
    from .models import WebhookDelivery

    now = _now()
    for row_id in ids:
        session.execute(
            text(
                "UPDATE webhookdelivery"
                " SET status = 'success', delivered_at = :ts"
                " WHERE id = :id"
            ),
            {"id": row_id, "ts": now.isoformat()},
        )
    session.commit()


def _mark_retry_or_dead(session: Session, ids: list[int], error: str) -> None:
    """Increment retry_count.  If exhausted, move to dead letter + audit."""
    from .models import WebhookDelivery, WebhookDeadLetter
    from .audit_log import write_audit_log

    for row_id in ids:
        row: WebhookDelivery | None = session.get(WebhookDelivery, row_id)
        if row is None:
            continue

        new_count = row.retry_count + 1
        if new_count >= _DEAD_AFTER:
            # Move to dead letter
            dead = WebhookDeadLetter(
                org_id=row.org_id,
                event_json=row.event_json,
                error_summary=error[:800],
                retry_count=new_count,
            )
            session.add(dead)
            session.execute(
                text("UPDATE webhookdelivery SET status = 'dead_lettered' WHERE id = :id"),
                {"id": row_id},
            )
            session.commit()
            write_audit_log(
                session,
                action="webhook.dead_lettered",
                resource_type="webhook",
                resource_id=str(row_id),
                org_id=row.org_id,
                metadata={"retry_count": new_count, "error": error[:300]},
            )
            log.warning(
                "E1: webhook delivery dead-lettered org=%d delivery_id=%d retries=%d",
                row.org_id, row_id, new_count,
            )
        else:
            # Schedule next retry
            next_at = _next_retry_at(new_count)
            session.execute(
                text(
                    "UPDATE webhookdelivery"
                    " SET status = 'pending', retry_count = :rc,"
                    " next_retry_at = :nra, last_error = :err"
                    " WHERE id = :id"
                ),
                {
                    "id": row_id,
                    "rc": new_count,
                    "nra": next_at.isoformat(),
                    "err": error[:400],
                },
            )
            session.commit()
            log.info(
                "E1: webhook retry scheduled org=%d delivery_id=%d attempt=%d next=%s",
                row.org_id, row_id, new_count, next_at.isoformat(),
            )


def _deliver_ids(session: Session, org_id: int, ids: list[int]) -> None:
    """Attempt delivery for a set of delivery IDs belonging to one org."""
    from .models import OrgWebhook, WebhookDelivery
    from .audit_log import write_audit_log

    hook: OrgWebhook | None = session.exec(
        select(OrgWebhook).where(
            OrgWebhook.org_id == org_id,
            OrgWebhook.is_active == True,  # noqa: E712
        )
    ).first()

    if hook is None:
        # Webhook was removed or deactivated — silently dead-letter all
        _mark_retry_or_dead(session, ids, "Webhook not found or deactivated")
        return

    # Load event payloads
    rows: list[WebhookDelivery] = []
    for row_id in ids:
        row = session.get(WebhookDelivery, row_id)
        if row is not None:
            rows.append(row)

    if not rows:
        return

    # Build payload — batch if enough events
    if len(rows) >= _BATCH_THRESHOLD:
        events = [json.loads(r.event_json) for r in rows]
        payload: dict[str, Any] = {"batch": True, "count": len(events), "events": events}
    else:
        # Single events sent individually
        for row in rows:
            try:
                _post(hook.url, hook.secret, json.loads(row.event_json))
                _mark_success(session, [row.id])  # type: ignore[list-item]
                hook.last_sent_at = _now()
                hook.last_error = None
                session.add(hook)
                session.commit()
                write_audit_log(
                    session,
                    action="webhook.delivered",
                    resource_type="webhook",
                    resource_id=str(row.id),
                    org_id=org_id,
                    metadata={"retry_count": row.retry_count},
                )
            except Exception as exc:
                err = str(exc)[:400]
                hook.last_error = err
                session.add(hook)
                session.commit()
                _mark_retry_or_dead(session, [row.id], err)  # type: ignore[list-item]
        return

    # Batch send
    try:
        _post(hook.url, hook.secret, payload)
        _mark_success(session, ids)
        hook.last_sent_at = _now()
        hook.last_error = None
        session.add(hook)
        session.commit()
        write_audit_log(
            session,
            action="webhook.delivered",
            resource_type="webhook",
            resource_id=f"batch:{org_id}",
            org_id=org_id,
            metadata={"batch_size": len(ids), "delivery_ids": ids},
        )
        log.info("E1: batch webhook delivered org=%d count=%d", org_id, len(ids))
    except Exception as exc:
        err = str(exc)[:400]
        hook.last_error = err
        session.add(hook)
        session.commit()
        _mark_retry_or_dead(session, ids, err)


# ---------------------------------------------------------------------------
# Main entry for worker
# ---------------------------------------------------------------------------

def process_pending_deliveries(session: Session) -> int:
    """Claim due deliveries, group by org, attempt delivery.

    Returns the number of delivery rows processed (attempted).
    Called by worker.py every poll cycle.
    """
    claimed_ids = _claim_due(session)
    if not claimed_ids:
        return 0

    # Group by org_id
    from .models import WebhookDelivery

    groups: dict[int, list[int]] = {}
    for row_id in claimed_ids:
        row = session.get(WebhookDelivery, row_id)
        if row is not None:
            groups.setdefault(row.org_id, []).append(row_id)

    for org_id, ids in groups.items():
        try:
            _deliver_ids(session, org_id, ids)
        except Exception as exc:
            log.exception("E1: delivery error org=%d: %s", org_id, exc)

    return len(claimed_ids)
