"""Stripe billing helpers — checkout session creation and webhook handling."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

try:
    import stripe
    _STRIPE_AVAILABLE = True
except ImportError:
    stripe = None  # type: ignore[assignment]
    _STRIPE_AVAILABLE = False

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session, select

from .config import app_url as _app_url
from .db import engine
from .models import Organization, StripeEvent, User

logger = logging.getLogger("promptsentinel.billing")

_MISSING = "Billing not configured"


class StripeMissingError(Exception):
    """Raised when the stripe package is not installed."""


def _require_stripe() -> None:
    if not _STRIPE_AVAILABLE:
        raise StripeMissingError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _stripe_env() -> tuple[str, str]:
    """Return (secret_key, price_id) or raise 503 billing_unavailable."""
    secret_key = os.environ.get("STRIPE_SECRET_KEY", "")
    price_id = os.environ.get("STRIPE_PRICE_ID_PRO", "")
    if not all([secret_key, price_id]):
        raise HTTPException(
            status_code=503,
            detail={"type": "billing_unavailable", "message": "Billing is not configured on this server.", "code": "stripe_missing_config"},
        )
    return secret_key, price_id


def _checkout_urls() -> tuple[str, str]:
    """Return (success_url, cancel_url) derived from the configured app URL."""
    base = _app_url()
    return (
        f"{base}/billing/success?billing=success",
        f"{base}/billing/cancel?billing=cancel",
    )


def _ensure_org_customer(org: Organization, initiating_user: User, db: Session) -> str:
    """Return org.stripe_customer_id, creating a Stripe customer if needed."""
    if not org.stripe_customer_id:
        customer = stripe.Customer.create(
            email=initiating_user.email,
            name=org.name,
            metadata={"org_id": str(org.id), "user_id": str(initiating_user.id)},
        )
        org.stripe_customer_id = customer.id
        db.add(org)
        db.commit()
    return org.stripe_customer_id  # type: ignore[return-value]


def _ensure_user_customer(user: User, db: Session) -> str:
    """Return user.stripe_customer_id, creating a Stripe customer if needed."""
    if not user.stripe_customer_id:
        customer = stripe.Customer.create(
            email=user.email,
            metadata={"user_id": str(user.id)},
        )
        user.stripe_customer_id = customer.id
        db.add(user)
        db.commit()
    return user.stripe_customer_id  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Checkout
# ---------------------------------------------------------------------------

def _effective_plan(user: User, db: Session) -> str:
    """Return the highest plan applicable to the user (own or org-inherited)."""
    if user.plan == "pro":
        return "pro"
    if user.org_id is not None:
        org = db.get(Organization, user.org_id)
        if org is not None and org.plan == "pro":
            return "pro"
    return user.plan


def create_checkout_url(user: User, session: Session) -> str:
    """Create (or reuse) a Stripe customer and return a Checkout session URL."""
    _require_stripe()
    if _effective_plan(user, session) == "pro":
        raise HTTPException(
            status_code=409,
            detail={"type": "already_subscribed", "message": "Your account already has an active Pro subscription.", "code": "already_pro"},
        )
    secret_key, price_id = _stripe_env()
    success_url, cancel_url = _checkout_urls()
    stripe.api_key = secret_key

    meta: dict = {"user_id": str(user.id)}
    if user.org_id is not None:
        org = session.get(Organization, user.org_id)
        if org is not None:
            customer_id = _ensure_org_customer(org, user, session)
            meta["org_id"] = str(org.id)
        else:
            customer_id = _ensure_user_customer(user, session)
    else:
        customer_id = _ensure_user_customer(user, session)

    checkout = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        client_reference_id=str(user.id),
        metadata=meta,
    )
    return checkout.url


# ---------------------------------------------------------------------------
# Webhook helpers
# ---------------------------------------------------------------------------

def _set_user_plan(
    user: User,
    plan: str,
    db: Session,
    *,
    sub_id: str | None = None,
    customer_id: str | None = None,
    period_end: int | None = None,
) -> None:
    old_plan = user.plan
    user.plan = plan
    if sub_id is not None:
        user.stripe_subscription_id = sub_id
    if customer_id is not None:
        user.stripe_customer_id = customer_id
    if period_end is not None:
        user.stripe_current_period_end = datetime.fromtimestamp(period_end, tz=timezone.utc)
    db.add(user)
    db.commit()
    # Audit: plan change
    try:
        from .audit_log import write_audit_log
        write_audit_log(
            db,
            action="plan.changed",
            resource_type="user",
            resource_id=str(user.id),
            org_id=user.org_id,
            user_id=user.id,
            metadata={"old_plan": old_plan, "new_plan": plan, "sub_id": sub_id},
        )
    except Exception:
        pass


def _set_org_plan(
    org: Organization,
    plan: str,
    db: Session,
    *,
    sub_id: str | None = None,
    customer_id: str | None = None,
) -> None:
    old_plan = org.plan
    org.plan = plan
    if sub_id is not None:
        org.stripe_subscription_id = sub_id
    if customer_id is not None:
        org.stripe_customer_id = customer_id
    db.add(org)
    db.commit()
    # Audit: plan change
    try:
        from .audit_log import write_audit_log
        write_audit_log(
            db,
            action="plan.changed",
            resource_type="organization",
            resource_id=str(org.id),
            org_id=org.id,
            metadata={"old_plan": old_plan, "new_plan": plan, "sub_id": sub_id},
        )
    except Exception:
        pass


def plan_from_subscription_status(status: str) -> str:
    """Map any Stripe subscription status to internal plan string.

    active / trialing           → "pro"
    everything else (canceled, unpaid, incomplete_expired, paused,
                     past_due, incomplete, …) → "free"
    """
    if status in {"active", "trialing"}:
        return "pro"
    return "free"


def _sub_plan(status: str) -> str:
    """Internal alias kept for call-site compatibility."""
    return plan_from_subscription_status(status)


def _find_billing_target(
    customer_id: str,
    sub_id: str,
    metadata: dict,
    db: Session,
) -> tuple[Organization | None, User | None]:
    """Resolve the billing target from a Stripe event.

    Resolution order:
    a) Organization by stripe_customer_id     — org-scoped billing
    b) User by stripe_subscription_id         — user billing (sub match)
    c) User by stripe_customer_id             — user billing (customer match)
    d) Organization by metadata["org_id"]     — metadata fallback
    e) User by metadata["user_id"]            — metadata fallback (pre-B12 sessions)

    Returns (org, None) for org billing, (None, user) for user billing,
    or (None, None) when nothing matches.
    """
    if customer_id:
        org = db.exec(
            select(Organization).where(Organization.stripe_customer_id == customer_id)
        ).first()
        if org is not None:
            return org, None

    if sub_id:
        user = db.exec(
            select(User).where(User.stripe_subscription_id == sub_id)
        ).first()
        if user is not None:
            return None, user

    if customer_id:
        user = db.exec(
            select(User).where(User.stripe_customer_id == customer_id)
        ).first()
        if user is not None:
            return None, user

    # Metadata fallback — covers pre-B12 checkout sessions
    org_id_str = metadata.get("org_id", "")
    if org_id_str:
        try:
            org = db.get(Organization, int(org_id_str))
            if org is not None:
                return org, None
        except (ValueError, TypeError):
            pass

    user_id_str = metadata.get("user_id", "")
    if user_id_str:
        try:
            user = db.get(User, int(user_id_str))
            if user is not None:
                return None, user
        except (ValueError, TypeError):
            pass

    return None, None


def _handle_checkout_completed(obj: dict, db: Session) -> None:
    if obj.get("mode") != "subscription":
        return
    customer_id: str = obj.get("customer") or ""
    sub_id: str = obj.get("subscription") or ""
    metadata: dict = obj.get("metadata") or {}

    org, user = _find_billing_target(customer_id, sub_id, metadata, db)
    if org is not None:
        _set_org_plan(org, "pro", db,
                      sub_id=sub_id or None, customer_id=customer_id or None)
        logger.info("org_id=%d plan=pro (checkout)", org.id)
    elif user is not None:
        _set_user_plan(user, "pro", db,
                       sub_id=sub_id or None, customer_id=customer_id or None)
        logger.info("user_id=%d plan=pro (checkout)", user.id)
    else:
        logger.warning(
            "checkout.session.completed: no billing target found customer=%s metadata=%s",
            customer_id[:8] if customer_id else "", metadata,
        )


def _handle_subscription_change(obj: dict, db: Session) -> None:
    sub_id: str = obj.get("id", "")
    customer_id: str = obj.get("customer", "")
    metadata: dict = obj.get("metadata") or {}
    plan = plan_from_subscription_status(obj.get("status", ""))

    org, user = _find_billing_target(customer_id, sub_id, metadata, db)
    if org is not None:
        _set_org_plan(org, plan, db,
                      sub_id=sub_id or None, customer_id=customer_id or None)
        logger.info("org_id=%d plan=%s sub=%s", org.id, plan,
                    sub_id[:8] + "…" if sub_id else "")
    elif user is not None:
        _set_user_plan(user, plan, db,
                       sub_id=sub_id or None, customer_id=customer_id or None,
                       period_end=obj.get("current_period_end"))
        logger.info("user_id=%d plan=%s sub=%s", user.id, plan,
                    sub_id[:8] + "…" if sub_id else "")
    else:
        logger.warning(
            "subscription change: no target for sub=%s customer=%s — acknowledged",
            sub_id[:8] if sub_id else "", customer_id[:8] if customer_id else "",
        )


def _handle_subscription_deleted(obj: dict, db: Session) -> None:
    sub_id: str = obj.get("id", "")
    customer_id: str = obj.get("customer", "")
    metadata: dict = obj.get("metadata") or {}

    org, user = _find_billing_target(customer_id, sub_id, metadata, db)
    if org is not None:
        _set_org_plan(org, "free", db)
        logger.info("org_id=%d plan=free (subscription canceled)", org.id)
    elif user is not None:
        _set_user_plan(user, "free", db)
        logger.info("user_id=%d plan=free (subscription canceled)", user.id)
    else:
        logger.info("subscription.deleted: no matched target (ok)")


def handle_webhook(raw_body: bytes, sig_header: str) -> dict:
    """Verify Stripe signature, dispatch event, return ack. Uses its own DB session.

    Idempotency: a ``StripeEvent`` row is inserted (status=received) before
    any processing.  The unique index on ``event_id`` means a second delivery
    of the same event hits an IntegrityError and is silently acknowledged
    without re-processing.

    Error handling: exceptions during dispatch are recorded on the
    ``StripeEvent`` row (status=failed) and swallowed — Stripe receives 200
    so it does not retry indefinitely for non-transient failures.
    """
    _require_stripe()
    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not webhook_secret:
        raise HTTPException(
            status_code=500,
            detail={"type": "config_error", "message": "Webhook not configured"},
        )
    stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "")
    try:
        event = stripe.Webhook.construct_event(raw_body, sig_header, webhook_secret)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    try:
        event_id: str = event["id"]
        event_type: str = event["type"]
        obj: dict = event["data"]["object"]
    except (KeyError, TypeError) as exc:
        logger.error("Malformed Stripe webhook payload: %s", exc)
        raise HTTPException(status_code=400, detail="Malformed event payload")
    logger.info("webhook event_type=%s id=%s", event_type, event_id[:16])

    with Session(engine) as db:
        # ------------------------------------------------------------------
        # 1. Idempotency guard — insert first; unique constraint rejects dupes
        # ------------------------------------------------------------------
        stripe_evt = StripeEvent(
            event_id=event_id,
            event_type=event_type,
            received_at=datetime.now(tz=timezone.utc),
            status="received",
        )
        db.add(stripe_evt)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            logger.info("webhook duplicate event_id=%s — acknowledged", event_id[:16])
            return {"received": True}

        # Store PK in a plain int before any session state changes.
        stripe_evt_id: int = stripe_evt.id  # type: ignore[assignment]

        # ------------------------------------------------------------------
        # 1b. Distributed lock — prevent concurrent delivery of the same event
        # ------------------------------------------------------------------
        from .locking import acquire_lock, release_lock

        lock_key = f"webhook:{event_id}"
        _lock_owner = acquire_lock(db, lock_key)
        if _lock_owner is None:
            logger.warning(
                "webhook: lock unavailable for event_id=%s — ack without processing",
                event_id[:16],
            )
            return {"received": True}

        # ------------------------------------------------------------------
        # 2. Dispatch
        # ------------------------------------------------------------------
        try:
            if event_type == "checkout.session.completed":
                _handle_checkout_completed(obj, db)
            elif event_type in ("customer.subscription.updated", "customer.subscription.created"):
                _handle_subscription_change(obj, db)
            elif event_type == "customer.subscription.deleted":
                _handle_subscription_deleted(obj, db)
            else:
                # Unknown type — acknowledge without action
                stripe_evt.status = "ignored"
                stripe_evt.processed_at = datetime.now(tz=timezone.utc)
                db.add(stripe_evt)
                db.commit()
                return {"received": True}

            # Attribute the event to org/user via the same resolver used by handlers.
            customer_id: str = (obj.get("customer", "") or "") if isinstance(obj, dict) else ""
            sub_id: str = (obj.get("id", "") or "") if isinstance(obj, dict) else ""
            metadata: dict = (obj.get("metadata") or {}) if isinstance(obj, dict) else {}
            org_ref, user_ref = _find_billing_target(customer_id, sub_id, metadata, db)

            stripe_evt.status = "processed"
            stripe_evt.processed_at = datetime.now(tz=timezone.utc)
            if org_ref is not None:
                stripe_evt.org_id = org_ref.id
            elif user_ref is not None:
                stripe_evt.user_id = user_ref.id
                stripe_evt.org_id = user_ref.org_id
            db.add(stripe_evt)
            db.commit()
            # Audit: webhook received + dispatched successfully
            try:
                from .audit_log import write_audit_log
                write_audit_log(
                    db,
                    action="webhook.received",
                    resource_type="webhook",
                    resource_id=event_id[:64],
                    org_id=org_ref.id if org_ref is not None else (user_ref.org_id if user_ref else None),
                    user_id=user_ref.id if user_ref is not None else None,
                    metadata={"event_type": event_type, "status": "processed"},
                )
            except Exception:
                pass

        except Exception as exc:  # noqa: BLE001
            logger.exception("webhook processing failed event_id=%s type=%s", event_id[:16], event_type)
            try:
                db.rollback()
                failed_evt = db.get(StripeEvent, stripe_evt_id)
                if failed_evt is not None:
                    failed_evt.status = "failed"
                    failed_evt.error_message = str(exc)[:500]
                    db.add(failed_evt)
                    db.commit()
            except Exception:  # noqa: BLE001
                pass  # never mask the original; 200 is returned below
        finally:
            # Always release the distributed lock, even on failure.
            release_lock(db, lock_key, _lock_owner)

    return {"received": True}


def create_portal_session(user: User) -> dict:
    """Create a Stripe Customer Portal session. Returns {"url": ...}.

    For org members, the org-level Stripe customer is preferred so the billing
    owner manages the subscription rather than the individual user.
    """
    _require_stripe()
    secret_key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not secret_key:
        raise HTTPException(
            status_code=503,
            detail={"type": "billing_unavailable", "message": "Billing is not configured on this server.", "code": "stripe_missing_config"},
        )

    # Prefer org-level customer; fall back to user-level.
    customer_id: str | None = None
    if user.org_id is not None:
        with Session(engine) as db:
            org = db.get(Organization, user.org_id)
            if org is not None:
                customer_id = org.stripe_customer_id
    if not customer_id:
        customer_id = user.stripe_customer_id

    if not customer_id:
        raise HTTPException(
            status_code=400,
            detail={"type": "billing_error", "message": "No billing account on file. Please upgrade to Pro first.", "code": "no_customer"},
        )
    stripe.api_key = secret_key
    app_url = os.environ.get("PROMPTSENTINEL_APP_URL", "http://localhost:3000")
    portal = stripe.billing_portal.Session.create(
        customer=customer_id,
        return_url=f"{app_url}/dashboard",
    )
    return {"url": portal.url}


def create_checkout_session(user: User, db: Session) -> dict:
    """Create a Stripe Checkout session. Returns {"checkout_url": ..., "session_id": ...}.

    Billing target resolution:
    - User belongs to an org → Stripe customer is attached to the org.
    - No org → Stripe customer is attached to the user.
    In both cases the customer is created once and reused on subsequent calls.
    """
    _require_stripe()
    if _effective_plan(user, db) == "pro":
        raise HTTPException(
            status_code=409,
            detail={"type": "already_subscribed", "message": "Your account already has an active Pro subscription.", "code": "already_pro"},
        )
    secret_key, price_id = _stripe_env()
    success_url, cancel_url = _checkout_urls()
    stripe.api_key = secret_key

    meta: dict = {"user_id": str(user.id)}
    if user.org_id is not None:
        org = db.get(Organization, user.org_id)
        if org is not None:
            customer_id = _ensure_org_customer(org, user, db)
            meta["org_id"] = str(org.id)
        else:
            customer_id = _ensure_user_customer(user, db)
    else:
        customer_id = _ensure_user_customer(user, db)

    checkout = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        client_reference_id=str(user.id),
        allow_promotion_codes=True,
        metadata=meta,
    )
    return {"checkout_url": checkout.url, "session_id": checkout.id}
