from __future__ import annotations

import json
import logging
from typing import Any, Dict

from sqlmodel import Session

logger = logging.getLogger("promptsentinel.audit")


def log_audit_event(
    session: Session,
    *,
    event_type: str,
    org_id: int | None = None,
    user_id: int | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    metadata: Dict[str, Any] | None = None,
    ip: str | None = None,
) -> None:
    """Append a structured audit event with resource context. Never raises."""
    try:
        from .models import AuditEvent

        try:
            meta_str = json.dumps(metadata or {}, default=str)
        except Exception:
            meta_str = "{}"

        event = AuditEvent(
            event_type=event_type,
            user_id=user_id,
            org_id=org_id,
            resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            ip=ip,
            metadata_json=meta_str,
        )
        session.add(event)
        session.commit()
    except Exception as exc:
        logger.warning("log_audit_event failed event_type=%s: %s", event_type, exc)


def log_event(
    session: Session,
    event_type: str,
    user_id: int | None,
    metadata: Dict[str, Any],
    *,
    ip: str | None = None,
    org_id: int | None = None,
) -> None:
    """Append an audit event row. Never raises — audit must not crash requests."""
    try:
        from .models import AuditEvent

        try:
            meta_str = json.dumps(metadata, default=str)
        except Exception:
            meta_str = "{}"

        event = AuditEvent(
            event_type=event_type,
            user_id=user_id,
            org_id=org_id,
            ip=ip,
            metadata_json=meta_str,
        )
        session.add(event)
        session.commit()
    except Exception as exc:  # pragma: no cover
        logger.warning("audit log_event failed: %s", exc)
