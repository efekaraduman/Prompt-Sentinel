"""Best-effort SMTP email sender (Phase 2.3).

Reads configuration from environment variables:
  PROMPTSENTINEL_SMTP_HOST  — required; if unset, every call is a no-op
  PROMPTSENTINEL_SMTP_PORT  — default 587
  PROMPTSENTINEL_SMTP_USER  — SMTP login username (optional)
  PROMPTSENTINEL_SMTP_PASS  — SMTP login password (optional)
  PROMPTSENTINEL_SMTP_FROM  — From address (falls back to SMTP_USER)

Returns True on successful send, False on any error or when unconfigured.
"""
from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage


def maybe_send_email(to_email: str, subject: str, body: str) -> bool:
    """Try to send a plain-text email via SMTP.  Never raises."""
    host = os.environ.get("PROMPTSENTINEL_SMTP_HOST", "").strip()
    if not host:
        return False  # SMTP not configured — silently skip

    port = int(os.environ.get("PROMPTSENTINEL_SMTP_PORT", "587"))
    user = os.environ.get("PROMPTSENTINEL_SMTP_USER", "")
    password = os.environ.get("PROMPTSENTINEL_SMTP_PASS", "")
    from_addr = (
        os.environ.get("PROMPTSENTINEL_SMTP_FROM", "").strip()
        or user
        or "noreply@promptsentinel.ai"
    )

    try:
        msg = EmailMessage()
        msg["From"] = from_addr
        msg["To"] = to_email
        msg["Subject"] = subject
        msg.set_content(body)
        with smtplib.SMTP(host, port, timeout=5) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if user:
                smtp.login(user, password)
            smtp.send_message(msg)
        return True
    except Exception:
        return False
