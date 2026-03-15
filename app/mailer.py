"""SMTP email sender for magic-link authentication.

Uses only stdlib (smtplib + email.message) — no extra dependencies.
Auto-selects TLS mode:
  port 465  → SMTP_SSL (implicit TLS)
  any other → STARTTLS (explicit TLS, default 587)
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from .config import get_settings

logger = logging.getLogger("promptsentinel.mailer")


class MailError(Exception):
    """Raised when an email cannot be delivered. Never crashes the caller."""


def send_magic_link(to_email: str, link_url: str) -> None:
    """Compose and deliver a magic-link email.  Raises :exc:`MailError` on failure."""
    cfg = get_settings()
    host: str = cfg["smtp_host"]
    port: int = cfg["smtp_port"]
    user: str = cfg["smtp_user"]
    password: str = cfg["smtp_pass"]
    from_addr: str = cfg["smtp_from"]

    msg = EmailMessage()
    msg["Subject"] = "Your PromptSentinel sign-in link"
    msg["From"] = from_addr
    msg["To"] = to_email
    msg.set_content(
        f"Click the link below to sign in to PromptSentinel.\n\n"
        f"  {link_url}\n\n"
        f"This link expires in 15 minutes and can only be used once.\n"
        f"If you did not request this, you can safely ignore this email."
    )
    msg.add_alternative(
        f"<p>Click the link below to sign in to <strong>PromptSentinel</strong>.</p>"
        f'<p><a href="{link_url}">{link_url}</a></p>'
        f"<p>This link expires in <strong>15 minutes</strong> and can only be used once.</p>"
        f"<p style='color:#666'>If you did not request this, ignore this email.</p>",
        subtype="html",
    )

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port, timeout=10) as smtp:
                if user:
                    smtp.login(user, password)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=10) as smtp:
                smtp.ehlo()
                smtp.starttls()
                smtp.ehlo()
                if user:
                    smtp.login(user, password)
                smtp.send_message(msg)
        logger.info("Magic-link email sent to %s", to_email)
    except Exception as exc:
        logger.error("Failed to send magic-link email to %s: %s", to_email, exc)
        raise MailError(str(exc)) from exc
