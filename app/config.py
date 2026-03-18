"""Centralised environment-variable configuration for PromptSentinel.

All env reads are consolidated here so nothing else needs to call os.environ
directly.  The cached dict is filled once at first access; call
``get_settings.cache_clear()`` in tests to reset between cases.
"""
from __future__ import annotations

import os
from functools import lru_cache


def _safe_int(var: str, default: int) -> int:
    try:
        return int(os.environ.get(var, ""))
    except (ValueError, TypeError):
        return default


@lru_cache(maxsize=1)
def get_settings() -> dict:
    """Return a frozen snapshot of every env-var the app consumes.

    NOTE: two variables are read directly by the modules that need them and are
    therefore intentionally absent here:
      - PROMPTSENTINEL_DB_PATH  → app/db.py (SQLite engine creation)
      - PROMPTSENTINEL_CORS_ORIGINS → app/main.py (CORS middleware setup)
    All other env vars should be read via this function.
    """
    return {
        # Core
        "admin_api_key": os.environ.get("PROMPTSENTINEL_API_KEY", ""),
        "rate_limit_per_min": _safe_int("PROMPTSENTINEL_RATE_LIMIT_PER_MIN", 0),
        "dev_reset_db": os.environ.get("PROMPTSENTINEL_DEV_RESET_DB", "") in ("1", "true", "yes"),
        "log_level": os.environ.get("LOG_LEVEL", "INFO").upper(),
        "app_url": os.environ.get("PROMPTSENTINEL_APP_URL", "http://localhost:3000"),
        # Auth / magic-link
        "dev_login": os.environ.get("PROMPTSENTINEL_DEV_LOGIN", "") in ("1", "true", "yes"),
        "public_base_url": os.environ.get("PROMPTSENTINEL_PUBLIC_BASE_URL", "http://localhost:3000"),
        # Stripe
        "stripe_secret_key": os.environ.get("STRIPE_SECRET_KEY", ""),
        "stripe_webhook_secret": os.environ.get("STRIPE_WEBHOOK_SECRET", ""),
        "stripe_price_id_pro": os.environ.get("STRIPE_PRICE_ID_PRO", ""),
        "stripe_success_url": os.environ.get("STRIPE_SUCCESS_URL", ""),
        "stripe_cancel_url": os.environ.get("STRIPE_CANCEL_URL", ""),
        # Demo mode
        "demo_mode": os.environ.get("PROMPTSENTINEL_DEMO_MODE", "") in ("1", "true", "yes"),
        # Redis
        "redis_url": os.environ.get("REDIS_URL", ""),
        # SMTP (B4.2)
        "smtp_host": os.environ.get("SMTP_HOST", ""),
        "smtp_port": _safe_int("SMTP_PORT", 587),
        "smtp_user": os.environ.get("SMTP_USER", ""),
        "smtp_pass": os.environ.get("SMTP_PASS", ""),
        "smtp_from": os.environ.get("SMTP_FROM", ""),
    }


def app_url() -> str:
    """Return PROMPTSENTINEL_APP_URL with no trailing slash."""
    return get_settings()["app_url"].rstrip("/")


def smtp_configured() -> bool:
    """Return True when the minimum SMTP env vars (host + from) are set."""
    s = get_settings()
    return bool(s["smtp_host"] and s["smtp_from"])


def require_stripe() -> tuple[str, str]:
    """Return ``(secret_key, webhook_secret)`` or raise ``ValueError``.

    Callers should convert the ``ValueError`` to an appropriate HTTP 503
    response rather than letting it propagate as an unhandled exception.
    """
    s = get_settings()
    if not s["stripe_secret_key"]:
        raise ValueError(
            "STRIPE_SECRET_KEY is not set. "
            "Pass -StripeKey to run.ps1 or set the env var before starting."
        )
    return s["stripe_secret_key"], s["stripe_webhook_secret"]
