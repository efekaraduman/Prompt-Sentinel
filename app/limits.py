"""Phase 1.3 — per-plan monthly usage limits.

PROMPTSENTINEL_LIMITS_TEST_MODE=1 reduces free/public limits to
guard_scans=3, campaigns_started=2 so you can trigger the limit quickly in
local testing without burning real quota.
"""
from __future__ import annotations

import os
from typing import Optional

# None means unlimited
_DEFAULT_LIMITS: dict[str, dict[str, Optional[int]]] = {
    "public": {"guard_scans": 50,  "campaigns_started": 5},
    "free":   {"guard_scans": 300, "campaigns_started": 20},
    "pro":    {"guard_scans": None, "campaigns_started": None},
}

# Test-mode overrides (free/public only)
_TEST_LIMITS: dict[str, dict[str, Optional[int]]] = {
    "public": {"guard_scans": 3, "campaigns_started": 2},
    "free":   {"guard_scans": 3, "campaigns_started": 2},
    "pro":    {"guard_scans": None, "campaigns_started": None},
}

_VALID = frozenset({"public", "free", "pro"})


def resolve_plan(user_plan: str | None) -> str:
    """Canonicalize plan string to 'public' | 'free' | 'pro'."""
    if user_plan in _VALID:
        return user_plan  # type: ignore[return-value]
    return "public" if user_plan is None else "free"


def _active_table() -> dict[str, dict[str, Optional[int]]]:
    return _TEST_LIMITS if os.environ.get("PROMPTSENTINEL_LIMITS_TEST_MODE", "") in ("1", "true", "yes") else _DEFAULT_LIMITS


def get_monthly_limits(plan: str) -> tuple[Optional[int], Optional[int]]:
    """Return (guard_scans_limit, campaigns_started_limit). None = unlimited."""
    limits = _active_table()[resolve_plan(plan)]
    return limits["guard_scans"], limits["campaigns_started"]
