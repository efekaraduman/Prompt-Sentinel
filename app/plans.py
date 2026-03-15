"""Subscription plan definitions and limit helpers."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

_VALID_PLANS = frozenset({"public", "free", "pro"})


@dataclass(frozen=True)
class PlanLimits:
    iterations_max: int
    rate_limit_per_min: int
    export_enabled: bool
    guard_scans_per_month: int   # -1 = unlimited
    campaigns_per_month: int     # -1 = unlimited


PLAN_LIMITS: dict[str, PlanLimits] = {
    # Unauthenticated / anonymous callers.
    "public": PlanLimits(iterations_max=50,   rate_limit_per_min=0,   export_enabled=False, guard_scans_per_month=50,   campaigns_per_month=5),
    # Authenticated users on the free tier.
    "free":   PlanLimits(iterations_max=300,  rate_limit_per_min=30,  export_enabled=True,  guard_scans_per_month=300,  campaigns_per_month=20),
    # Paying Pro subscribers.
    "pro":    PlanLimits(iterations_max=1000, rate_limit_per_min=300, export_enabled=True,  guard_scans_per_month=-1,   campaigns_per_month=-1),
}


def normalize_plan(plan: str | None) -> str:
    """Return a canonical plan name: 'public', 'free', or 'pro'.

    Any unrecognised value (including ``None``) is treated as ``'free'``
    so existing users without an explicit plan record are not punished.
    """
    if plan is None:
        return "free"          # backward compat: existing users with NULL plan → free tier
    p = plan.lower().strip()
    return p if p in _VALID_PLANS else "public"  # unrecognised string → safest tier


def get_limits(plan: str) -> PlanLimits:
    """Return limits for the given plan, falling back to 'free' for unknown plans."""
    return PLAN_LIMITS.get(normalize_plan(plan), PLAN_LIMITS["free"])


# Alias used by main.py / usage.py
get_limits_for_plan = get_limits


def max_iterations_for(plan: str | None) -> int:
    """Return the maximum iterations allowed for *plan*."""
    return PLAN_LIMITS[normalize_plan(plan)].iterations_max


def allow_export_for(plan: str | None) -> bool:
    """Return ``True`` when *plan* is permitted to export campaign data."""
    return PLAN_LIMITS[normalize_plan(plan)].export_enabled


class PlanLimitError(Exception):
    """Raised when a request exceeds the user's plan limits.

    Caught by the registered exception handler which converts it to a 402
    response with structured body and diagnostic headers.
    """

    def __init__(
        self,
        code: str = "plan_limit",
        message: str = "Monthly plan limit exceeded. Upgrade to Pro.",
        plan: str = "free",
        period: str = "",
        guard_scans: int = 0,
        campaigns_started: int = 0,
        guard_limit: Optional[int] = None,
        campaigns_limit: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.plan = plan
        self.period = period
        self.guard_scans = guard_scans
        self.campaigns_started = campaigns_started
        self.guard_limit = guard_limit
        self.campaigns_limit = campaigns_limit
