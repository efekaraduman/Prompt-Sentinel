"""Authentication dependencies: API-key (existing) + email/password session tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Header
from sqlmodel import Session, select

from .db import get_session
from .models import LoginToken, OrgMember, SessionToken, User

# ---------------------------------------------------------------------------
# Password hashing  (PBKDF2-SHA256, 600k iterations — OWASP 2023 minimum)
# ---------------------------------------------------------------------------

_HASH_ITERS = 600_000
_SALT_BYTES = 32

TOKEN_TTL_DAYS = 30


def hash_password(plain: str) -> str:
    salt = os.urandom(_SALT_BYTES)
    key = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, _HASH_ITERS)
    return base64.b64encode(salt + key).decode()


def verify_password(plain: str, stored: str) -> bool:
    raw = base64.b64decode(stored.encode())
    salt, key = raw[:_SALT_BYTES], raw[_SALT_BYTES:]
    check = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt, _HASH_ITERS)
    return hmac.compare_digest(key, check)


# ---------------------------------------------------------------------------
# Session token helpers
# ---------------------------------------------------------------------------

def create_session_token(user_id: int, session: Session) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    st = SessionToken(
        token=token,
        user_id=user_id,
        created_at=now,
        expires_at=now + timedelta(days=TOKEN_TTL_DAYS),
        is_active=True,
    )
    session.add(st)
    session.commit()
    return token


def _resolve_bearer(token: str, session: Session) -> bool:
    """Return True if the bearer token is valid, active, and not expired."""
    now = datetime.now(timezone.utc)
    st = session.exec(
        select(SessionToken).where(SessionToken.token == token)
    ).first()
    if st is None or not st.is_active:
        return False
    # expires_at may be naive (stored without tz); normalise for comparison
    expires = st.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > now


# ---------------------------------------------------------------------------
# FastAPI dependencies
# ---------------------------------------------------------------------------

class APIKeyError(Exception):
    """Raised when a required credential is missing or invalid."""


class OrgAdminError(Exception):
    """Raised when org-admin access is required but not present."""


class InsufficientRoleError(Exception):
    """Raised when the caller's org role is below the required minimum."""


# ---------------------------------------------------------------------------
# RBAC — role hierarchy
# ---------------------------------------------------------------------------

ROLE_HIERARCHY: dict[str, int] = {
    "viewer":  0,
    "analyst": 1,
    "admin":   2,
    "owner":   3,
}


def require_min_role(min_role: str):
    """Factory: returns a FastAPI dependency that enforces a minimum org role.

    Resolution order:
    1. Dev mode (no env key set) → bypass.
    2. Admin env key → owner-level bypass.
    3. user.is_admin flag → admin-level bypass (backward compat).
    4. Org member → OrgMember.role checked against hierarchy.
    5. Non-org user → treated as analyst (individual API access).
    """
    min_level = ROLE_HIERARCHY.get(min_role, 99)

    def _dep(
        x_api_key: str | None = Header(default=None),
        authorization: str | None = Header(default=None),
        session: Session = Depends(get_session),
    ) -> "User | None":
        admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
        # Dev mode — no auth configured
        if not admin_key:
            return None

        # Resolve raw token from Bearer header (if present)
        resolved_key: str | None = x_api_key
        if authorization:
            scheme, _, token = authorization.partition(" ")
            if scheme.lower() == "bearer" and token:
                if _resolve_bearer(token, session):
                    # Fetch the user behind the bearer token
                    st = session.exec(
                        select(SessionToken).where(SessionToken.token == token)
                    ).first()
                    if st:
                        u = session.get(User, st.user_id)
                        if u and u.is_active:
                            resolved_key = u.api_key

        # Admin env key → owner-level bypass
        if resolved_key == admin_key:
            return None

        if not resolved_key:
            raise InsufficientRoleError()

        user = session.exec(
            select(User).where(User.api_key == resolved_key)
        ).first()
        if user is None or not user.is_active:
            raise InsufficientRoleError()

        # user.is_admin flag → admin-level bypass (backward compat)
        if user.is_admin and min_level <= ROLE_HIERARCHY["admin"]:
            return user

        # Resolve org membership
        org_id = resolve_org_id(session, user)
        if org_id is None:
            # Non-org / individual user → grant analyst-level access
            if min_level <= ROLE_HIERARCHY["analyst"]:
                return user
            raise InsufficientRoleError()

        member = session.exec(
            select(OrgMember).where(
                OrgMember.org_id == org_id,
                OrgMember.user_id == user.id,
            )
        ).first()
        if member is None:
            raise InsufficientRoleError()

        caller_level = ROLE_HIERARCHY.get(member.role, -1)
        if caller_level < min_level:
            raise InsufficientRoleError()

        return user

    return _dep


def require_api_key(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> None:
    """No-op when PROMPTSENTINEL_API_KEY is unset (dev mode).
    Otherwise accepts:
      a) X-API-Key: <admin key or user api_key>
      b) Authorization: Bearer <session token>
    """
    admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
    if not admin_key:
        return  # auth disabled in dev

    # --- Bearer token path ---
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            if _resolve_bearer(token, session):
                return
            raise APIKeyError()

    # --- X-API-Key path ---
    if x_api_key is None:
        raise APIKeyError()

    if x_api_key == admin_key:
        return

    user = session.exec(select(User).where(User.api_key == x_api_key)).first()
    if user is None or not user.is_active:
        raise APIKeyError()


def get_current_user(
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> User | None:
    """Return the authenticated User, or None for admin key / dev mode (no plan limits)."""
    admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
    if not admin_key:
        return None  # dev mode — no limits

    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token:
            st = session.exec(
                select(SessionToken).where(SessionToken.token == token)
            ).first()
            if st and st.is_active and st.user_id is not None:
                expires = st.expires_at
                if expires.tzinfo is None:
                    expires = expires.replace(tzinfo=timezone.utc)
                if expires > datetime.now(timezone.utc):
                    user = session.get(User, st.user_id)
                    return user if user and user.is_active else None
            return None

    if x_api_key and x_api_key != admin_key:
        return session.exec(select(User).where(User.api_key == x_api_key)).first()

    return None  # admin key — no limits


# ---------------------------------------------------------------------------
# Magic-link helpers
# ---------------------------------------------------------------------------

MAGIC_TTL_MINUTES = 15


def _hash_token(raw: str) -> str:
    """Return the SHA-256 hex digest of a raw token string."""
    return hashlib.sha256(raw.encode()).hexdigest()


def create_login_token(session: Session, email: str, ttl_minutes: int = MAGIC_TTL_MINUTES) -> str:
    """Mint a one-time login token, persist its hash, and return the raw token."""
    raw = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    lt = LoginToken(
        email=email.lower().strip(),
        token_hash=_hash_token(raw),
        expires_at=now + timedelta(minutes=ttl_minutes),
        created_at=now,
    )
    session.add(lt)
    session.commit()
    return raw


def redeem_login_token(session: Session, raw_token: str) -> User:
    """Validate and consume a magic-link token; return (or create) the matching User."""
    h = _hash_token(raw_token)
    lt = session.exec(select(LoginToken).where(LoginToken.token_hash == h)).first()
    if lt is None:
        raise ValueError("Invalid or expired token")
    now = datetime.now(timezone.utc)
    expires = lt.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    # Always delete the token (one-time use), even if expired
    session.delete(lt)
    session.commit()
    if expires <= now:
        raise ValueError("Token has expired")

    email = lt.email
    user = session.exec(select(User).where(User.email == email)).first()
    if user is None:
        user = User(email=email, api_key=secrets.token_urlsafe(32))
        session.add(user)
        session.commit()
        session.refresh(user)
    else:
        changed = False
        if not user.api_key:
            user.api_key = secrets.token_urlsafe(32)
            changed = True
        if not user.is_active:
            user.is_active = True
            changed = True
        if changed:
            session.add(user)
            session.commit()
            session.refresh(user)
    return user


def get_request_user_org(
    request: "Request",
    session: "Session | None" = None,
) -> tuple[int | None, int | None, bool]:
    """Read resolved identity from request.state (populated by identity_middleware).

    Falls back to a direct DB lookup when state is unpopulated and *session*
    is provided — guards against the middleware's silent ``except Exception: pass``
    swallowing transient errors.

    Returns (user_id, org_id, is_admin).
    is_admin is True when the caller supplied the env admin key directly.
    """
    admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
    x_api_key: str | None = request.headers.get("x-api-key")
    is_admin = bool(admin_key and x_api_key == admin_key)
    user_id: int | None = getattr(request.state, "user_id", None)
    org_id: int | None = getattr(request.state, "org_id", None)

    # Fallback: if middleware silently failed, resolve directly from the DB.
    if user_id is None and x_api_key and not is_admin and session is not None:
        try:
            user = session.exec(select(User).where(User.api_key == x_api_key)).first()
            if user and user.is_active:
                user_id = user.id
                org_id = resolve_org_id(session, user)
        except Exception:
            pass

    return user_id, org_id, is_admin


def resolve_org_id(session: Session, user: User) -> int | None:
    """Return the effective org_id for *user* (E3 multi-org support).

    Priority: default_org_id (explicit) > first OrgMember row > legacy org_id.
    Persists the result to ``user.default_org_id`` when auto-discovered so the
    next call is O(1) (index lookup only).
    """
    if user.default_org_id is not None:
        return user.default_org_id

    member = session.exec(
        select(OrgMember).where(OrgMember.user_id == user.id)
    ).first()
    if member is not None:
        user.default_org_id = member.org_id
        session.add(user)
        try:
            session.commit()
        except Exception:
            session.rollback()
        return member.org_id

    return user.org_id  # legacy single-org field


async def set_request_state(
    request: "Request",
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> None:
    """FastAPI dependency: populates request.state with resolved identity fields.

    Sets request.state.user_id, request.state.org_id, request.state.user_plan.
    Admin-key bypass sets user_plan='pro' with no user_id/org_id.
    """
    from fastapi import Request as _Req  # noqa: F401 — used for type hint only
    request.state.user_id = None
    request.state.org_id = None
    request.state.user_plan = "public"

    admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
    if not x_api_key:
        return
    if admin_key and x_api_key == admin_key:
        request.state.user_plan = "pro"
        return

    user = session.exec(select(User).where(User.api_key == x_api_key)).first()
    if user is None or not user.is_active:
        return

    from .plans import normalize_plan
    from .models import Organization

    org_id = resolve_org_id(session, user)
    if org_id is not None:
        org = session.get(Organization, org_id)
        plan = normalize_plan(org.plan) if org else normalize_plan(user.plan)
    else:
        plan = normalize_plan(user.plan)

    request.state.user_id = user.id
    request.state.org_id = org_id
    request.state.user_plan = plan


# ---------------------------------------------------------------------------
# Backward-compat alias — existing endpoints that used require_org_admin now
# enforce the "admin" tier via the RBAC hierarchy.  Raises InsufficientRoleError
# (→ 403) which is handled by the same handler as OrgAdminError.
# ---------------------------------------------------------------------------

require_org_admin = require_min_role("admin")


def require_admin_key(
    x_api_key: str | None = Header(default=None),
) -> None:
    """Requires PROMPTSENTINEL_API_KEY to be set and to match the header."""
    admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
    if not admin_key or x_api_key != admin_key:
        raise APIKeyError()


def get_user_plan(session: Session, x_api_key: str | None) -> str:
    """Return the caller's subscription plan: ``'public'``, ``'free'``, or ``'pro'``.

    Resolution order (B8.2)
    -----------------------
    1. No key           → ``'public'`` (unauthenticated).
    2. Admin env key    → ``'pro'`` (admin always gets Pro limits).
    3. User in org      → ``normalize_plan(org.plan)`` (org-scoped billing).
    4. User, no org     → ``normalize_plan(user.plan)`` (individual plan).
    5. Unknown / inactive key → ``'public'``.
    """
    from .plans import normalize_plan  # local import avoids circular dependency at module load
    from .models import Organization   # local import — models already imported at top but safe

    if not x_api_key:
        return "public"

    admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
    if admin_key and x_api_key == admin_key:
        return "pro"

    user = session.exec(select(User).where(User.api_key == x_api_key)).first()
    if user is None or not user.is_active:
        return "public"

    # Org-scoped billing: resolve via OrgMember / default_org_id (E3) then legacy org_id.
    org_id = resolve_org_id(session, user)
    if org_id is not None:
        org = session.get(Organization, org_id)
        if org is not None:
            return normalize_plan(org.plan)

    return normalize_plan(user.plan)
