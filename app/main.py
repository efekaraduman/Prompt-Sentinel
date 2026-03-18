from __future__ import annotations

import asyncio
import csv
import hmac
import io
import json
import logging
import os
from typing import Any, Dict, List

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy import text
from sqlmodel import Session, select

from . import campaigns as campaign_service
from .audit import log_event, log_audit_event
from .auth import (
    APIKeyError, InsufficientRoleError, OrgAdminError,
    create_login_token, get_current_user, get_user_plan,
    get_request_user_org,
    redeem_login_token, require_admin_key, require_api_key, require_min_role,
    require_org_admin, resolve_org_id, set_request_state,
)
from .mailer import MailError, send_magic_link
from .config import get_settings, smtp_configured
from .billing import create_checkout_url, create_checkout_session, create_portal_session, handle_webhook, StripeMissingError
from .webhooks import fire_guard_event
from .usage import (
    current_period_ym, get_or_create_counter, plan_quotas,
    enforce_guard_scans, enforce_campaign_iterations,
    org_enforce_guard_scans, org_enforce_campaign_iterations,
    incr_guard_scans, incr_campaign_iterations,
    bump_usage, current_period,
    read_usage, org_total_usage,
    # E6 — org-scoped quota enforcement
    current_ym, limits_for_plan, get_or_create_usage,
    increment_guard, increment_campaign,
)
from .limits import get_monthly_limits, resolve_plan as resolve_plan_tier
from .guard import run_guard_scan
from .plans import PlanLimitError, allow_export_for, max_iterations_for, normalize_plan
from .ratelimit import (
    MULTI_WORKER, MULTI_WORKER_REASON, RateLimitError,
    require_rate_limit, require_rate_limit_campaigns, require_rate_limit_guard,
)
from .attack_engine import simulate_attacks
from .db import get_session, init_db
from .redaction import redact_finding_dict, redact_finding_list, redact_string
from .risk_analyzer import analyze_risk
from .schemas import (
    CampaignCreateRequest,
    CampaignCreateResponse,
    CampaignStatus,
    CampaignStatusResponse,
    CreateUserRequest,
    CreateUserResponse,
    UserKeyResponse,
    UserSafeResponse,
    MeResponse,
    DashboardSummaryResponse,
    RecentCampaignItem,
    FindingResponse,
    PaginatedFindingsResponse,
    TestLLMRequest,
    TestLLMResponse,
    SignupRequest,
    PasswordLoginRequest,
    LoginRequest,
    LoginResponse,
    RedeemRequest,
    RedeemResponse,
    TokenResponse,
    AdminGlobalAnalyticsResponse,
    AdminUserUsageItem,
    AuditEventItem,
    DailyCount,
    DailyCountPoint,
    GuardAnalyticsResponse,
    OrgThreatTrendResponse,
    GuardScanAsyncRequest,
    ThreatTrendResponse,
    GuardScanHistoryItem,
    GuardScanItem,
    GuardScanHistoryResponse,
    GuardScanQueuedResponse,
    GuardScanRequest,
    GuardScanResponse,
    GuardScanResultResponse,
    RiskTrendItem,
    ThreatClusterItem,
    ThreatClusterListResponse,
    SignatureClusterItem,
    SecurityEventExportItem,
    SecurityExportResponse,
    ThreatSignatureItem,
    TrendPoint,
    ThreatTrendsResponse,
    ThreatAnalyticsResponse,
    UsageResponse,
    UsageStatusResponse,
    CreateOrgRequest,
    OrgResponse,
    AssignUserOrgRequest,
    AddOrgMemberRequest,
    SetUserOrgRequest,
    AnomalyItem,
    AnomalyResponse,
    EmergingThreatItem,
    EmergingThreatResponse,
    WebhookConfigRequest,
    WebhookConfigResponse,
    SketchClusterItem,
    ClusterTrendPoint,
    UsageSummaryResponse,
    WebhookAck,
    OrgRemainingResponse,
    UpgradeBannerResponse,
    ThreatGraphNode,
    WebhookDeliveryListResponse,
    WebhookDeadLetterListResponse,
    ThreatGraphEdge,
    ThreatGraphResponse,
    ThreatFeedItem,
    ThreatFeedResponse,
    UpdateOrgRetentionRequest,
    SetStrictModeRequest,
    OrgSecurityConfigRequest,
    OrgSecurityConfigResponse,
    ZeroTrustConfigRequest,
    GuardSimulateRequest,
    GuardSimulateResponse,
    HardeningSuggestion,
    HardeningSuggestionsResponse,
    AttackerProfileResponse,
    AttackerProfileItem,
    GuardReplayResponse,
    MonthlyReportResponse,
    EnterpriseReportResponse,
    ReportTrendPoint,
    ReportUsage,
    ReportRiskPercentile,
    ReportCluster,
    ReportSignature,
    OrgUsageResponse,
    DailyTrendPoint,
    OrgTrendResponse,
    AuditEventListResponse,
    PerformanceAnalyticsResponse,
    AttackerPatternMetricItem,
    AttackerPatternMetricResponse,
    ExecutiveSummaryResponse,
    SecurityScorecardResponse,
    PublicTrustStatusResponse,
    TrustCapabilityItem,
    TrustCapabilitiesResponse,
    PromptMutationRequest,
    PromptMutationResponse,
    RedTeamGenerateRequest,
    RedTeamGenerateResponse,
    MonthlyEnterpriseReportResponse,
    CrossModelConsensusRequest,
    CrossModelConsensusResponse,
    TrustScoreResponse,
)


app = FastAPI(
    title="PromptSentinel API",
    description="Simulate prompt-injection attacks against an LLM and compute a simple risk score.",
    version="0.3.0",
)

_cors_env = os.environ.get("PROMPTSENTINEL_CORS_ORIGINS", "")
if _cors_env.strip():
    _allowed_origins = [o.strip() for o in _cors_env.split(",") if o.strip()]
else:
    _allowed_origins = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Requested-With"],
)

logging.basicConfig(level=get_settings()["log_level"])
logger = logging.getLogger("promptsentinel")


# ---------------------------------------------------------------------------
# Security response headers middleware
# ---------------------------------------------------------------------------

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next: Any) -> Any:
    """Attach browser security headers to every response."""
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    # Strict-Transport-Security: send in production OR when HTTPS env flag is set.
    # Never send HSTS over plain HTTP (breaks dev) — only when ENVIRONMENT=production or HTTPS=1.
    _env = os.environ.get("ENVIRONMENT", "")
    _force_https = os.environ.get("HTTPS", "0") not in ("0", "", "false", "False")
    if _env == "production" or _force_https:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


# ---------------------------------------------------------------------------
# E3 — Identity middleware: resolves caller and populates request.state
# ---------------------------------------------------------------------------

@app.middleware("http")
async def identity_middleware(request: Request, call_next: Any) -> Any:
    """Resolve caller identity early and expose on request.state.

    Sets request.state.user_id (int|None), request.state.org_id (int|None),
    request.state.user_plan ('public'|'free'|'pro').
    Admin-key callers get user_plan='pro', no user_id/org_id.
    Opens a short-lived session; main endpoint sessions are unaffected.
    """
    from sqlmodel import Session as _Session
    from .db import engine as _engine
    from .models import Organization as _Org, User as _User
    from .plans import normalize_plan as _np

    request.state.user_id = None
    request.state.org_id = None
    request.state.user_plan = "public"

    api_key: str | None = request.headers.get("x-api-key")
    admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")

    if api_key:
        if admin_key and hmac.compare_digest(api_key, admin_key):
            request.state.user_plan = "pro"
        else:
            try:
                with _Session(_engine) as _s:
                    _user = _s.exec(select(_User).where(_User.api_key == api_key)).first()
                    if _user and _user.is_active:
                        _org_id = resolve_org_id(_s, _user)
                        if _org_id is not None:
                            _org = _s.get(_Org, _org_id)
                            _plan = _np(_org.plan) if _org else _np(_user.plan)
                        else:
                            _plan = _np(_user.plan)
                        request.state.user_id = _user.id
                        request.state.org_id = _org_id
                        request.state.user_plan = _plan
            except Exception as _mid_exc:
                logger.warning("identity_middleware: user resolution error — %s", _mid_exc, exc_info=_mid_exc)

    return await call_next(request)


@app.on_event("startup")
def on_startup() -> None:
    """Initialise database schema on application startup."""
    init_db()


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "type": "validation_error",
                "message": "Request validation error",
                "details": exc.errors(),
            }
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    # Dict detail (e.g. quota errors) is passed through as-is under "error".
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
    detail = exc.detail if isinstance(exc.detail, str) else "HTTP error"
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "type": "http_error",
                "message": detail,
            }
        },
    )


@app.exception_handler(RateLimitError)
async def rate_limit_error_handler(request: Request, exc: RateLimitError) -> JSONResponse:
    return JSONResponse(
        status_code=429,
        content={"error": {"type": "rate_limited", "message": "Too many requests"}},
        headers={
            "Retry-After": str(exc.retry_after),
            "X-RateLimit-Limit": str(exc.limit),
            "X-RateLimit-Remaining": "0",
        },
    )


@app.exception_handler(PlanLimitError)
async def plan_limit_error_handler(request: Request, exc: PlanLimitError) -> JSONResponse:
    return JSONResponse(
        status_code=402,
        content={"error": {"type": "plan_limit", "message": exc.message, "code": exc.code}},
        headers={
            "X-Plan": exc.plan,
            "X-Usage-Period": exc.period,
            "X-Usage-GuardScans": str(exc.guard_scans),
            "X-Usage-CampaignsStarted": str(exc.campaigns_started),
            "X-Limit-GuardScans": str(exc.guard_limit) if exc.guard_limit is not None else "unlimited",
            "X-Limit-CampaignsStarted": str(exc.campaigns_limit) if exc.campaigns_limit is not None else "unlimited",
        },
    )


@app.exception_handler(APIKeyError)
async def api_key_error_handler(request: Request, exc: APIKeyError) -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={"error": {"type": "auth_error", "message": "Invalid API key"}},
    )


@app.exception_handler(OrgAdminError)
async def org_admin_error_handler(request: Request, exc: OrgAdminError) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={"error": {"type": "forbidden", "message": "Org admin required"}},
    )


@app.exception_handler(InsufficientRoleError)
async def insufficient_role_handler(request: Request, exc: InsufficientRoleError) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={"error": {"type": "forbidden", "message": "Insufficient role for this operation"}},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled application error", exc_info=exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "type": "internal_error",
                "message": "An unexpected error occurred. Please contact support if this persists.",
            }
        },
    )


# ---------------------------------------------------------------------------
# Demo-mode guard dependency
# ---------------------------------------------------------------------------

def require_not_demo() -> None:
    """Raise 403 when the server is running in read-only demo mode.

    Attach as a FastAPI dependency to any endpoint that mutates state or
    triggers external calls (billing, auth, campaign creation, etc.).
    Safe read-only endpoints and ``POST /guard/scan`` are intentionally
    excluded so visitors can still explore the product.
    """
    if get_settings().get("demo_mode"):
        raise HTTPException(
            status_code=403,
            detail={
                "error": {
                    "type": "demo_mode",
                    "message": "This action is disabled in demo mode. Deploy your own instance to use this feature.",
                }
            },
        )


@app.get("/dashboard/summary", response_model=DashboardSummaryResponse)
async def dashboard_summary(
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> DashboardSummaryResponse:
    """Aggregate SaaS dashboard metrics."""
    from sqlalchemy import func as safunc
    from .models import Campaign, Finding, User

    # None when admin key / dev mode → global view; User.org_id when org-scoped caller
    _org_id = getattr(_role, "org_id", None)

    def _count(model):
        return session.exec(select(safunc.count()).select_from(model)).one()

    def _count_status(status: str) -> int:
        q = select(safunc.count()).select_from(Campaign).where(Campaign.status == status)
        if _org_id is not None:
            q = q.where(Campaign.org_id == _org_id)
        return session.exec(q).one()

    total_users = _count(User)  # platform-level stat kept global
    if _org_id is not None:
        total_campaigns = session.exec(
            select(safunc.count()).select_from(Campaign).where(Campaign.org_id == _org_id)
        ).one()
        total_findings = session.exec(
            select(safunc.count()).select_from(Finding)
            .join(Campaign, Finding.campaign_id == Campaign.id)  # type: ignore[arg-type]
            .where(Campaign.org_id == _org_id)
        ).one()
    else:
        total_campaigns = _count(Campaign)
        total_findings = _count(Finding)
    running_campaigns = _count_status("running")
    completed_campaigns = _count_status("completed")
    failed_campaigns = _count_status("failed")

    # avg_risk_global from completed campaigns' metrics_json
    q_completed = select(Campaign.metrics_json).where(Campaign.status == "completed")
    if _org_id is not None:
        q_completed = q_completed.where(Campaign.org_id == _org_id)
    completed_mj = session.exec(q_completed).all()
    avg_risks = []
    for mj in completed_mj:
        try:
            v = json.loads(mj or "{}").get("avg_risk")
            if v is not None:
                avg_risks.append(float(v))
        except Exception:
            pass
    avg_risk_global = round(sum(avg_risks) / len(avg_risks), 2) if avg_risks else 0.0

    # high_risk_campaign_ratio: max_risk >= 80 across org-scoped campaigns
    q_all = select(Campaign.metrics_json)
    if _org_id is not None:
        q_all = q_all.where(Campaign.org_id == _org_id)
    all_mj = session.exec(q_all).all()
    high_risk = sum(
        1 for mj in all_mj
        if float((json.loads(mj or "{}")).get("max_risk", 0) or 0) >= 80
    )
    high_risk_campaign_ratio = round(high_risk / total_campaigns, 4) if total_campaigns else 0.0

    return DashboardSummaryResponse(
        total_users=total_users,
        total_campaigns=total_campaigns,
        running_campaigns=running_campaigns,
        completed_campaigns=completed_campaigns,
        failed_campaigns=failed_campaigns,
        total_findings=total_findings,
        avg_risk_global=avg_risk_global,
        high_risk_campaign_ratio=high_risk_campaign_ratio,
    )


@app.get("/dashboard/recent", response_model=List[RecentCampaignItem])
async def dashboard_recent(
    limit: int = Query(10, ge=1, le=100),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> List[RecentCampaignItem]:
    """Return the most recent campaigns ordered by created_at desc."""
    from .models import Campaign

    _org_id = getattr(_role, "org_id", None)
    q = select(Campaign).order_by(Campaign.created_at.desc()).limit(limit)
    if _org_id is not None:
        q = q.where(Campaign.org_id == _org_id)
    rows = session.exec(q).all()

    items: List[RecentCampaignItem] = []
    for c in rows:
        try:
            metrics = json.loads(c.metrics_json or "{}")
        except Exception as _json_exc:
            logger.warning("dashboard: malformed metrics_json for campaign id=%s — %s", c.id, _json_exc)
            metrics = {}
        max_risk = int(metrics.get("max_risk", 0) or 0)
        avg_risk = float(metrics.get("avg_risk", 0.0) or 0.0)
        total = c.iterations_total or 1
        progress = round(min(1.0, (c.iterations_done or 0) / total), 4)
        items.append(
            RecentCampaignItem(
                id=c.id,
                created_at=c.created_at,
                status=c.status,
                iterations_total=c.iterations_total,
                iterations_done=c.iterations_done,
                progress=progress,
                max_risk=max_risk,
                avg_risk=avg_risk,
            )
        )
    return items


@app.get("/dashboard/risk-trend", response_model=List[RiskTrendItem])
async def dashboard_risk_trend(
    limit: int = Query(10, ge=1, le=50),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> List[RiskTrendItem]:
    """Return last N completed campaigns ordered by created_at DESC for trend display."""
    from .models import Campaign

    _org_id = getattr(_role, "org_id", None)
    q = (
        select(Campaign)
        .where(Campaign.status == "completed")
        .order_by(Campaign.created_at.desc())
        .limit(limit)
    )
    if _org_id is not None:
        q = q.where(Campaign.org_id == _org_id)
    rows = session.exec(q).all()

    items: List[RiskTrendItem] = []
    for c in rows:
        try:
            metrics = json.loads(c.metrics_json or "{}")
        except Exception as _json_exc:
            logger.warning("dashboard: malformed metrics_json for campaign id=%s — %s", c.id, _json_exc)
            metrics = {}
        items.append(
            RiskTrendItem(
                campaign_id=c.id,
                created_at=c.created_at,
                avg_risk=float(metrics.get("avg_risk", 0.0) or 0.0),
                max_risk=int(metrics.get("max_risk", 0) or 0),
            )
        )
    return items


@app.get("/analytics/guard", response_model=GuardAnalyticsResponse)
async def guard_analytics(
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    user: object = Depends(get_current_user),
) -> GuardAnalyticsResponse:
    """Return guard-scan analytics for the current user derived from audit events."""
    from .models import AuditEvent, User as UserModel

    if not isinstance(user, UserModel):
        raise HTTPException(status_code=403, detail="User account required")

    rows = session.exec(
        select(AuditEvent)
        .where(AuditEvent.user_id == user.id)
        .where(AuditEvent.event_type == "guard_scan")
    ).all()

    allows = warns = blocks = 0
    latencies: list[float] = []
    category_counts: dict[str, int] = {}

    for r in rows:
        try:
            meta = json.loads(r.metadata_json or "{}")
        except Exception:
            continue
        decision = meta.get("decision", "allow")
        if decision == "warn":
            warns += 1
        elif decision == "block":
            blocks += 1
        else:
            allows += 1
        elapsed = meta.get("elapsed_ms")
        if isinstance(elapsed, (int, float)):
            latencies.append(float(elapsed))
        for cat in meta.get("categories") or []:
            if isinstance(cat, str):
                category_counts[cat] = category_counts.get(cat, 0) + 1

    total = allows + warns + blocks
    avg_ms = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    top_cats = dict(sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:10])

    return GuardAnalyticsResponse(
        total_scans=total,
        allows=allows,
        warns=warns,
        blocks=blocks,
        avg_latency_ms=avg_ms,
        top_category_counts=top_cats,
    )


@app.get("/analytics/guard/trend", response_model=ThreatTrendResponse)
async def guard_analytics_trend(
    days: int = Query(default=7, ge=1, le=90),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> ThreatTrendResponse:
    """Return daily guard scan totals + blocked counts for the last N days.

    Uses GuardScanRecord (written for every scan, sync and async).
    Missing days are zero-filled so the response always contains exactly
    ``days`` points in ascending date order.
    """
    from .models import GuardScanRecord, User as _User
    from datetime import datetime, timezone, timedelta

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Valid API key required")

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    q = select(GuardScanRecord).where(GuardScanRecord.created_at >= cutoff)
    if user.org_id is not None:
        q = q.where(GuardScanRecord.org_id == user.org_id)
    else:
        q = q.where(GuardScanRecord.user_id == user.id)
    rows = session.exec(q).all()

    today = datetime.now(timezone.utc).date()
    date_range = [
        (today - timedelta(days=i)).isoformat()
        for i in range(days - 1, -1, -1)
    ]
    counts: dict[str, list[int]] = {d: [0, 0] for d in date_range}  # [total, blocked]

    for r in rows:
        day = str(r.created_at)[:10]
        if day in counts:
            counts[day][0] += 1
            if r.blocked:
                counts[day][1] += 1

    return ThreatTrendResponse(
        days=days,
        points=[
            DailyCountPoint(day=d, total=counts[d][0], blocked=counts[d][1])
            for d in date_range
        ],
    )


@app.get("/analytics/org/trend", response_model=OrgTrendResponse)
async def analytics_org_trend(
    request: Request,
    days: int = Query(default=7, ge=1, le=30),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> OrgTrendResponse:
    """Org-scoped daily trend analytics for guard scans and campaigns.

    days must be 7 or 30; any other value returns 422.
    """
    if days not in (7, 30):
        raise HTTPException(status_code=422, detail="days must be 7 or 30")

    from .models import GuardScanRecord, Campaign as _Camp, OrgUsageMonth, User as _User
    from datetime import datetime as _dt, timedelta, timezone as _tz
    import json as _json
    from collections import Counter

    # Authenticate
    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    _, org_id, _ = get_request_user_org(request, session)

    now = _dt.now(_tz.utc)
    cutoff = now - timedelta(days=days)

    # Zero-filled day buckets (oldest → newest)
    day_keys = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(days - 1, -1, -1)]
    scans_total: dict[str, int]   = {d: 0 for d in day_keys}
    scans_blocked: dict[str, int] = {d: 0 for d in day_keys}
    camps_per_day: dict[str, int] = {d: 0 for d in day_keys}
    cat_counter: Counter[str]     = Counter()

    # Aggregate GuardScanRecord per day
    scan_q = select(GuardScanRecord).where(GuardScanRecord.created_at >= cutoff)
    if org_id is not None:
        scan_q = scan_q.where(GuardScanRecord.org_id == org_id)
    else:
        scan_q = scan_q.where(GuardScanRecord.user_id == user.id)
    for r in session.exec(scan_q).all():
        d = r.created_at.strftime("%Y-%m-%d")
        if d in scans_total:
            scans_total[d] += 1
            if r.decision == "block":
                scans_blocked[d] += 1
        try:
            for cat in _json.loads(r.categories_json or "[]"):
                cat_counter[cat] += 1
        except Exception:
            pass

    # Aggregate Campaign creations per day (org-scoped only)
    if org_id is not None:
        camp_q = select(_Camp).where(
            _Camp.created_at >= cutoff,
            _Camp.org_id == org_id,
        )
        for r in session.exec(camp_q).all():
            d = r.created_at.strftime("%Y-%m-%d")
            if d in camps_per_day:
                camps_per_day[d] += 1

    # Current month OrgUsageMonth summary
    _ym = current_ym()
    cm_guard = cm_camps = 0
    if org_id is not None:
        _um = session.exec(
            select(OrgUsageMonth)
            .where(OrgUsageMonth.org_id == org_id)
            .where(OrgUsageMonth.ym == _ym)
        ).first()
        if _um:
            cm_guard = _um.guard_scans
            cm_camps = _um.campaigns_created

    return OrgTrendResponse(
        days=days,
        points=[
            DailyTrendPoint(
                day=d,
                scans_total=scans_total[d],
                scans_blocked=scans_blocked[d],
                campaigns_created=camps_per_day[d],
            )
            for d in day_keys
        ],
        top_categories=dict(cat_counter.most_common(10)),
        current_month_guard_scans=cm_guard,
        current_month_campaigns_created=cm_camps,
    )


@app.post("/admin/users", response_model=CreateUserResponse, status_code=201)
async def create_user(
    payload: CreateUserRequest,
    request: Request,
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> CreateUserResponse:
    """Create a new API user (admin only). Returns the generated API key."""
    import secrets
    from sqlalchemy.exc import IntegrityError
    from .models import User

    user = User(email=payload.email, api_key=secrets.token_urlsafe(32))
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Email already exists")
    session.refresh(user)
    log_event(session, "admin_user_created", None, {"created_user_id": user.id},
              ip=request.client.host if request.client else None)
    return CreateUserResponse(email=user.email, api_key=user.api_key)


@app.get("/admin/users", response_model=List[UserSafeResponse])
async def list_users(
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> List[UserSafeResponse]:
    """List all users (admin only). Never returns api_key."""
    from .models import User as UserModel

    users = session.exec(select(UserModel)).all()
    return [
        UserSafeResponse(id=u.id, email=u.email, created_at=u.created_at, is_active=u.is_active, plan=u.plan)
        for u in users
    ]


@app.get("/admin/analytics", response_model=AdminGlobalAnalyticsResponse)
async def admin_global_analytics(
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> AdminGlobalAnalyticsResponse:
    """Return system-wide analytics (admin only)."""
    from sqlalchemy import func as safunc
    from .models import AuditEvent, Campaign, User as UserModel

    total_users = session.exec(select(safunc.count()).select_from(UserModel)).one()
    active_users = session.exec(
        select(safunc.count()).select_from(UserModel).where(UserModel.is_active == True)  # noqa: E712
    ).one()
    pro_users = session.exec(
        select(safunc.count()).select_from(UserModel).where(UserModel.plan == "pro")
    ).one()
    total_campaigns = session.exec(select(safunc.count()).select_from(Campaign)).one()
    campaigns_completed = session.exec(
        select(safunc.count()).select_from(Campaign).where(Campaign.status == "completed")
    ).one()
    campaigns_failed = session.exec(
        select(safunc.count()).select_from(Campaign).where(Campaign.status == "failed")
    ).one()

    scan_rows = session.exec(
        select(AuditEvent.metadata_json).where(AuditEvent.event_type == "guard_scan")
    ).all()

    guard_blocks = guard_warns = guard_allows = 0
    latencies: list[float] = []
    for raw in scan_rows:
        try:
            meta = json.loads(raw or "{}")
        except Exception:
            continue
        d = meta.get("decision", "allow")
        if d == "block":
            guard_blocks += 1
        elif d == "warn":
            guard_warns += 1
        else:
            guard_allows += 1
        el = meta.get("elapsed_ms")
        if isinstance(el, (int, float)):
            latencies.append(float(el))

    guard_total = guard_blocks + guard_warns + guard_allows
    avg_ms = round(sum(latencies) / len(latencies), 2) if latencies else 0.0

    return AdminGlobalAnalyticsResponse(
        total_users=total_users,
        active_users=active_users,
        pro_users=pro_users,
        total_campaigns=total_campaigns,
        campaigns_completed=campaigns_completed,
        campaigns_failed=campaigns_failed,
        guard_total_scans=guard_total,
        guard_blocks=guard_blocks,
        guard_warns=guard_warns,
        guard_allows=guard_allows,
        avg_guard_latency_ms=avg_ms,
    )


@app.get("/admin/users/usage", response_model=List[AdminUserUsageItem])
async def admin_users_usage(
    limit: int = Query(50, ge=1, le=500),
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> List[AdminUserUsageItem]:
    """Return per-user plan + monthly usage stats (admin only)."""
    from .models import User as UserModel

    users = session.exec(
        select(UserModel).order_by(UserModel.created_at.desc()).limit(limit)
    ).all()

    ym = current_period_ym()
    items: List[AdminUserUsageItem] = []
    for u in users:
        counter = get_or_create_counter(session, u.id, ym)
        quotas = plan_quotas(u.plan)
        items.append(
            AdminUserUsageItem(
                id=u.id,
                email=u.email,
                is_active=u.is_active,
                plan=u.plan,
                period_ym=ym,
                guard_scans_used=counter.guard_scans,
                guard_scans_limit=quotas.guard_scans,
                guard_scans_remaining=max(0, quotas.guard_scans - counter.guard_scans),
                campaign_iterations_used=counter.campaign_iterations,
                campaign_iterations_limit=quotas.campaign_iterations,
                campaign_iterations_remaining=max(0, quotas.campaign_iterations - counter.campaign_iterations),
            )
        )
    return items


@app.get("/admin/audit", response_model=List[AuditEventItem])
async def list_audit_events(
    limit: int = Query(50, ge=1, le=200),
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> List[AuditEventItem]:
    """Return recent audit events ordered by created_at DESC (admin only)."""
    from .models import AuditEvent

    rows = session.exec(
        select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    ).all()

    items: List[AuditEventItem] = []
    for r in rows:
        try:
            meta = json.loads(r.metadata_json or "{}")
        except Exception:
            meta = {}
        items.append(
            AuditEventItem(
                id=r.id,
                created_at=r.created_at,
                org_id=r.org_id,
                user_id=r.user_id,
                event_type=r.event_type,
                resource_type=getattr(r, "resource_type", None),
                resource_id=getattr(r, "resource_id", None),
                metadata=meta,
            )
        )
    return items


@app.post("/admin/users/{user_id}/deactivate", response_model=UserSafeResponse)
async def deactivate_user(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> UserSafeResponse:
    """Set is_active=False for a user (admin only)."""
    from .models import User as UserModel

    user = session.get(UserModel, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_active = False
    session.add(user)
    session.commit()
    session.refresh(user)
    log_event(session, "admin_user_deactivated", None, {"target_user_id": user.id},
              ip=request.client.host if request.client else None)
    return UserSafeResponse(id=user.id, email=user.email, created_at=user.created_at, is_active=user.is_active, plan=user.plan)


@app.post("/admin/users/{user_id}/rotate-key", response_model=UserKeyResponse)
async def rotate_user_key(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> UserKeyResponse:
    """Generate a new API key for a user (admin only). Returns the new key."""
    import secrets
    from .models import User as UserModel

    user = session.get(UserModel, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    user.api_key = secrets.token_urlsafe(32)
    session.add(user)
    session.commit()
    session.refresh(user)
    log_event(session, "admin_user_key_rotated", None, {"target_user_id": user.id},
              ip=request.client.host if request.client else None)
    return UserKeyResponse(id=user.id, email=user.email, api_key=user.api_key)


# ---------------------------------------------------------------------------
# B8.3 — Org-admin self-serve endpoints
# ---------------------------------------------------------------------------

@app.get("/org/users", response_model=List[UserSafeResponse])
async def org_list_users(
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
) -> List[UserSafeResponse]:
    """List all users in the caller's organisation (viewer+ role)."""
    from .models import User as UserModel

    _org_id = getattr(_role, "org_id", None)
    if _org_id is None:
        raise HTTPException(status_code=403, detail="User must belong to an organisation")
    users = session.exec(
        select(UserModel).where(UserModel.org_id == _org_id)
    ).all()
    return [
        UserSafeResponse(id=u.id, email=u.email, created_at=u.created_at, is_active=u.is_active, plan=u.plan)
        for u in users
    ]


@app.post("/org/users", response_model=UserKeyResponse, status_code=201)
async def org_create_user(
    payload: CreateUserRequest,
    request: Request,
    session: Session = Depends(get_session),
    admin: object = Depends(require_org_admin),
) -> UserKeyResponse:
    """Create a user in the caller's org (org admin only). Returns one-time api_key."""
    import secrets
    from sqlalchemy.exc import IntegrityError
    from .models import User as UserModel

    user = UserModel(
        email=payload.email,
        api_key=secrets.token_urlsafe(32),
        org_id=admin.org_id,
    )
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Email already exists")
    session.refresh(user)
    log_event(session, "org_user_created", admin.id, {"created_user_id": user.id, "org_id": admin.org_id},
              ip=request.client.host if request.client else None, org_id=admin.org_id)
    return UserKeyResponse(id=user.id, email=user.email, api_key=user.api_key)


@app.post("/org/users/{user_id}/deactivate", response_model=UserSafeResponse)
async def org_deactivate_user(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    admin: object = Depends(require_org_admin),
) -> UserSafeResponse:
    """Deactivate a user in the caller's org (org admin only)."""
    from .models import User as UserModel

    user = session.get(UserModel, user_id)
    if user is None or user.org_id != admin.org_id:
        raise HTTPException(status_code=404, detail="User not found in your org")
    user.is_active = False
    session.add(user)
    session.commit()
    session.refresh(user)
    log_event(session, "org_user_deactivated", admin.id, {"target_user_id": user.id},
              ip=request.client.host if request.client else None, org_id=admin.org_id)
    return UserSafeResponse(id=user.id, email=user.email, created_at=user.created_at, is_active=user.is_active, plan=user.plan)


@app.post("/org/users/{user_id}/rotate-key", response_model=UserKeyResponse)
async def org_rotate_user_key(
    user_id: int,
    request: Request,
    session: Session = Depends(get_session),
    admin: object = Depends(require_org_admin),
) -> UserKeyResponse:
    """Rotate the API key for a user in the caller's org (org admin only)."""
    import secrets
    from .models import User as UserModel

    user = session.get(UserModel, user_id)
    if user is None or user.org_id != admin.org_id:
        raise HTTPException(status_code=404, detail="User not found in your org")
    user.api_key = secrets.token_urlsafe(32)
    session.add(user)
    session.commit()
    session.refresh(user)
    log_event(session, "org_user_key_rotated", admin.id, {"target_user_id": user.id},
              ip=request.client.host if request.client else None, org_id=admin.org_id)
    return UserKeyResponse(id=user.id, email=user.email, api_key=user.api_key)


# ---------------------------------------------------------------------------
# B8.1 — Organisation admin endpoints
# ---------------------------------------------------------------------------

@app.post("/admin/orgs", response_model=OrgResponse, status_code=201)
async def create_org(
    payload: CreateOrgRequest,
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> OrgResponse:
    """Create a new organisation (admin only)."""
    from sqlalchemy.exc import IntegrityError
    from .models import Organization

    org = Organization(name=payload.name)
    session.add(org)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Organisation name already exists")
    session.refresh(org)
    log_audit_event(session, event_type="org_created", org_id=org.id,
                    resource_type="organization", resource_id=str(org.id),
                    metadata={"name": org.name})
    return OrgResponse(id=org.id, name=org.name, plan=org.plan, created_at=org.created_at,
                       retention_days=org.retention_days,
                       strict_mode=bool(org.strict_mode))


@app.get("/admin/orgs", response_model=List[OrgResponse])
async def list_orgs(
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> List[OrgResponse]:
    """List all organisations (admin only)."""
    from .models import Organization

    orgs = session.exec(select(Organization)).all()
    return [OrgResponse(id=o.id, name=o.name, plan=o.plan, created_at=o.created_at,
                        retention_days=o.retention_days,
                        strict_mode=bool(o.strict_mode)) for o in orgs]


@app.patch("/admin/orgs/{org_id}/retention", response_model=OrgResponse)
async def set_org_retention(
    org_id: int,
    payload: UpdateOrgRetentionRequest,
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> OrgResponse:
    """Set or clear the data-retention window for an organisation (admin only).

    ``retention_days`` — delete GuardScan, GuardScanRecord, AuditLog, and
    AuditEvent rows older than this many days.  Set to ``null`` to disable.
    Minimum: 7 days.  Maximum: 3650 days (10 years).

    Cleanup runs in the background worker every 60 poll cycles.
    """
    from .models import Organization

    org = session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    org.retention_days = payload.retention_days
    session.add(org)
    session.commit()
    session.refresh(org)
    return OrgResponse(id=org.id, name=org.name, plan=org.plan, created_at=org.created_at,
                       retention_days=org.retention_days,
                       strict_mode=bool(org.strict_mode))


@app.patch("/admin/orgs/{org_id}/strict-mode", response_model=OrgResponse)
async def set_org_strict_mode(
    org_id: int,
    payload: SetStrictModeRequest,
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> OrgResponse:
    """Enable or disable Strict Mode for an organisation (admin only).

    When ``strict_mode`` is ``true``, the guard pipeline applies two extra
    blocking rules to every scan made by org members, regardless of the
    per-request policy supplied by the caller:

    - **Medium severity → block** — inputs scored as medium risk are blocked
      instead of warned, eliminating the grey zone for suspicious but
      non-conclusive inputs.
    - **Override attempt → immediate block** — any input classified as
      ``prompt_injection`` or ``policy_leakage`` is blocked even when the
      caller's policy sets ``block_injection=false``.  This prevents clients
      from opting out of injection blocking in a strict org context.

    Strict Mode is enforced server-side and cannot be overridden by the
    per-request ``policy`` payload.
    """
    from .models import Organization

    org = session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    org.strict_mode = payload.strict_mode
    session.add(org)
    session.commit()
    session.refresh(org)
    return OrgResponse(id=org.id, name=org.name, plan=org.plan, created_at=org.created_at,
                       retention_days=org.retention_days,
                       strict_mode=bool(org.strict_mode))


@app.put("/org/security-config", response_model=OrgSecurityConfigResponse)
async def put_org_security_config(
    payload: OrgSecurityConfigRequest,
    session: Session = Depends(get_session),
    user: object = Depends(require_min_role("admin")),
    _rl: None = Depends(require_rate_limit),
) -> OrgSecurityConfigResponse:
    """Set org-level strict-mode security policy (org admin or platform admin). PHASE 2.18.

    ``strict_mode_default=true`` applies strict mode to all scans where the
    caller did not explicitly include a ``policy.strict_mode`` field.
    ``force_strict_mode=true`` additionally prevents request-level overrides
    (same as the admin-only ``strict_mode`` force flag, but settable by org admins).
    """
    from .models import Organization, User as _UserM

    _org_id = getattr(user, "org_id", None) if isinstance(user, _UserM) else None
    if _org_id is None:
        raise HTTPException(status_code=400, detail="No org associated with this account")

    org = session.get(Organization, _org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")

    org.strict_mode_default = payload.strict_mode_default
    if payload.force_strict_mode is not None:
        org.strict_mode = payload.force_strict_mode
    session.add(org)
    session.commit()
    session.refresh(org)

    _resolution = (
        "forced" if org.strict_mode
        else "default" if org.strict_mode_default
        else "request"
    )
    return OrgSecurityConfigResponse(
        org_id=org.id,
        strict_mode=bool(org.strict_mode),
        strict_mode_default=bool(org.strict_mode_default),
        policy_resolution=_resolution,
        zero_trust_mode=bool(getattr(org, "zero_trust_mode", False)),
    )


# ── PHASE 2.27 — Zero-Trust Mode ──────────────────────────────────────────────

@app.put("/org/security-config/zero-trust", response_model=OrgSecurityConfigResponse)
async def put_org_zero_trust(
    payload: ZeroTrustConfigRequest,
    session: Session = Depends(get_session),
    user: object = Depends(require_min_role("admin")),
    _rl: None = Depends(require_rate_limit),
) -> OrgSecurityConfigResponse:
    """Enable / disable zero-trust mode for the caller's org (org admin or platform admin).

    When zero_trust_mode=true all medium/high/critical risk scans are blocked,
    RAG injection and tool abuse are always blocked, and low-consensus scans are
    blocked regardless of request-level policy overrides.
    """
    from .models import Organization, User as _UserM

    _org_id = getattr(user, "org_id", None) if isinstance(user, _UserM) else None
    if _org_id is None:
        raise HTTPException(status_code=400, detail="No org associated with this account")

    org = session.get(Organization, _org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")

    org.zero_trust_mode = payload.zero_trust_mode
    if payload.zero_trust_mode:
        # Zero-trust supersedes the lesser strict-mode flags
        org.strict_mode = True
        org.strict_mode_default = True
    session.add(org)
    session.commit()
    session.refresh(org)

    return OrgSecurityConfigResponse(
        org_id=org.id,
        strict_mode=bool(org.strict_mode),
        strict_mode_default=bool(org.strict_mode_default),
        zero_trust_mode=bool(org.zero_trust_mode),
        policy_resolution="forced" if org.zero_trust_mode or org.strict_mode else (
            "default" if org.strict_mode_default else "request"
        ),
    )


@app.post("/admin/orgs/assign-user")
async def assign_user_to_org(
    payload: AssignUserOrgRequest,
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> dict:
    """Assign a user to an organisation and optionally grant org-admin (admin only)."""
    from .models import Organization, User as UserModel

    user = session.get(UserModel, payload.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    org = session.get(Organization, payload.org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    user.org_id = payload.org_id
    user.is_admin = payload.is_admin
    session.add(user)
    session.commit()
    # Audit: org assignment
    from .audit_log import write_audit_log as _wal
    _wal(session, action="user.org_assigned", resource_type="user",
         resource_id=str(user.id), org_id=payload.org_id, user_id=user.id,
         metadata={"org_id": payload.org_id, "is_admin": payload.is_admin})
    return {"ok": True}


# ---------------------------------------------------------------------------
# E3 — Org membership + user default-org endpoints (admin only)
# ---------------------------------------------------------------------------

@app.post("/admin/orgs/{org_id}/members", status_code=201)
async def add_org_member(
    org_id: int,
    payload: AddOrgMemberRequest,
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> dict:
    """Add a user to an org via OrgMember (many-to-many). Idempotent on role update."""
    from sqlalchemy.exc import IntegrityError as _IE
    from .models import OrgMember, Organization, User as UserModel

    org = session.get(Organization, org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")
    user = session.get(UserModel, payload.user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    existing = session.exec(
        select(OrgMember)
        .where(OrgMember.org_id == org_id)
        .where(OrgMember.user_id == payload.user_id)
    ).first()
    if existing:
        existing.role = payload.role
        session.add(existing)
        session.commit()
        from .audit_log import write_audit_log as _wal
        _wal(session, action="member.updated", resource_type="org_member",
             resource_id=str(existing.id), org_id=org_id, user_id=payload.user_id,
             metadata={"role": payload.role})
        return {"ok": True, "created": False}

    member = OrgMember(org_id=org_id, user_id=payload.user_id, role=payload.role)
    session.add(member)
    try:
        session.commit()
    except _IE:
        session.rollback()
        raise HTTPException(status_code=409, detail="Membership already exists")
    from .audit_log import write_audit_log as _wal
    _wal(session, action="member.added", resource_type="org_member",
         resource_id=str(member.id), org_id=org_id, user_id=payload.user_id,
         metadata={"role": payload.role})
    return {"ok": True, "created": True}


@app.post("/admin/users/{user_id}/set-org")
async def set_user_default_org(
    user_id: int,
    payload: SetUserOrgRequest,
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> dict:
    """Set a user's default_org_id (E3). Also syncs the legacy org_id field."""
    from .models import Organization, User as UserModel

    user = session.get(UserModel, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    org = session.get(Organization, payload.org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="Organisation not found")

    user.default_org_id = payload.org_id
    user.org_id = payload.org_id   # keep legacy field in sync
    session.add(user)
    session.commit()
    from .audit_log import write_audit_log as _wal
    _wal(session, action="user.org_assigned", resource_type="user",
         resource_id=str(user_id), org_id=payload.org_id, user_id=user_id,
         metadata={"default_org_id": payload.org_id})
    return {"ok": True, "user_id": user_id, "default_org_id": payload.org_id}


# ---------------------------------------------------------------------------
# B16 — Demo data seed (admin only)
# ---------------------------------------------------------------------------

@app.post("/admin/demo/seed")
async def seed_demo_data(
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> JSONResponse:
    """Create 3 sample campaigns + findings so the dashboard is non-empty.

    Idempotent — returns ``{"ok": true, "created": 0}`` if demo data already
    exists.  Requires admin key.
    """
    from .demo_seed import seed_demo
    created = seed_demo(session)
    return JSONResponse({"ok": True, "created": created})


@app.get("/admin/usage/notifications")
async def admin_usage_notifications(
    limit: int = Query(default=20, ge=1, le=200),
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
) -> JSONResponse:
    """Return recent UsageNotification rows for verification (admin only)."""
    from .models import UsageNotification
    from sqlalchemy import desc
    rows = session.exec(
        select(UsageNotification)
        .order_by(desc(UsageNotification.id))
        .limit(limit)
    ).all()
    return JSONResponse([{
        "id": r.id,
        "period": r.period_yyyymm,
        "org_id": r.org_id,
        "user_id": r.user_id,
        "kind": r.kind,
        "created_at": str(r.created_at),
    } for r in rows])


# ── Phase 3.14 — SIEM Webhook admin endpoints ─────────────────────────────────

@app.put("/admin/webhook", response_model=WebhookConfigResponse)
async def admin_set_webhook(
    payload: WebhookConfigRequest,
    session: Session = Depends(get_session),
    user: object = Depends(require_org_admin),
) -> WebhookConfigResponse:
    """Create or update the SIEM webhook for the caller's org (org-admin only)."""
    from .models import OrgWebhook, User as _User
    org_id: int | None = getattr(user, "org_id", None)
    if org_id is None:
        raise HTTPException(status_code=400, detail="User has no org")

    hook = session.exec(select(OrgWebhook).where(OrgWebhook.org_id == org_id)).first()
    if hook is None:
        hook = OrgWebhook(org_id=org_id, url=payload.url, secret=payload.secret, is_active=payload.is_active)
    else:
        hook.url = payload.url
        hook.secret = payload.secret
        hook.is_active = payload.is_active
    session.add(hook)
    session.commit()
    session.refresh(hook)
    return WebhookConfigResponse(
        url=hook.url,
        is_active=hook.is_active,
        created_at=hook.created_at,
        last_error=hook.last_error,
        last_sent_at=hook.last_sent_at,
    )


@app.get("/admin/webhook", response_model=WebhookConfigResponse)
async def admin_get_webhook(
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
) -> WebhookConfigResponse:
    """Read webhook config for the caller's org (viewer+ role)."""
    from .models import OrgWebhook
    org_id: int | None = getattr(_role, "org_id", None)
    if org_id is None:
        raise HTTPException(status_code=400, detail="User has no org")
    hook = session.exec(select(OrgWebhook).where(OrgWebhook.org_id == org_id)).first()
    if hook is None:
        raise HTTPException(status_code=404, detail="No webhook configured")
    return WebhookConfigResponse(
        url=hook.url,
        is_active=hook.is_active,
        created_at=hook.created_at,
        last_error=hook.last_error,
        last_sent_at=hook.last_sent_at,
    )


# ── E1 — Webhook delivery status endpoints ────────────────────────────────────

@app.get("/admin/webhook/deliveries", response_model=WebhookDeliveryListResponse)
async def admin_webhook_deliveries(
    status: str | None = Query(default=None, description="Filter by status: pending|success|dead_lettered"),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    user: object = Depends(require_min_role("viewer")),
) -> WebhookDeliveryListResponse:
    """List webhook delivery history for the caller's org (viewer+ role)."""
    from .models import WebhookDelivery
    from .schemas import WebhookDeliveryItem as _WDI
    org_id: int | None = getattr(user, "org_id", None)
    if org_id is None:
        raise HTTPException(status_code=400, detail="User has no org")

    from sqlalchemy import func as _safunc
    q = select(WebhookDelivery).where(WebhookDelivery.org_id == org_id)
    if status:
        q = q.where(WebhookDelivery.status == status)

    total = session.exec(
        select(_safunc.count()).select_from(WebhookDelivery)
        .where(WebhookDelivery.org_id == org_id)
        .where(*([] if not status else [WebhookDelivery.status == status]))
    ).one()
    items = list(session.exec(
        q.order_by(WebhookDelivery.created_at.desc()).offset(offset).limit(limit)  # type: ignore[arg-type]
    ).all())

    return WebhookDeliveryListResponse(
        items=[
            _WDI(
                id=r.id,
                org_id=r.org_id,
                status=r.status,
                retry_count=r.retry_count,
                next_retry_at=r.next_retry_at,
                last_error=r.last_error,
                created_at=r.created_at,
                delivered_at=r.delivered_at,
            )
            for r in items
        ],
        total=total,
    )


@app.get("/admin/webhook/dead-letters", response_model=WebhookDeadLetterListResponse)
async def admin_webhook_dead_letters(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    user: object = Depends(require_min_role("admin")),
) -> WebhookDeadLetterListResponse:
    """List dead-lettered webhook deliveries for the caller's org (admin+ role)."""
    from .models import WebhookDeadLetter
    from .schemas import WebhookDeadLetterItem as _WDLI
    org_id: int | None = getattr(user, "org_id", None)
    if org_id is None:
        raise HTTPException(status_code=400, detail="User has no org")

    from sqlalchemy import func as _safunc2
    total = session.exec(
        select(_safunc2.count()).select_from(WebhookDeadLetter)
        .where(WebhookDeadLetter.org_id == org_id)
    ).one()
    items = list(session.exec(
        select(WebhookDeadLetter)
        .where(WebhookDeadLetter.org_id == org_id)
        .order_by(WebhookDeadLetter.created_at.desc())  # type: ignore[arg-type]
        .offset(offset).limit(limit)
    ).all())

    return WebhookDeadLetterListResponse(
        items=[
            _WDLI(
                id=r.id,
                org_id=r.org_id,
                error_summary=r.error_summary,
                retry_count=r.retry_count,
                created_at=r.created_at,
            )
            for r in items
        ],
        total=total,
    )


# ── Phase 3.14 — SIEM export endpoint ────────────────────────────────────────

@app.get("/guard/history/export")
async def guard_history_export(
    request: Request,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    limit: int = Query(default=1000, ge=1, le=5000),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> Response:
    """Export org-scoped guard scan history as JSON or CSV (Phase 3.14)."""
    from .models import GuardScanRecord, User as _User
    from sqlalchemy import desc

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid API key")

    _plan = normalize_plan(getattr(user, "plan", None))
    if not allow_export_for(_plan):
        raise HTTPException(
            status_code=403,
            detail={"type": "plan_limit_exceeded", "message": f"Export is not available on the '{_plan}' plan."},
        )

    _, _org_id, _is_admin = get_request_user_org(request, session)
    q = select(GuardScanRecord).order_by(desc(GuardScanRecord.created_at)).limit(limit)
    if _is_admin:
        pass  # admin sees all
    elif _org_id is not None:
        q = q.where(GuardScanRecord.org_id == _org_id)
    else:
        q = q.where(GuardScanRecord.user_id == user.id)
    rows = session.exec(q).all()

    fields = ["id", "created_at", "decision", "severity", "categories",
              "signature_hash", "risk_score", "elapsed_ms", "blocked"]

    def _row_dict(r: GuardScanRecord) -> dict:
        return {
            "id": r.id,
            "created_at": str(r.created_at),
            "decision": r.decision,
            "severity": r.severity,
            "categories": json.loads(r.categories_json or "[]"),
            "signature_hash": r.signature_hash,
            "risk_score": r.risk_score,
            "elapsed_ms": r.elapsed_ms,
            "blocked": r.blocked,
        }

    if format == "json":
        return JSONResponse([_row_dict(r) for r in rows])

    # CSV
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for r in rows:
        d = _row_dict(r)
        d["categories"] = "|".join(d["categories"])  # flatten list for CSV
        writer.writerow(d)
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=guard_export.csv"},
    )


@app.post("/test-llm", response_model=TestLLMResponse)
async def test_llm(
    payload: TestLLMRequest,
    _: None = Depends(require_admin_key),
    _rl: None = Depends(require_rate_limit),
) -> TestLLMResponse:
    """Run a small battery of simulated prompt-injection tests against the provided system prompt."""
    simulated_tests = simulate_attacks(system_prompt=payload.system_prompt, model=payload.model)
    overall_score, summary, annotated_tests = analyze_risk(
        system_prompt=payload.system_prompt,
        tests=simulated_tests,
    )
    return TestLLMResponse(
        risk_score=overall_score,
        summary=summary,
        tests=annotated_tests,
    )


@app.post("/campaigns", response_model=CampaignCreateResponse)
async def create_campaign(
    payload: CampaignCreateRequest,
    request: Request,
    response: Response,
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _demo: None = Depends(require_not_demo),
    _role: object = Depends(require_min_role("analyst")),
    _rl: None = Depends(require_rate_limit_campaigns),
    user: object = Depends(get_current_user),
) -> CampaignCreateResponse:
    """Enqueue a new long-running campaign."""
    from .models import User as UserModel
    plan = get_user_plan(session, x_api_key)
    if payload.iterations > max_iterations_for(plan):
        raise HTTPException(
            status_code=403,
            detail={
                "type": "plan_limit_exceeded",
                "message": (
                    f"Your '{plan}' plan allows at most "
                    f"{max_iterations_for(plan)} iterations per campaign."
                ),
            },
        )
    if isinstance(user, UserModel):
        allowed, remaining = enforce_campaign_iterations(
            session, user.id, user.plan, payload.iterations
        )
        if not allowed:
            ym = current_period_ym()
            limit = plan_quotas(user.plan).campaign_iterations
            raise HTTPException(
                status_code=429,
                detail={"type": "quota_exceeded", "message": "Monthly quota exceeded"},
                headers={
                    "X-Quota-Limit": str(limit),
                    "X-Quota-Remaining": str(remaining),
                    "X-Quota-Period": ym,
                },
            )

    # Phase 1.3 — plan-based monthly campaigns_started limit
    if isinstance(user, UserModel):
        _plan_tier = resolve_plan_tier(user.plan)
        _period = current_period()
        _guard_lim, _camp_lim = get_monthly_limits(_plan_tier)
        if _camp_lim is not None:
            _gs, _cs = (
                org_total_usage(session, _period, user.org_id)
                if user.org_id
                else read_usage(session, _period, user.id)
            )
            if _cs >= _camp_lim:
                raise PlanLimitError(
                    code="campaigns_started_limit",
                    message=f"Monthly campaign limit ({_camp_lim}) reached. Upgrade to Pro for unlimited campaigns.",
                    plan=_plan_tier,
                    period=_period,
                    guard_scans=_gs,
                    campaigns_started=_cs,
                    guard_limit=_guard_lim,
                    campaigns_limit=_camp_lim,
                )

    # E6 — Org-scoped OrgUsageMonth campaign quota: check + increment BEFORE enqueue.
    _, _caller_org_id, _ = get_request_user_org(request, session)
    if isinstance(user, UserModel) and _caller_org_id is not None:
        _org_plan = resolve_plan_tier(user.plan)
        increment_campaign(session, _caller_org_id, _org_plan)
        # increment_campaign raises HTTPException(402) if limit exceeded.

    # Set campaign quota response headers
    try:
        from .models import OrgUsageMonth as _OUM2
        _c_plan = normalize_plan(user.plan) if isinstance(user, UserModel) else "public"
        _c_ym   = current_ym()
        _c_clim = limits_for_plan(_c_plan)["campaigns"]
        if isinstance(user, UserModel) and _caller_org_id is not None:
            _c_row = session.exec(
                select(_OUM2)
                .where(_OUM2.org_id == _caller_org_id)
                .where(_OUM2.ym == _c_ym)
            ).first()
            _c_used = _c_row.campaigns_created if _c_row else 0
        else:
            _c_used = 0
        response.headers["X-Plan"]                  = _c_plan
        response.headers["X-Usage-Period"]           = _c_ym
        response.headers["X-Campaign-Limit"]         = str(_c_clim) if _c_clim != -1 else "unlimited"
        response.headers["X-Campaign-Used"]          = str(_c_used)
        response.headers["X-Campaign-Remaining"]     = str(max(0, _c_clim - _c_used)) if _c_clim != -1 else "unlimited"
    except Exception:
        pass

    if payload.categories:
        allowed = [c for c in payload.categories if c in campaign_service.ATTACK_CATEGORIES]
    else:
        allowed = list(campaign_service.ATTACK_CATEGORIES)
    if not allowed:
        allowed = list(campaign_service.ATTACK_CATEGORIES)

    from .models import Campaign
    campaign = Campaign(
        system_prompt=payload.system_prompt,
        model=payload.model,
        iterations_total=payload.iterations,
        iterations_done=0,
        status=CampaignStatus.QUEUED.value,
        metrics_json=json.dumps(campaign_service.ensure_metrics({})),
        org_id=_caller_org_id,   # E4 — stamp org on creation
    )
    session.add(campaign)
    session.commit()
    session.refresh(campaign)

    if isinstance(user, UserModel):
        incr_campaign_iterations(session, user.id, payload.iterations)
        try:
            bump_usage(session, org_id=getattr(user, "org_id", None), user_id=user.id, field="campaigns_started", plan=user.plan)
        except Exception:
            pass

    uid = user.id if isinstance(user, UserModel) else None
    log_event(session, "campaign_created", uid, {
        "campaign_id": campaign.id,
        "iterations": payload.iterations,
        "categories_count": len(allowed),
    })

    asyncio.create_task(campaign_service.start_campaign(campaign.id, allowed))
    return CampaignCreateResponse(campaign_id=campaign.id, status=CampaignStatus.QUEUED)


# (F) Diff report — must be registered before {campaign_id} routes.
@app.get("/campaigns/diff")
async def diff_campaigns(
    request: Request,
    left_id: int = Query(...),
    right_id: int = Query(...),
    session: Session = Depends(get_session),
    _: None = Depends(require_api_key),
    _rl: None = Depends(require_rate_limit_campaigns),
) -> Response:
    """Compare two campaigns and return risk deltas."""
    _, _org_id, _is_admin = get_request_user_org(request, session)
    left = campaign_service.get_campaign_or_none(session, left_id)
    if left is None:
        raise HTTPException(status_code=404, detail=f"Campaign {left_id} not found")
    right = campaign_service.get_campaign_or_none(session, right_id)
    if right is None:
        raise HTTPException(status_code=404, detail=f"Campaign {right_id} not found")
    _check_campaign_org(left, _org_id, _is_admin)
    _check_campaign_org(right, _org_id, _is_admin)

    lm = _decode_metrics(left.metrics_json)
    rm = _decode_metrics(right.metrics_json)

    def _delta(key: str) -> float:
        return float(rm.get(key, 0) or 0) - float(lm.get(key, 0) or 0)

    l_cat: Dict[str, float] = lm.get("category_avg_risk", {}) or {}
    r_cat: Dict[str, float] = rm.get("category_avg_risk", {}) or {}
    all_cats = sorted(set(l_cat) | set(r_cat))
    category_deltas = {
        c: round(float(r_cat.get(c, 0)) - float(l_cat.get(c, 0)), 2)
        for c in all_cats
    }
    top_changes = sorted(category_deltas.items(), key=lambda x: abs(x[1]), reverse=True)[:5]

    result = {
        "left_id": left_id,
        "right_id": right_id,
        "overall_delta": {
            "max_risk": _delta("max_risk"),
            "avg_risk": round(_delta("avg_risk"), 2),
        },
        "category_deltas": category_deltas,
        "top_category_changes": [{"category": c, "delta": d} for c, d in top_changes],
    }
    return Response(
        content=json.dumps(result, ensure_ascii=False),
        media_type="application/json",
    )


def _decode_metrics(raw: str) -> Dict:
    if not raw:
        return campaign_service.public_metrics({})
    try:
        data = json.loads(raw)
        return campaign_service.public_metrics(data)
    except Exception:
        return campaign_service.public_metrics({})


def _check_campaign_org(campaign: Any, caller_org_id: int | None, is_admin: bool) -> None:
    """Raise 404 if *caller_org_id* does not match *campaign.org_id* (E4).

    Rules:
    - Admin key → always allowed.
    - Either side has no org_id (legacy/public rows) → skip check.
    - Both have org_id and they differ → 404 (do not leak existence).
    """
    if is_admin:
        return
    c_org: int | None = getattr(campaign, "org_id", None)
    if c_org is None or caller_org_id is None:
        return
    if c_org != caller_org_id:
        raise HTTPException(status_code=404, detail="Campaign not found")


def _finding_to_redacted_dict(f: Any) -> Dict[str, Any]:
    """Convert a Finding ORM object to a redacted dict for API/export output."""
    d: Dict[str, Any] = {
        "id": f.id,
        "campaign_id": f.campaign_id,
        "iteration": f.iteration,
        "category": f.category,
        "attack_prompt": f.attack_prompt,
        "llm_response": f.llm_response,
        "leakage_detected": f.leakage_detected,
        "override_detected": f.override_detected,
        "risk_score": f.risk_score,
        "notes": f.notes,
        "created_at": f.created_at.isoformat() if f.created_at else None,
        "turn_count": f.turn_count,
        "transform_name": f.transform_name,
        "confidence_score": f.confidence_score,
    }
    return redact_finding_dict(d)


@app.get("/campaigns/{campaign_id}", response_model=CampaignStatusResponse)
async def get_campaign(
    campaign_id: int,
    request: Request,
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> CampaignStatusResponse:
    """Retrieve high-level status and metrics for a campaign."""
    campaign = campaign_service.get_campaign_or_none(session, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    _, _org_id, _is_admin = get_request_user_org(request, session)
    _check_campaign_org(campaign, _org_id, _is_admin)

    progress = (
        float(campaign.iterations_done) / float(campaign.iterations_total)
        if campaign.iterations_total else 0.0
    )
    metrics = _decode_metrics(campaign.metrics_json)
    status = CampaignStatus(campaign.status)

    return CampaignStatusResponse(
        campaign_id=campaign.id,
        status=status,
        iterations_total=campaign.iterations_total,
        iterations_done=campaign.iterations_done,
        progress=progress,
        metrics=metrics,
        error_message=campaign.error_message,
    )


@app.get("/campaigns/{campaign_id}/findings", response_model=PaginatedFindingsResponse)
async def list_campaign_findings(
    campaign_id: int,
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    min_risk: int = Query(0, ge=0, le=100),
    sort: str = Query("desc", pattern="^(asc|desc)$"),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit_campaigns),
) -> PaginatedFindingsResponse:
    """List findings for a campaign with pagination and risk filtering."""
    campaign = campaign_service.get_campaign_or_none(session, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    _, _org_id, _is_admin = get_request_user_org(request, session)
    _check_campaign_org(campaign, _org_id, _is_admin)

    data = campaign_service.get_findings_for_campaign(
        session=session,
        campaign_id=campaign_id,
        page=page,
        page_size=page_size,
        min_risk=min_risk,
        sort_desc=(sort == "desc"),
    )

    raw_items = data["items"]
    total = int(data["total"])

    # Redact sensitive data in response.
    items = []
    for item in raw_items:
        fr = FindingResponse.model_validate(item, from_attributes=True)
        fr.llm_response = redact_string(fr.llm_response) or fr.llm_response
        fr.notes = redact_string(fr.notes)
        items.append(fr)

    return PaginatedFindingsResponse(items=items, page=page, page_size=page_size, total=total)


@app.post("/campaigns/{campaign_id}/stop", response_model=CampaignStatusResponse)
async def stop_campaign(
    campaign_id: int,
    request: Request,
    session: Session = Depends(get_session),
    _demo: None = Depends(require_not_demo),
    _role: object = Depends(require_min_role("analyst")),
    _rl: None = Depends(require_rate_limit_campaigns),
) -> CampaignStatusResponse:
    """Request that a running campaign stop after its current iteration."""
    campaign = campaign_service.get_campaign_or_none(session, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    _, _org_id, _is_admin = get_request_user_org(request, session)
    _check_campaign_org(campaign, _org_id, _is_admin)

    if campaign.status not in {
        CampaignStatus.COMPLETED.value,
        CampaignStatus.FAILED.value,
        CampaignStatus.STOPPED.value,
    }:
        campaign.status = CampaignStatus.STOPPED.value
        session.add(campaign)
        session.commit()
        session.refresh(campaign)

    progress = (
        float(campaign.iterations_done) / float(campaign.iterations_total)
        if campaign.iterations_total else 0.0
    )
    metrics = _decode_metrics(campaign.metrics_json)
    status = CampaignStatus(campaign.status)

    return CampaignStatusResponse(
        campaign_id=campaign.id,
        status=status,
        iterations_total=campaign.iterations_total,
        iterations_done=campaign.iterations_done,
        progress=progress,
        metrics=metrics,
        error_message=campaign.error_message,
    )


@app.get("/campaigns/{campaign_id}/export")
async def export_campaign(
    campaign_id: int,
    request: Request,
    format: str = Query("json", pattern="^(json|csv)$"),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("analyst")),
    _rl: None = Depends(require_rate_limit_campaigns),
    user: object = Depends(get_current_user),
) -> Response:
    """Export full campaign data (metrics + all findings) as JSON or CSV with enrichment."""
    plan = get_user_plan(session, x_api_key)
    if not allow_export_for(plan):
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "type": "plan_limit_exceeded",
                    "message": f"Campaign export is not available on the '{plan}' plan.",
                }
            },
        )

    campaign = campaign_service.get_campaign_or_none(session, campaign_id)
    if campaign is None:
        raise HTTPException(status_code=404, detail="Campaign not found")
    _, _org_id, _is_admin = get_request_user_org(request, session)
    _check_campaign_org(campaign, _org_id, _is_admin)

    findings: List = campaign_service.get_all_findings_for_campaign(session, campaign_id)
    metrics = _decode_metrics(campaign.metrics_json)

    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        columns = [
            "iteration", "category", "risk_score",
            "leakage_detected", "override_detected",
            "attack_prompt", "llm_response", "notes", "created_at",
            "turn_count", "transform_name", "confidence_score",
        ]
        writer.writerow(columns)
        for f in findings:
            rd = _finding_to_redacted_dict(f)
            writer.writerow([
                f.iteration, f.category, f.risk_score,
                f.leakage_detected, f.override_detected,
                rd["attack_prompt"], rd["llm_response"], rd["notes"],
                f.created_at.isoformat() if f.created_at else "",
                f.turn_count, f.transform_name, f.confidence_score,
            ])
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="promptsentinel_campaign_{campaign_id}.csv"',
            },
        )

    # JSON export with enrichment (E).
    progress = (
        float(campaign.iterations_done) / float(campaign.iterations_total)
        if campaign.iterations_total else 0.0
    )
    finding_dicts = [_finding_to_redacted_dict(f) for f in findings]

    # Summary enrichment.
    risk_trend = [{"iteration": f.iteration, "risk": f.risk_score} for f in findings]

    sorted_by_risk = sorted(findings, key=lambda f: f.risk_score, reverse=True)
    top_findings = [_finding_to_redacted_dict(f) for f in sorted_by_risk[:5]]

    cat_risk: Dict[str, List[int]] = {}
    for f in findings:
        cat_risk.setdefault(f.category, []).append(f.risk_score)
    top_categories = sorted(
        (c for c in cat_risk.keys() if cat_risk[c]),  # guard against empty lists (ZeroDivisionError)
        key=lambda c: sum(cat_risk[c]) / len(cat_risk[c]),
        reverse=True,
    )

    summary = {
        "top_categories": top_categories,
        "top_findings": top_findings,
        "risk_trend": risk_trend,
    }

    payload = {
        "campaign_id": campaign.id,
        "status": campaign.status,
        "iterations_total": campaign.iterations_total,
        "iterations_done": campaign.iterations_done,
        "progress": progress,
        "metrics": metrics,
        "findings": finding_dicts,
        "summary": summary,
    }
    return Response(
        content=json.dumps(payload, ensure_ascii=False),
        media_type="application/json",
    )


@app.post("/auth/signup", response_model=TokenResponse, status_code=201)
async def auth_signup(
    payload: SignupRequest,
    session: Session = Depends(get_session),
    _demo: None = Depends(require_not_demo),
) -> TokenResponse:
    """Register a new user with email + password. Returns a session token."""
    import secrets
    from sqlalchemy.exc import IntegrityError
    from .auth import hash_password, create_session_token
    from .models import User

    user = User(
        email=payload.email,
        api_key=secrets.token_urlsafe(32),
        password_hash=hash_password(payload.password),
    )
    session.add(user)
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        raise HTTPException(status_code=409, detail="Email already registered")
    session.refresh(user)
    token = create_session_token(user.id, session)
    return TokenResponse(token=token)


@app.post("/auth/login-password", response_model=TokenResponse)
async def auth_login_password(
    payload: PasswordLoginRequest,
    session: Session = Depends(get_session),
    _demo: None = Depends(require_not_demo),
) -> TokenResponse:
    """Authenticate with email + password (legacy). Returns a session token."""
    from .auth import verify_password, create_session_token
    from .models import User

    user = session.exec(select(User).where(User.email == payload.email)).first()
    if user is None or not user.is_active or not user.password_hash:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_session_token(user.id, session)
    return TokenResponse(token=token)


@app.post("/auth/login", response_model=LoginResponse)
async def auth_magic_login(
    payload: LoginRequest,
    session: Session = Depends(get_session),
    _demo: None = Depends(require_not_demo),
    _rl: None = Depends(require_rate_limit),
) -> LoginResponse:
    """Initiate magic-link login.

    Behaviour:
    - SMTP configured → sends email, returns ``{ok: true}`` (no token).
    - SMTP absent + DEV_LOGIN=1 → returns ``{ok: true, dev_token: <token>}``.
    - SMTP absent + DEV_LOGIN=0 → 503 email_unavailable.
    """
    raw_token = create_login_token(session, payload.email)
    cfg = get_settings()

    if smtp_configured():
        base_url = cfg["public_base_url"].rstrip("/")
        link = f"{base_url}/login?token={raw_token}"
        try:
            send_magic_link(payload.email, link)
        except MailError as exc:
            logger.error("magic-link send failed: %s", exc)
            raise HTTPException(
                status_code=503,
                detail={"type": "email_unavailable", "message": "Failed to send email"},
            )
        return LoginResponse(ok=True)

    if cfg["dev_login"]:
        return LoginResponse(ok=True, dev_token=raw_token)

    return JSONResponse(
        {"error": {"type": "email_unavailable", "message": "Email not configured"}},
        status_code=503,
    )


@app.post("/auth/redeem", response_model=RedeemResponse)
async def auth_redeem(
    payload: RedeemRequest,
    session: Session = Depends(get_session),
    _demo: None = Depends(require_not_demo),
) -> RedeemResponse:
    """Consume a magic-link token and return the user's API key."""
    try:
        user = redeem_login_token(session, payload.token)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return RedeemResponse(api_key=user.api_key, email=user.email, plan=user.plan)


# ── PHASE 2.39 — billing guardrails ──────────────────────────────────────────

def _billing_guard_pro(user: object, db: Session) -> JSONResponse | None:
    """Return a 409 JSONResponse if the user (or their org) is already on Pro.

    Call at the top of every checkout endpoint before hitting Stripe.
    Returns None if the user is eligible to upgrade.
    """
    from .models import User as _BUser, Organization as _BOrg
    if not isinstance(user, _BUser):
        return None
    plan = user.plan
    if plan != "pro" and user.org_id is not None:
        org = db.get(_BOrg, user.org_id)
        if org is not None and org.plan == "pro":
            plan = "pro"
    if plan == "pro":
        return JSONResponse(
            {"error": {"type": "already_subscribed",
                       "message": "Your account already has an active Pro subscription.",
                       "code": "already_pro"}},
            status_code=409,
        )
    return None


@app.post("/billing/checkout")
async def billing_checkout(
    session: Session = Depends(get_session),
    _demo: None = Depends(require_not_demo),
    _role: object = Depends(require_min_role("owner")),
    user: object = Depends(get_current_user),
) -> JSONResponse:
    """Create a Stripe Checkout session for Pro plan upgrade."""
    if not get_settings()["stripe_secret_key"]:
        return JSONResponse(
            {"error": {"type": "billing_unavailable", "message": "Stripe not configured"}},
            status_code=503,
        )
    from .models import User as UserModel
    if not isinstance(user, UserModel):
        raise HTTPException(status_code=403, detail="User account required for billing")
    _guard = _billing_guard_pro(user, session)
    if _guard is not None:
        return _guard
    try:
        url = create_checkout_url(user, session)
    except StripeMissingError:
        return JSONResponse(
            {"error": {"type": "billing_unavailable", "message": "Stripe not installed"}},
            status_code=501,
        )
    return JSONResponse({"url": url})


@app.post("/billing/checkout-session")
async def billing_checkout_session(
    request: Request,
    session: Session = Depends(get_session),
    _demo: None = Depends(require_not_demo),
    _role: object = Depends(require_min_role("owner")),
    user: object = Depends(get_current_user),
) -> JSONResponse:
    """Create a Stripe Checkout session for Pro upgrade. Returns checkout_url + session_id."""
    if not get_settings()["stripe_secret_key"]:
        return JSONResponse(
            {"error": {"type": "billing_unavailable", "message": "Stripe not configured"}},
            status_code=503,
        )
    from .models import User as UserModel
    if not isinstance(user, UserModel):
        raise HTTPException(status_code=403, detail="User account required for billing")
    _guard = _billing_guard_pro(user, session)
    if _guard is not None:
        return _guard
    try:
        result = create_checkout_session(user, session)
    except StripeMissingError:
        return JSONResponse(
            {"error": {"type": "billing_unavailable", "message": "Stripe not installed"}},
            status_code=501,
        )
    log_event(session, "billing_checkout_created", user.id, {
        "session_id": result.get("session_id", ""),
    }, ip=request.client.host if request.client else None)
    return JSONResponse(result)


@app.post("/billing/checkout/pro")
async def billing_checkout_pro(
    request: Request,
    session: Session = Depends(get_session),
    _demo: None = Depends(require_not_demo),
    _role: object = Depends(require_min_role("owner")),
    user: object = Depends(get_current_user),
) -> JSONResponse:
    """Canonical upgrade endpoint — returns only checkout_url. No Stripe SDK version leak."""
    if not get_settings()["stripe_secret_key"]:
        return JSONResponse(
            {"error": {"type": "billing_unavailable", "message": "Stripe not configured"}},
            status_code=503,
        )
    from .models import User as UserModel
    if not isinstance(user, UserModel):
        raise HTTPException(status_code=403, detail="User account required for billing")
    _guard = _billing_guard_pro(user, session)
    if _guard is not None:
        return _guard
    try:
        result = create_checkout_session(user, session)
    except StripeMissingError:
        return JSONResponse(
            {"error": {"type": "billing_unavailable", "message": "Stripe not installed"}},
            status_code=501,
        )
    log_event(session, "billing_checkout_created", user.id, {
        "session_id": result.get("session_id", ""),
        "via": "checkout/pro",
    }, ip=request.client.host if request.client else None)
    return JSONResponse({"checkout_url": result["checkout_url"]})


@app.post("/billing/portal-session")
async def billing_portal_session(
    request: Request,
    session: Session = Depends(get_session),
    _demo: None = Depends(require_not_demo),
    _role: object = Depends(require_min_role("owner")),
    user: object = Depends(get_current_user),
) -> JSONResponse:
    """Create a Stripe Customer Portal session for the current user."""
    if not get_settings()["stripe_secret_key"]:
        return JSONResponse(
            {"error": {"type": "billing_unavailable", "message": "Stripe not configured"}},
            status_code=503,
        )
    from .models import User as UserModel
    if not isinstance(user, UserModel):
        raise HTTPException(status_code=403, detail="User account required for billing")
    try:
        result = create_portal_session(user)
    except StripeMissingError:
        return JSONResponse(
            {"error": {"type": "billing_unavailable", "message": "Stripe not installed"}},
            status_code=501,
        )
    log_event(session, "billing_portal_created", user.id, {"user_id": user.id},
              ip=request.client.host if request.client else None)
    return JSONResponse(result)


@app.post("/billing/webhook", response_model=WebhookAck)
async def billing_webhook(
    request: Request,
    session: Session = Depends(get_session),
) -> JSONResponse:
    """Public Stripe webhook — no API-key auth, verified by Stripe-Signature."""
    if not get_settings()["stripe_secret_key"]:
        return JSONResponse(
            {"error": {"type": "billing_unavailable", "message": "Stripe not configured"}},
            status_code=503,
        )
    raw_body = await request.body()
    sig_header = request.headers.get("stripe-signature", "")
    try:
        result = handle_webhook(raw_body, sig_header)
    except StripeMissingError:
        return JSONResponse(
            {"error": {"type": "billing_unavailable", "message": "Stripe not installed"}},
            status_code=501,
        )
    # Audit subscription changes using the already-verified body (no re-verification needed).
    try:
        evt = json.loads(raw_body)
        evt_type: str = evt.get("type", "")
        if evt_type in (
            "customer.subscription.updated",
            "customer.subscription.created",
            "customer.subscription.deleted",
        ):
            from .billing import plan_from_subscription_status
            from .models import User as _User
            obj = evt.get("data", {}).get("object", {})
            stripe_status = obj.get("status", "")
            plan = plan_from_subscription_status(stripe_status)
            customer_id = obj.get("customer", "")
            matched = session.exec(
                select(_User).where(_User.stripe_customer_id == customer_id)
            ).first() if customer_id else None
            log_event(session, "billing_subscription_updated", matched.id if matched else None, {
                "stripe_status": stripe_status,
                "plan": plan,
                "stripe_event_type": evt_type,
            })
    except Exception:
        pass  # audit must never crash the webhook ack
    return JSONResponse(result)


@app.get("/billing/upgrade-banner", response_model=UpgradeBannerResponse)
async def upgrade_banner(
    request: Request,
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> UpgradeBannerResponse:
    """Single endpoint for UI upgrade-banner logic.

    show=True when plan != 'pro' AND any of:
      - scans_remaining <= 20
      - campaigns_remaining <= 2
      - scans_pct >= 0.80 or campaigns_pct >= 0.80

    reason: 'limit_reached'       – remaining == 0 for either resource
            'near_limit'          – remaining low or pct >= 80 %
            'plan_feature_locked' – plan is 'public' (always show to nudge signup)
            ''                    – show=False
    """
    from .models import User as _User

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Valid user API key required")

    _, _org_id, _ = get_request_user_org(request, session)
    bucket_org_id: int = _org_id if _org_id is not None else -(user.id)

    plan = resolve_plan_tier(user.plan)
    ym = current_ym()
    row = get_or_create_usage(session, bucket_org_id, ym)
    lim = limits_for_plan(plan)

    s_limit = lim["guard_scans"]
    c_limit = lim["campaigns"]
    s_used = row.guard_scans
    c_used = row.campaigns_created
    s_rem = max(0, s_limit - s_used)
    c_rem = max(0, c_limit - c_used)
    s_pct = round(s_used / s_limit, 4) if s_limit > 0 else 0.0
    c_pct = round(c_used / c_limit, 4) if c_limit > 0 else 0.0

    show = False
    reason = ""
    if plan != "pro":
        if s_rem == 0 or c_rem == 0:
            show, reason = True, "limit_reached"
        elif s_rem <= 20 or c_rem <= 2 or s_pct >= 0.80 or c_pct >= 0.80:
            show, reason = True, "near_limit"
        elif plan == "public":
            show, reason = True, "plan_feature_locked"

    return UpgradeBannerResponse(
        show=show,
        reason=reason,
        plan=plan,
        ym=ym,
        scans_used=s_used,
        scans_limit=s_limit,
        scans_remaining=s_rem,
        campaigns_used=c_used,
        campaigns_limit=c_limit,
        campaigns_remaining=c_rem,
        scans_pct=s_pct,
        campaigns_pct=c_pct,
    )


@app.get("/threats/trend", response_model=OrgThreatTrendResponse)
async def threats_trend(
    request: Request,
    days: int = Query(default=7, ge=1, le=30),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> OrgThreatTrendResponse:
    """Org-scoped SOC analytics: daily scan breakdown, top categories, campaigns per day.

    ``days`` must be 7 or 30 (anything else → 422).
    Org members share a single view; solo users see their own data.
    """
    from .models import GuardScanRecord, Campaign as _Campaign, User as _User
    from datetime import datetime as _dt, timedelta, timezone as tz

    if days not in (7, 30):
        raise HTTPException(status_code=422, detail="days must be 7 or 30")

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Valid API key required")

    _, _org_id, _is_admin = get_request_user_org(request, session)

    now = _dt.now(tz.utc)
    window_start = now - timedelta(days=days)
    today = now.date()
    date_range = [
        (today - timedelta(days=i)).isoformat()
        for i in range(days - 1, -1, -1)
    ]

    # ── Guard scan rows ───────────────────────────────────────────────────────
    scan_q = select(GuardScanRecord).where(GuardScanRecord.created_at >= window_start)
    if not _is_admin:
        if _org_id is not None:
            scan_q = scan_q.where(GuardScanRecord.org_id == _org_id)
        else:
            scan_q = scan_q.where(GuardScanRecord.user_id == user.id)
    scans = session.exec(scan_q).all()

    # Daily decision buckets
    scan_buckets: dict[str, dict[str, int]] = {
        d: {"total": 0, "allow": 0, "warn": 0, "block": 0} for d in date_range
    }
    cat_counts: dict[str, int] = {}
    for r in scans:
        day = str(r.created_at)[:10]
        if day in scan_buckets:
            scan_buckets[day]["total"] += 1
            dec = r.decision if r.decision in ("allow", "warn", "block") else "allow"
            scan_buckets[day][dec] += 1
        try:
            for cat in json.loads(r.categories_json or "[]"):
                cat_counts[str(cat)] = cat_counts.get(str(cat), 0) + 1
        except Exception:
            pass

    scans_per_day = [
        DailyCount(
            day=d,
            total=scan_buckets[d]["total"],
            allow=scan_buckets[d]["allow"],
            warn=scan_buckets[d]["warn"],
            block=scan_buckets[d]["block"],
        )
        for d in date_range
    ]
    top_categories: list[dict[str, int]] = [
        {k: v}
        for k, v in sorted(cat_counts.items(), key=lambda x: -x[1])[:10]
    ]

    # ── Campaign rows ─────────────────────────────────────────────────────────
    camp_q = select(_Campaign).where(_Campaign.created_at >= window_start)
    if not _is_admin:
        if _org_id is not None:
            camp_q = camp_q.where(_Campaign.org_id == _org_id)
        else:
            camp_q = camp_q.where(_Campaign.org_id == None)  # noqa: E711
    camps = session.exec(camp_q).all()

    camp_buckets: dict[str, int] = {d: 0 for d in date_range}
    for c in camps:
        day = str(c.created_at)[:10]
        if day in camp_buckets:
            camp_buckets[day] += 1
    campaigns_per_day: list[dict[str, int]] = [{d: camp_buckets[d]} for d in date_range]

    return OrgThreatTrendResponse(
        days=days,
        scans=scans_per_day,
        top_categories=top_categories,
        campaigns_per_day=campaigns_per_day,
        total_scans=len(scans),
        total_campaigns=len(camps),
    )


@app.get("/threats/top", response_model=List[ThreatSignatureItem])
async def threats_top(
    limit: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
) -> List[ThreatSignatureItem]:
    """Return top attack signatures ordered by count desc, last_seen_at desc."""
    from .models import AttackSignature
    from sqlalchemy import desc

    rows = session.exec(
        select(AttackSignature)
        .order_by(desc(AttackSignature.count), desc(AttackSignature.last_seen_at))
        .limit(limit)
    ).all()

    return [
        ThreatSignatureItem(
            signature_hash=r.signature_hash,
            count=r.count,
            top_category=r.top_category,
            first_seen_at=r.first_seen_at,
            last_seen_at=r.last_seen_at,
            example_snippet=r.example_snippet,
        )
        for r in rows
    ]


@app.get("/threats/clusters", response_model=ThreatClusterListResponse)
async def threats_clusters(
    limit: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> ThreatClusterListResponse:
    """Threat clusters from ThreatCluster table, sorted by count DESC then last_seen_at DESC (PHASE 2.15)."""
    from .models import ThreatCluster
    from sqlalchemy import desc

    rows = session.exec(
        select(ThreatCluster)
        .order_by(desc(ThreatCluster.member_count), desc(ThreatCluster.updated_at))
        .limit(limit)
    ).all()

    items = [
        ThreatClusterItem(
            cluster_id=r.centroid_hash,
            first_seen_at=r.created_at,
            last_seen_at=r.updated_at,
            count=r.member_count,
            top_category=r.top_category,
            example_signature_hash=r.example_signature_hash,
            example_snippet=r.example_snippet,
        )
        for r in rows
    ]
    return ThreatClusterListResponse(clusters=items, total=len(items))


# ── Phase 3.15 — Sketch cluster endpoints ────────────────────────────────────

@app.get("/threats/clusters/top", response_model=List[SketchClusterItem])
async def threats_clusters_top(
    limit: int = Query(20, ge=1, le=100),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> List[SketchClusterItem]:
    """Top sketch-based threat clusters by member_count (Phase 3.15)."""
    from .models import ThreatCluster
    from sqlalchemy import desc

    rows = session.exec(
        select(ThreatCluster)
        .order_by(desc(ThreatCluster.member_count), desc(ThreatCluster.updated_at))
        .limit(limit)
    ).all()

    return [
        SketchClusterItem(
            centroid_hash=r.centroid_hash,
            member_count=r.member_count,
            top_category=r.top_category,
            first_seen_at=r.created_at,
            last_seen_at=r.updated_at,
            example_snippet=r.example_snippet,
        )
        for r in rows
    ]


# ── Phase ADVANCED — Signature Graph Mapping ─────────────────────────────────

@app.get("/threats/graph", response_model=ThreatGraphResponse)
async def threats_graph(
    limit: int = Query(100, ge=1, le=500, description="Max clusters to include as nodes"),
    threshold: float = Query(
        0.30, ge=0.0, le=1.0,
        description="Minimum Jaccard similarity required to draw an edge between two clusters",
    ),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> ThreatGraphResponse:
    """Return the threat-cluster adjacency graph.

    **Nodes** — top *limit* ThreatCluster rows ordered by member_count desc.

    **Edges** — undirected pairs whose Jaccard similarity on tokenised
    ``example_snippet`` is >= *threshold*.  The default threshold (0.30) is
    intentionally lower than the cluster-assignment threshold (0.55), so edges
    reveal *related-but-distinct* clusters rather than near-duplicates.

    The response can be fed directly into graph-visualisation libraries
    (e.g. D3 force-graph, Cytoscape.js).

    Query params
    ------------
    limit     — 1–500, default 100
    threshold — 0.0–1.0, default 0.30
    """
    from .models import ThreatCluster
    from .cluster import build_cluster_graph
    from sqlalchemy import desc

    rows = session.exec(
        select(ThreatCluster)
        .order_by(desc(ThreatCluster.member_count), desc(ThreatCluster.updated_at))
        .limit(limit)
    ).all()

    nodes_raw, edges_raw = build_cluster_graph(list(rows), threshold=threshold)

    nodes = [ThreatGraphNode(**n) for n in nodes_raw]
    edges = [ThreatGraphEdge(**e) for e in edges_raw]

    return ThreatGraphResponse(
        nodes=nodes,
        edges=edges,
        threshold=threshold,
        node_count=len(nodes),
        edge_count=len(edges),
    )


# ── Phase ENTERPRISE — SIEM Export ───────────────────────────────────────────

@app.get("/threats/feed")
async def threats_feed(
    format: str = Query(
        "json",
        pattern="^(cef|json)$",
        description="Output format: 'json' (structured) or 'cef' (ArcSight CEF v25)",
    ),
    hours: int = Query(
        24, ge=1, le=168,
        description="Lookback window in hours (1–168, default 24)",
    ),
    min_severity: str = Query(
        "low",
        pattern="^(low|medium|high|critical)$",
        description="Minimum severity to include: low | medium | high | critical",
    ),
    limit: int = Query(
        1000, ge=1, le=10000,
        description="Maximum number of events to return (1–10 000)",
    ),
    syslog: bool = Query(
        False,
        description="CEF only — prepend RFC-5424 syslog header to each line",
    ),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
):
    """SIEM-ready threat event feed.

    Returns recent ``GuardScanRecord`` events ordered newest-first.

    **JSON format** (``format=json``) — returns ``application/json``
    with a ``ThreatFeedResponse`` envelope.  Suitable for polling by
    Splunk HEC, Elastic Logstash, or any REST-capable SIEM ingestor.

    **CEF format** (``format=cef``) — returns ``text/plain``, one
    ArcSight CEF v25 line per event.  Each line is self-contained and
    can be piped directly into ``logger``, forwarded via UDP syslog, or
    ingested by ArcSight SmartConnector.

    **Syslog wrapping** (``syslog=true``, CEF only) — prepends an
    RFC-5424 priority header to every CEF line, making output suitable
    for direct delivery to rsyslog / syslog-ng / Splunk UF:

        <34>1 2026-03-05T12:00:00Z host PromptSentinel - - - CEF:0|...

    Query parameters
    ----------------
    format       cef | json   (default: json)
    hours        1–168        (default: 24)
    min_severity low | medium | high | critical  (default: low)
    limit        1–10 000     (default: 1 000)
    syslog       true | false  (default: false; CEF only)
    """
    from .models import GuardScanRecord
    from .siem import record_to_cef, record_to_dict, filter_min_severity
    from datetime import datetime as _dt, timedelta, timezone as _tz

    cutoff = _dt.now(_tz.utc) - timedelta(hours=hours)

    _feed_org_id = getattr(_role, "org_id", None)
    q = (
        select(GuardScanRecord)
        .where(GuardScanRecord.created_at >= cutoff)
        .order_by(GuardScanRecord.created_at.desc())
        .limit(limit)
    )
    if _feed_org_id is not None:
        q = q.where(GuardScanRecord.org_id == _feed_org_id)
    rows = session.exec(q).all()

    # Apply severity filter
    rows = filter_min_severity(list(rows), min_severity)

    # ── CEF output ────────────────────────────────────────────────────────────
    if format == "cef":
        lines = [record_to_cef(r, syslog=syslog) for r in rows]
        body = "\n".join(lines)
        if body:
            body += "\n"
        return Response(content=body, media_type="text/plain; charset=utf-8")

    # ── JSON output ───────────────────────────────────────────────────────────
    events = [ThreatFeedItem(**record_to_dict(r)) for r in rows]
    return ThreatFeedResponse(
        format="json",
        hours=hours,
        min_severity=min_severity,
        total=len(events),
        events=events,
    )


@app.get("/audit/logs")
async def get_audit_logs(
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
    user: object = Depends(get_current_user),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> dict:
    """Return AuditLog rows scoped to the caller's org (or user for solo accounts).

    Params
    ------
    days    How far back to look (1–90, default 7).
    limit   Max rows returned (1–500, default 100).
    offset  Pagination offset.
    """
    from .models import AuditLog, User as _User
    from .schemas import AuditLogItem, AuditLogResponse
    from datetime import datetime, timezone, timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Scope: org members see the whole org's log; solo users see only their own.
    org_id: int | None = getattr(user, "org_id", None) if isinstance(user, _User) else None
    user_id: int | None = getattr(user, "id", None) if isinstance(user, _User) else None

    q = select(AuditLog).where(AuditLog.created_at >= cutoff)
    if org_id is not None:
        q = q.where(AuditLog.org_id == org_id)
    elif user_id is not None:
        q = q.where(AuditLog.user_id == user_id)
    else:
        return {"logs": [], "total": 0, "days": days}

    total = len(session.exec(q).all())
    rows = session.exec(
        q.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit)
    ).all()

    import json as _json
    logs = [
        AuditLogItem(
            id=r.id,
            created_at=r.created_at,
            org_id=r.org_id,
            user_id=r.user_id,
            action=r.action,
            resource_type=r.resource_type,
            resource_id=r.resource_id,
            metadata=_json.loads(r.metadata_json or "{}"),
        )
        for r in rows
    ]
    return AuditLogResponse(logs=logs, total=total, days=days).model_dump()


@app.get("/audit/events", response_model=AuditEventListResponse)
async def get_audit_events(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    event_type: str | None = Query(default=None),
    days: int = Query(default=7, ge=1, le=90),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> AuditEventListResponse:
    """Paginated audit event list scoped to the caller's org (or user).

    Admin key sees all rows; authenticated org members see only their org's rows.
    """
    from .models import AuditEvent, User as _User
    from datetime import datetime as _dt, timedelta, timezone as _tz
    from sqlalchemy import desc, func as _sfunc

    _empty = AuditEventListResponse(items=[], total=0, page=page, page_size=page_size)

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        return _empty

    admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
    is_admin = bool(admin_key and x_api_key == admin_key)

    cutoff = _dt.now(_tz.utc) - timedelta(days=days)
    _, org_id, _ = get_request_user_org(request, session)

    filters = [AuditEvent.created_at >= cutoff]
    if not is_admin:
        if org_id is not None:
            filters.append(AuditEvent.org_id == org_id)
        else:
            filters.append(AuditEvent.user_id == user.id)
    if event_type:
        filters.append(AuditEvent.event_type == event_type)

    count_q = select(_sfunc.count(AuditEvent.id))
    for f in filters:
        count_q = count_q.where(f)
    total: int = session.execute(count_q).scalar_one()

    offset = (page - 1) * page_size
    row_q = select(AuditEvent)
    for f in filters:
        row_q = row_q.where(f)
    rows = session.exec(
        row_q.order_by(desc(AuditEvent.created_at)).offset(offset).limit(page_size)
    ).all()

    items = []
    for r in rows:
        try:
            meta = json.loads(r.metadata_json or "{}")
        except Exception:
            meta = {}
        items.append(AuditEventItem(
            id=r.id,
            created_at=r.created_at,
            org_id=r.org_id,
            user_id=r.user_id,
            event_type=r.event_type,
            resource_type=getattr(r, "resource_type", None),
            resource_id=getattr(r, "resource_id", None),
            metadata=meta,
        ))

    return AuditEventListResponse(items=items, total=total, page=page, page_size=page_size)


@app.get("/audit/export")
async def audit_export(
    request: Request,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    limit: int = Query(default=1000, ge=1, le=5000),
    days: int = Query(default=30, ge=1, le=90),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
):
    """Export recent AuditEvent rows for the caller's org as JSON or CSV."""
    from .models import AuditEvent, User as _User
    from datetime import datetime as _dt, timedelta, timezone as _tz

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication required")

    _plan = normalize_plan(getattr(user, "plan", None))
    if not allow_export_for(_plan):
        raise HTTPException(
            status_code=403,
            detail={"type": "plan_limit_exceeded", "message": f"Export is not available on the '{_plan}' plan."},
        )

    _, org_id, _ = get_request_user_org(request, session)
    cutoff = _dt.now(_tz.utc) - timedelta(days=days)

    q = select(AuditEvent).where(AuditEvent.created_at >= cutoff)
    if org_id is not None:
        q = q.where(AuditEvent.org_id == org_id)
    else:
        q = q.where(AuditEvent.user_id == user.id)
    rows = session.exec(
        q.order_by(AuditEvent.created_at.desc()).limit(limit)
    ).all()

    records = []
    for r in rows:
        try:
            meta = json.loads(r.metadata_json or "{}")
        except Exception:
            meta = {}
        records.append({
            "id": r.id,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "org_id": r.org_id,
            "user_id": r.user_id,
            "event_type": r.event_type,
            "resource_type": getattr(r, "resource_type", None),
            "resource_id": getattr(r, "resource_id", None),
            "metadata": meta,
        })

    if format == "csv":
        import io, csv as _csv
        buf = io.StringIO()
        writer = _csv.DictWriter(buf, fieldnames=[
            "id", "created_at", "org_id", "user_id",
            "event_type", "resource_type", "resource_id", "metadata",
        ])
        writer.writeheader()
        for rec in records:
            rec["metadata"] = json.dumps(rec["metadata"])
            writer.writerow(rec)
        return Response(
            content=buf.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=audit_export.csv"},
        )

    return JSONResponse({"total": len(records), "rows": records})


@app.get("/analytics/models")
async def analytics_models(
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    user: object = Depends(get_current_user),
    _rl: None = Depends(require_rate_limit),
) -> dict:
    """Org-scoped model risk profiles sorted by sample_count DESC (PHASE 2.0)."""
    from .models import User as _UserM
    from .model_risk import list_model_profiles as _lmp
    from .schemas import ModelRiskProfileItem, ModelRiskProfileResponse

    _org_id = getattr(user, "org_id", None) if isinstance(user, _UserM) else None
    rows = _lmp(session, _org_id)

    profiles = [
        ModelRiskProfileItem(
            model_name=r.model_name,
            org_id=r.org_id,
            sample_count=r.sample_count,
            avg_risk_score=round(r.avg_risk_score, 2),
            avg_consensus_score=round(r.avg_consensus_score, 2),
            block_rate=round(r.block_rate, 4),
            warn_rate=round(r.warn_rate, 4),
            updated_at=r.updated_at,
        )
        for r in rows
    ]
    return ModelRiskProfileResponse(profiles=profiles, total=len(profiles)).model_dump()


@app.get("/analytics/clusters", response_model=List[ClusterTrendPoint])
async def analytics_clusters(
    days: int = Query(default=7, ge=1, le=90),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    user: object = Depends(get_current_user),
    _rl: None = Depends(require_rate_limit),
) -> List[ClusterTrendPoint]:
    """Daily unique sketch_cluster_id count + total scans (org-scoped, Phase 3.15)."""
    from .models import GuardScanRecord, User as _User
    from datetime import datetime, timezone, timedelta

    days = max(1, min(days, 90))
    org_id: int | None = getattr(user, "org_id", None) if isinstance(user, _User) else None
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    q = select(GuardScanRecord).where(GuardScanRecord.created_at >= cutoff)
    if org_id is not None:
        q = q.where(GuardScanRecord.org_id == org_id)
    rows = session.exec(q).all()

    today = datetime.now(timezone.utc).date()
    dates = [(today - timedelta(days=i)).isoformat() for i in range(days - 1, -1, -1)]
    daily_scans: dict[str, int] = {d: 0 for d in dates}
    daily_clusters: dict[str, set[str]] = {d: set() for d in dates}

    for r in rows:
        day = str(r.created_at)[:10]
        if day not in daily_scans:
            continue
        daily_scans[day] += 1
        if r.sketch_cluster_id:
            daily_clusters[day].add(r.sketch_cluster_id)

    return [
        ClusterTrendPoint(
            date=d,
            unique_clusters=len(daily_clusters[d]),
            total_scans=daily_scans[d],
        )
        for d in dates
    ]


@app.get("/analytics/threat-trend", response_model=ThreatTrendsResponse)
async def threat_trend(
    days: int = Query(default=7, ge=1, le=30),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> ThreatTrendsResponse:
    """Daily scan + block volume and top categories over a rolling window."""
    from .models import GuardScanRecord
    from datetime import datetime, timezone, timedelta

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    _trend_org_id = getattr(_role, "org_id", None)
    _trend_q = select(GuardScanRecord).where(GuardScanRecord.created_at >= cutoff)
    if _trend_org_id is not None:
        _trend_q = _trend_q.where(GuardScanRecord.org_id == _trend_org_id)
    rows = session.exec(_trend_q).all()

    # Aggregate per calendar day (UTC)
    daily: dict[str, dict[str, int]] = {}
    cat_totals: dict[str, int] = {}
    for r in rows:
        day = str(r.created_at)[:10]   # "YYYY-MM-DD" from stored naive-UTC datetime
        bucket = daily.setdefault(day, {"scans": 0, "blocked": 0})
        bucket["scans"] += 1
        if r.blocked:
            bucket["blocked"] += 1
        for cat in json.loads(r.categories_json or "[]"):
            cat_totals[cat] = cat_totals.get(cat, 0) + 1

    # Build ordered points list, filling gaps with zeros
    today = datetime.now(timezone.utc).date()
    points = [
        TrendPoint(
            date=(today - timedelta(days=i)).isoformat(),
            scans=daily.get((today - timedelta(days=i)).isoformat(), {}).get("scans", 0),
            blocked=daily.get((today - timedelta(days=i)).isoformat(), {}).get("blocked", 0),
        )
        for i in range(days - 1, -1, -1)
    ]

    return ThreatTrendsResponse(window_days=days, points=points, top_categories=cat_totals)


@app.get("/analytics/signatures/top", response_model=List[ThreatSignatureItem])
async def analytics_signatures_top(
    days: int = Query(default=7, ge=1, le=30),
    limit: int = Query(default=20, ge=1, le=100),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> List[ThreatSignatureItem]:
    """Top attack signatures last seen within the rolling window, ordered by count."""
    from .models import AttackSignature
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import desc

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = session.exec(
        select(AttackSignature)
        .where(AttackSignature.last_seen_at >= cutoff)
        .order_by(desc(AttackSignature.count), desc(AttackSignature.last_seen_at))
        .limit(limit)
    ).all()

    return [
        ThreatSignatureItem(
            signature_hash=r.signature_hash,
            count=r.count,
            top_category=r.top_category,
            first_seen_at=r.first_seen_at,
            last_seen_at=r.last_seen_at,
            example_snippet=r.example_snippet,
        )
        for r in rows
    ]


@app.get("/analytics/guard/overview", response_model=ThreatAnalyticsResponse)
async def guard_analytics_overview(
    days: int = Query(default=7, ge=1, le=90),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    user: object = Depends(get_current_user),
    _rl: None = Depends(require_rate_limit),
) -> ThreatAnalyticsResponse:
    """Combined threat analytics: daily trend + top categories + top signatures (Phase 3.11).

    Org-scoped: only scans attributed to the caller's org are counted.
    """
    from .models import GuardScanRecord, AttackSignature, User as UserModel
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import desc

    days = max(1, min(days, 90))
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Org-scope filter
    org_id: int | None = getattr(user, "org_id", None) if isinstance(user, UserModel) else None
    q = select(GuardScanRecord).where(GuardScanRecord.created_at >= cutoff)
    if org_id is not None:
        q = q.where(GuardScanRecord.org_id == org_id)
    rows = session.exec(q).all()

    # Daily aggregation
    daily: dict[str, dict[str, int]] = {}
    cat_totals: dict[str, int] = {}
    for r in rows:
        day = str(r.created_at)[:10]
        bucket = daily.setdefault(day, {"scans": 0, "blocked": 0})
        bucket["scans"] += 1
        if r.blocked:
            bucket["blocked"] += 1
        for cat in json.loads(r.categories_json or "[]"):
            cat_totals[cat] = cat_totals.get(cat, 0) + 1

    today = datetime.now(timezone.utc).date()
    points = [
        TrendPoint(
            date=(today - timedelta(days=i)).isoformat(),
            scans=daily.get((today - timedelta(days=i)).isoformat(), {}).get("scans", 0),
            blocked=daily.get((today - timedelta(days=i)).isoformat(), {}).get("blocked", 0),
        )
        for i in range(days - 1, -1, -1)
    ]

    # Top 10 categories
    top_cats = dict(sorted(cat_totals.items(), key=lambda x: x[1], reverse=True)[:10])

    # Top 10 signatures in window
    sig_rows = session.exec(
        select(AttackSignature)
        .where(AttackSignature.last_seen_at >= cutoff)
        .order_by(desc(AttackSignature.count), desc(AttackSignature.last_seen_at))
        .limit(10)
    ).all()
    top_sigs = [
        ThreatSignatureItem(
            signature_hash=r.signature_hash,
            count=r.count,
            top_category=r.top_category,
            first_seen_at=r.first_seen_at,
            last_seen_at=r.last_seen_at,
            example_snippet=r.example_snippet,
        )
        for r in sig_rows
    ]

    return ThreatAnalyticsResponse(
        window_days=days,
        points=points,
        top_categories=top_cats,
        top_signatures=top_sigs,
    )


# ── Phase 3.12.A — Anomaly Detection ─────────────────────────────────────────

# ── Phase 3.12.A — Deep Anomaly Detection ────────────────────────────────────

@app.get("/analytics/anomalies", response_model=AnomalyResponse)
async def analytics_anomalies(
    days: int = Query(default=30, ge=1, le=90),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    user: object = Depends(get_current_user),
    _rl: None = Depends(require_rate_limit),
) -> AnomalyResponse:
    """Rolling-baseline Z-score anomaly detection (Phase 3.12.A).

    Checks: scans, block_rate, top-5 categories.
    Returns only warning/critical rows — normal days omitted.
    """
    from .models import User as UserModel
    from .analytics import compute_daily_series, detect_anomalies, top_categories_in_window

    days = max(1, min(days, 90))
    org_id: int | None = getattr(user, "org_id", None) if isinstance(user, UserModel) else None

    try:
        metrics = ["scans", "block_rate"] + [
            f"category:{c}"
            for c in top_categories_in_window(session, org_id, days, top_n=5)
        ]

        all_anomalies: list[AnomalyItem] = []
        for metric in metrics:
            series = compute_daily_series(session, org_id, metric, days)
            all_anomalies.extend(detect_anomalies(series, metric, days))

        # Sort: critical first, then by date desc
        all_anomalies.sort(key=lambda x: (x.severity != "critical", x.date), reverse=False)
    except Exception:
        logger.warning("analytics_anomalies: computation error", exc_info=True)
        all_anomalies = []

    return AnomalyResponse(window_days=days, anomalies=all_anomalies)


# ── PHASE 2.22 — Guard Performance Analytics ──────────────────────────────────

@app.get("/analytics/performance", response_model=PerformanceAnalyticsResponse)
async def analytics_performance(
    days: int = Query(default=7, ge=1, le=90),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    user: object = Depends(get_current_user),
    _rl: None = Depends(require_rate_limit),
) -> PerformanceAnalyticsResponse:
    """Latency and per-stage timing breakdown for guard scans in the window."""
    import json as _json
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    from .models import GuardScanRecord as _GSR, User as _UserM

    _org_id: int | None = getattr(user, "org_id", None) if isinstance(user, _UserM) else None
    _user_id: int | None = getattr(user, "id", None) if isinstance(user, _UserM) else None

    _since = _dt.now(_tz.utc) - _td(days=days)
    _q = select(_GSR).where(_GSR.created_at >= _since)
    if _org_id is not None:
        _q = _q.where(_GSR.org_id == _org_id)
    elif _user_id is not None:
        _q = _q.where(_GSR.user_id == _user_id)
    _scans = session.exec(_q).all()

    _total = len(_scans)
    if _total == 0:
        return PerformanceAnalyticsResponse(
            window_days=days, total_scans=0,
            avg_elapsed_ms=0.0, p95_elapsed_ms=0.0, slow_scan_count=0,
        )

    _latencies = sorted(int(r.elapsed_ms or 0) for r in _scans)
    _avg_ms = round(sum(_latencies) / _total, 2)
    _p95_idx = max(0, int(len(_latencies) * 0.95) - 1)
    _p95_ms = float(_latencies[_p95_idx])
    _slow = sum(1 for ms in _latencies if ms > 50)

    # Average per-stage timings across scans that carry stage_timings_json
    _stage_sums: dict[str, float] = {}
    _stage_counts: dict[str, int] = {}
    for r in _scans:
        try:
            for stage, ms in _json.loads(r.stage_timings_json or "{}").items():
                _stage_sums[stage] = _stage_sums.get(stage, 0.0) + float(ms)
                _stage_counts[stage] = _stage_counts.get(stage, 0) + 1
        except Exception:
            pass
    _avg_stages = {
        s: round(_stage_sums[s] / _stage_counts[s], 2) for s in _stage_sums
    }

    return PerformanceAnalyticsResponse(
        window_days=days,
        total_scans=_total,
        avg_elapsed_ms=_avg_ms,
        p95_elapsed_ms=_p95_ms,
        slow_scan_count=_slow,
        avg_stage_timings=_avg_stages,
    )


# ── PHASE 2.28 — Executive / Investor Monthly Summary ─────────────────────────

@app.get("/analytics/executive-summary", response_model=ExecutiveSummaryResponse)
async def analytics_executive_summary(
    ym: str = Query(
        default=None,
        pattern=r"^\d{4}-\d{2}$",
        description="Report month YYYY-MM (defaults to current month)",
    ),
    session: Session = Depends(get_session),
    _: None = Depends(require_admin_key),
    _rl: None = Depends(require_rate_limit),
) -> ExecutiveSummaryResponse:
    """Concise monthly summary for non-technical stakeholders. PHASE 2.28.

    Aggregates guard scans, campaigns, threat signatures, and active orgs
    for the given month. All counters default to safe zeros when no data exists.
    """
    import json as _json
    from datetime import datetime as _dt, timezone as _tz
    from calendar import monthrange as _mr
    from .models import GuardScanRecord as _GSR, AttackSignature as _AS, Campaign as _Camp
    from .usage import current_ym as _cym

    # ── Parse month window ────────────────────────────────────────────────────
    _period = ym or _cym()
    try:
        _year, _mon = int(_period[:4]), int(_period[5:7])
        _start = _dt(_year, _mon, 1, tzinfo=_tz.utc)
        _end   = _dt(_year, _mon, _mr(_year, _mon)[1], 23, 59, 59, tzinfo=_tz.utc)
    except (ValueError, IndexError):
        raise HTTPException(status_code=422, detail="ym must be YYYY-MM")

    # ── Guard scans ───────────────────────────────────────────────────────────
    _scans = session.exec(
        select(_GSR).where(_GSR.created_at >= _start, _GSR.created_at <= _end)
    ).all()
    _total   = len(_scans)
    _blocked = sum(1 for r in _scans if r.decision == "block")
    _warned  = sum(1 for r in _scans if r.decision == "warn")
    _block_rate = round(_blocked / _total, 4) if _total > 0 else 0.0
    _avg_ms = round(sum(r.elapsed_ms for r in _scans) / _total, 2) if _total > 0 else 0.0

    # ── Top categories ────────────────────────────────────────────────────────
    _cat_counts: dict[str, int] = {}
    for r in _scans:
        for cat in _json.loads(r.categories_json or "[]"):
            _cat_counts[cat] = _cat_counts.get(cat, 0) + 1
    _top_cats = dict(sorted(_cat_counts.items(), key=lambda x: x[1], reverse=True)[:5])

    # ── Top signatures (global registry, not month-scoped) ────────────────────
    _top_sigs = [
        {"hash": s.signature_hash, "count": s.count, "category": s.top_category}
        for s in session.exec(select(_AS).order_by(_AS.count.desc()).limit(5)).all()
    ]

    # ── Active orgs + campaigns for the month ─────────────────────────────────
    _active_org_count = len({r.org_id for r in _scans if r.org_id is not None})
    _total_campaigns = len(session.exec(
        select(_Camp).where(_Camp.created_at >= _start, _Camp.created_at <= _end)
    ).all())

    # ── Deterministic summary text ────────────────────────────────────────────
    _top_cat = max(_top_cats, key=lambda k: _top_cats[k]) if _top_cats else "none"
    _summary_text = (
        f"In {_period} PromptSentinel processed {_total:,} requests, "
        f"blocked {_blocked:,} threats ({round(_block_rate * 100, 1)}% block rate), "
        f"and the most common threat category was {_top_cat}."
    )

    return ExecutiveSummaryResponse(
        month=_period,
        total_scans=_total,
        blocked_scans=_blocked,
        warn_scans=_warned,
        block_rate=_block_rate,
        avg_elapsed_ms=_avg_ms,
        top_categories=_top_cats,
        top_signatures=_top_sigs,
        active_org_count=_active_org_count,
        total_campaigns=_total_campaigns,
        summary_text=_summary_text,
    )


# ── Phase 3.12.B — Cross-Org Emerging Threats ────────────────────────────────

@app.get("/analytics/emerging", response_model=EmergingThreatResponse)
async def analytics_emerging(
    days: int = Query(default=7, ge=1, le=90),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> EmergingThreatResponse:
    """Top 10 cross-org threat fingerprints by scan count in window (Phase 3.12.B).

    Global (not org-scoped) — fingerprints carry no raw data.
    """
    from .models import ThreatFingerprint
    from datetime import date, timedelta
    from sqlalchemy import desc

    cutoff = date.today() - timedelta(days=days)
    rows = session.exec(
        select(ThreatFingerprint)
        .where(ThreatFingerprint.day >= cutoff)
        .order_by(desc(ThreatFingerprint.count))
        .limit(10)
    ).all()

    return EmergingThreatResponse(
        window_days=days,
        threats=[
            EmergingThreatItem(
                fingerprint=r.fingerprint,
                day=r.day.isoformat(),
                count=r.count,
                top_category=r.top_category,
            )
            for r in rows
        ],
    )


# ── ADVANCED — Attacker Behavior Profiling ────────────────────────────────────

@app.get("/analytics/attackers", response_model=AttackerProfileResponse)
async def analytics_attackers(
    min_score: int = Query(default=30, ge=1, le=100, description="Minimum attacker_pattern_score to include"),
    days: int = Query(default=7, ge=1, le=90, description="Look-back window in days"),
    limit: int = Query(default=20, ge=1, le=100),
    session: Session = Depends(get_session),
    user: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> AttackerProfileResponse:
    """Top attackers ranked by max attacker_pattern_score.

    Org-scoped: only returns identities (user_id / org_id) that belong to
    the caller's org (or the caller's own user_id for individual users).
    Returns max/avg score, scan count, last seen, and dominant signals.
    """
    from .models import GuardScanRecord, User as _User
    from sqlalchemy import func as _func, desc as _desc
    from datetime import datetime as _dt, timedelta, timezone as _tz

    cutoff = _dt.now(_tz.utc) - timedelta(days=days)

    # Determine identity scope
    caller_org_id: int | None = getattr(user, "org_id", None)
    caller_user_id: int | None = getattr(user, "id", None)

    stmt = (
        select(
            GuardScanRecord.user_id,
            GuardScanRecord.org_id,
            _func.max(GuardScanRecord.attacker_pattern_score).label("max_score"),
            _func.avg(GuardScanRecord.attacker_pattern_score).label("avg_score"),
            _func.count(GuardScanRecord.id).label("scan_count"),
            _func.max(GuardScanRecord.created_at).label("last_seen_at"),
        )
        .where(
            GuardScanRecord.attacker_pattern_score >= min_score,
            GuardScanRecord.created_at >= cutoff,
        )
    )

    # Org-scope filter
    if caller_org_id is not None:
        stmt = stmt.where(GuardScanRecord.org_id == caller_org_id)
    elif caller_user_id is not None:
        stmt = stmt.where(GuardScanRecord.user_id == caller_user_id)

    stmt = (
        stmt
        .group_by(GuardScanRecord.user_id, GuardScanRecord.org_id)
        .order_by(_desc("max_score"))
        .limit(limit)
    )

    rows = session.exec(stmt).all()  # type: ignore[call-overload]
    total = len(rows)

    # For each top-attacker identity, fetch the scan with max score to get signals
    items: list[AttackerProfileItem] = []
    for row in rows:
        uid, oid = row.user_id, row.org_id
        # Fetch the highest-scored scan record to extract dominant signals
        top_record = session.exec(
            select(GuardScanRecord)
            .where(
                GuardScanRecord.attacker_pattern_score == int(row.max_score),
                GuardScanRecord.created_at >= cutoff,
                *([GuardScanRecord.user_id == uid] if uid is not None else [GuardScanRecord.org_id == oid]),
            )
            .limit(1)
        ).first()

        # Derive dominant signals from attacker_pattern_score value itself (heuristic)
        dominant: list[str] = []
        if top_record:
            score = top_record.attacker_pattern_score
            # Approximate signal breakdown: variant > 0 if score >= 20, encoding if >= 15, nearmiss if >= 15
            # (exact signals not stored on record — use threshold heuristics)
            if score >= 20:
                dominant.append("rapid_variant_mutation")
            if score >= 35:
                dominant.append("encoding_cycling")
            if score >= 15:
                dominant.append("near_miss_attacks")

        items.append(AttackerProfileItem(
            user_id=uid,
            org_id=oid,
            max_score=int(row.max_score),
            avg_score=round(float(row.avg_score), 1),
            scan_count=int(row.scan_count),
            last_seen_at=row.last_seen_at,
            dominant_signals=dominant,
        ))

    return AttackerProfileResponse(
        items=items,
        total=total,
        min_score_threshold=min_score,
    )


# ── PHASE 2.26 — Attack Pattern Events ───────────────────────────────────────

@app.get("/analytics/attack-patterns", response_model=AttackerPatternMetricResponse)
async def analytics_attack_patterns(
    days: int = Query(default=7, ge=1, le=90),
    limit: int = Query(default=50, ge=1, le=200),
    pattern_type: str | None = Query(default=None, description="Filter by pattern_type"),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    user: object = Depends(get_current_user),
    _rl: None = Depends(require_rate_limit),
) -> AttackerPatternMetricResponse:
    """Recent per-signal attacker pattern events from the AttackerPatternMetric table.

    Org-scoped: only returns rows belonging to the caller's org (or user).
    """
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    from .models import AttackerPatternMetric as _APM, User as _UserM

    _org_id: int | None = getattr(user, "org_id", None) if isinstance(user, _UserM) else None
    _user_id: int | None = getattr(user, "id", None) if isinstance(user, _UserM) else None

    _since = _dt.now(_tz.utc) - _td(days=days)
    _q = select(_APM).where(_APM.created_at >= _since)
    if _org_id is not None:
        _q = _q.where(_APM.org_id == _org_id)
    elif _user_id is not None:
        _q = _q.where(_APM.user_id == _user_id)
    if pattern_type:
        _q = _q.where(_APM.pattern_type == pattern_type)
    _q = _q.order_by(_APM.created_at.desc()).limit(limit)
    _rows = session.exec(_q).all()

    return AttackerPatternMetricResponse(
        items=[
            AttackerPatternMetricItem(
                id=r.id,
                created_at=r.created_at,
                org_id=r.org_id,
                user_id=r.user_id,
                pattern_type=r.pattern_type,
                score=r.score,
                metadata_json=r.metadata_json,
            )
            for r in _rows
        ],
        total=len(_rows),
        window_days=days,
    )


# ── PHASE 2.29 — Security Scorecard ──────────────────────────────────────────

@app.get("/analytics/scorecard", response_model=SecurityScorecardResponse)
async def analytics_scorecard(
    days: int = Query(default=30, ge=1, le=90),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    user: object = Depends(get_current_user),
    _rl: None = Depends(require_rate_limit),
) -> SecurityScorecardResponse:
    """Deterministic security scorecard for the calling user's org.

    Three signals:
    - **exposure_score** (0–100): scan volume + attacker pattern intensity
    - **control_maturity_score** (0–100): org config flags (strict mode, zero-trust, webhook)
    - **threat_pressure_score** (0–100): block rate + attack category diversity

    Overall grade A→F derived from weighted composite of all three.
    """
    import json as _json
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    from .models import Organization as _Org, GuardScanRecord as _GSR, OrgWebhook as _OW, User as _UserM

    _org_id: int | None = getattr(user, "org_id", None) if isinstance(user, _UserM) else None
    _user_id: int | None = getattr(user, "id", None) if isinstance(user, _UserM) else None

    _since = _dt.now(_tz.utc) - _td(days=days)
    factors: list[str] = []

    # ── control_maturity_score ───────────────────────────────────────────────
    maturity = 10  # base — minimal posture
    _org = session.get(_Org, _org_id) if _org_id else None
    if _org is not None:
        if _org.strict_mode:
            maturity += 25
            factors.append("Strict mode enabled (+25)")
        if _org.zero_trust_mode:
            maturity += 30
            factors.append("Zero-trust mode enabled (+30)")
        _wh = session.exec(select(_OW).where(_OW.org_id == _org_id)).first()
        if _wh and _wh.is_active:
            maturity += 20
            factors.append("SIEM webhook active (+20)")
    maturity = min(100, maturity)

    # ── fetch scan window ────────────────────────────────────────────────────
    _sq = select(_GSR).where(_GSR.created_at >= _since)
    if _org_id is not None:
        _sq = _sq.where(_GSR.org_id == _org_id)
    elif _user_id is not None:
        _sq = _sq.where(_GSR.user_id == _user_id)
    _rows = list(session.exec(_sq).all())
    _total = len(_rows)

    # ── exposure_score ───────────────────────────────────────────────────────
    exposure = 0
    if _total > 0:
        _vol_pts = min(40, _total // 5)          # 5 scans ≈ 1 pt, capped at 40
        _ap_vals = [r.attacker_pattern_score or 0 for r in _rows if (r.attacker_pattern_score or 0) > 0]
        _ap_pts = int(min(60, (sum(_ap_vals) / max(len(_ap_vals), 1)) * 0.6)) if _ap_vals else 0
        exposure = min(100, _vol_pts + _ap_pts)
        if exposure >= 60:
            factors.append(f"High exposure: {_total} scans, mean attacker score {int(sum(_ap_vals)/max(len(_ap_vals),1))}")
        elif exposure >= 30:
            factors.append(f"Moderate exposure: {_total} scans in window")

    # ── threat_pressure_score ────────────────────────────────────────────────
    threat_pressure = 0
    if _total > 0:
        _blocked_n = sum(1 for r in _rows if r.blocked)
        _block_rate = _blocked_n / _total
        _bp = min(50, int(_block_rate * 100 * 0.5))   # 0..50 pts
        _cats: set[str] = set()
        for r in _rows:
            try:
                _cats.update(_json.loads(r.categories_json or "[]"))
            except Exception:
                pass
        _cat_pts = min(30, len(_cats) * 5)             # 0..30 pts
        threat_pressure = min(100, _bp + _cat_pts)
        if _block_rate > 0.3:
            factors.append(f"High block rate: {_block_rate:.0%}")
        if len(_cats) >= 5:
            factors.append(f"{len(_cats)} distinct attack categories detected")

    # ── overall_grade ────────────────────────────────────────────────────────
    _composite = maturity * 0.4 + (100 - exposure) * 0.3 + (100 - threat_pressure) * 0.3
    if _composite >= 85:
        grade = "A"
    elif _composite >= 70:
        grade = "B"
    elif _composite >= 55:
        grade = "C"
    elif _composite >= 40:
        grade = "D"
    else:
        grade = "F"

    if not factors:
        factors.append("No significant risks detected")

    return SecurityScorecardResponse(
        org_id=_org_id or 0,
        exposure_score=exposure,
        control_maturity_score=maturity,
        threat_pressure_score=threat_pressure,
        overall_grade=grade,
        contributing_factors=factors,
    )


# ── PHASE 2.30 — Trust Center / Customer-Facing Status ───────────────────────

_TRUST_CAPABILITIES: list[str] = [
    "prompt_injection",
    "pii",
    "hallucination",
    "rag_injection",
    "tool_abuse",
    "threat_analytics",
]


@app.get("/trust/status", response_model=PublicTrustStatusResponse)
async def trust_status() -> PublicTrustStatusResponse:
    """Public trust / status endpoint — safe for customer-facing embeds.

    Returns only generic platform-level info.  No tenant, user, or org data
    is included.  No authentication required.
    """
    from .ratelimit import _redis as _rl_redis
    from .config import get_settings as _gs

    _s = _gs()

    # rate_limit_mode: reflect actual runtime state
    if _rl_redis is not None:
        _rl_mode = "redis"
    elif int(os.environ.get("PROMPTSENTINEL_RATE_LIMIT_PER_MIN", "0")) > 0:
        _rl_mode = "memory"
    else:
        _rl_mode = "disabled"

    return PublicTrustStatusResponse(
        service_status="ok",
        guard_enabled=True,
        billing_configured=bool(_s.get("stripe_secret_key", "")),
        rate_limit_mode=_rl_mode,
        supported_capabilities=_TRUST_CAPABILITIES,
        version=app.version,
    )


_TRUST_CAPABILITY_DESCRIPTIONS: list[dict] = [
    {"name": "prompt_injection",  "description": "Detects attempts to override system instructions or hijack LLM behaviour via adversarial user input."},
    {"name": "pii",               "description": "Identifies accidental or deliberate leakage of personally identifiable information in model outputs."},
    {"name": "hallucination",     "description": "Flags outputs that diverge factually from grounded context or contradict source material."},
    {"name": "rag_injection",     "description": "Catches adversarial content embedded in retrieval-augmented context that attempts to redirect model responses."},
    {"name": "tool_abuse",        "description": "Detects misuse of function-call and tool-use interfaces triggered by injected instructions."},
    {"name": "threat_analytics",  "description": "Aggregates attack patterns and trends across scans for org-level risk visibility and reporting."},
]


@app.get("/trust/capabilities", response_model=TrustCapabilitiesResponse)
async def trust_capabilities() -> TrustCapabilitiesResponse:
    """Public endpoint listing supported guard capabilities with descriptions.

    No authentication required.  Safe for customer-facing embeds.
    """
    return TrustCapabilitiesResponse(
        capabilities=[TrustCapabilityItem(**c) for c in _TRUST_CAPABILITY_DESCRIPTIONS]
    )


# ── PHASE 2.33 — Prompt Mutation Engine ──────────────────────────────────────

@app.post("/redteam/mutate", response_model=PromptMutationResponse)
async def redteam_mutate(
    payload: PromptMutationRequest,
    _: None = Depends(require_api_key),
    _rl: None = Depends(require_rate_limit),
) -> PromptMutationResponse:
    """Generate adversarial prompt variants from a base prompt.

    All mutations are local (no LLM calls).  When *deterministic* is True the
    output is fully stable for the same input — useful for regression testing.
    Count is capped at 50; duplicates are suppressed automatically.
    """
    from .mutation import generate_variants as _gv

    variants = _gv(
        base_prompt=payload.base_prompt,
        count=payload.count,
        deterministic=payload.deterministic,
    )
    return PromptMutationResponse(base_prompt=payload.base_prompt, variants=variants)


# ── PHASE 2.34 — Adversarial Red-Team Generator ───────────────────────────────

@app.post("/redteam/generate", response_model=RedTeamGenerateResponse)
async def redteam_generate(
    payload: RedTeamGenerateRequest,
    _: None = Depends(require_api_key),
    _rl: None = Depends(require_rate_limit),
) -> RedTeamGenerateResponse:
    """Generate a category-aware adversarial prompt set.

    Each category ships with hand-crafted seed templates that are expanded via
    the Phase 2.33 mutation engine.  Returns up to *target_count* unique prompts.
    No external LLM calls.
    """
    from .redteam_generator import SUPPORTED_CATEGORIES as _SC, generate_for_category as _gfc

    if payload.category not in _SC:
        from fastapi import HTTPException as _HTTPException
        raise _HTTPException(
            status_code=422,
            detail=f"Unsupported category {payload.category!r}. Supported: {_SC}",
        )

    prompts = _gfc(
        category=payload.category,
        target_count=payload.target_count,
        deterministic=payload.deterministic,
    )
    return RedTeamGenerateResponse(category=payload.category, prompts=prompts)


# ── ENTERPRISE — Monthly Security Report ─────────────────────────────────────

@app.get("/report/monthly", response_model=MonthlyReportResponse)
async def report_monthly(
    format: str = Query(default="json", pattern="^json$", description="Output format (only 'json' supported)"),
    month: str | None = Query(default=None, pattern=r"^\d{4}-\d{2}$", description="Report month as YYYY-MM (defaults to current month)"),
    days: int = Query(default=30, ge=7, le=90, description="Lookback window in days (7–90)"),
    cluster_limit: int = Query(default=10, ge=1, le=50, description="Max clusters to include"),
    sig_limit: int = Query(default=10, ge=1, le=50, description="Max signatures to include"),
    session: Session = Depends(get_session),
    user: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> MonthlyReportResponse:
    """Comprehensive monthly security posture report.

    Aggregates all guard-scan signals for the calling user (or their org)
    over the requested window and returns a structured JSON report covering:

    - **trends** — daily scan breakdown (allow / warn / block / block_rate)
    - **anomalies** — Z-score anomaly detection results
    - **top_clusters** — top attack clusters by member count
    - **top_signatures** — top attack signatures by hit frequency
    - **usage** — quota consumption for the billing period
    - **risk_percentile** — P50 / P75 / P90 / P95 / P99 risk distribution

    Org members see org-scoped data.  Solo users see their own data.
    """
    import bisect as _bisect
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    from sqlalchemy import func as _func
    from .models import (
        GuardScanRecord as _GSR,
        ThreatCluster as _TC,
        AttackSignature as _AS,
        MonthlyUsage as _MU,
        OrgUsageMonth as _OUM,
    )
    from .analytics import (
        compute_daily_series,
        detect_anomalies,
        compute_risk_baseline,
        compute_risk_percentiles,
        top_categories_in_window,
    )
    from .usage import current_ym as _cym, limits_for_plan

    _now = _dt.now(_tz.utc)
    period = month or _cym()

    # ── resolve caller identity ────────────────────────────────────────────
    _user_obj = user  # the User model returned by require_min_role
    _user_id: int | None = getattr(_user_obj, "id", None)
    _org_id: int | None = getattr(_user_obj, "org_id", None) or getattr(_user_obj, "default_org_id", None)
    # Use org scope when available; fall back to individual user scope
    _scope_org: int | None = _org_id
    _scope_user: int | None = None if _scope_org else _user_id

    # ─────────────────────────────────────────────────────────────────────────
    # Section 1 — Trends (daily breakdown from GuardScanRecord)
    # ─────────────────────────────────────────────────────────────────────────
    cutoff_ts = _now - _td(days=days)

    _q_trend = select(_GSR).where(_GSR.created_at >= cutoff_ts)
    if _scope_org:
        _q_trend = _q_trend.where(_GSR.org_id == _scope_org)
    elif _scope_user:
        _q_trend = _q_trend.where(_GSR.user_id == _scope_user)
    _trend_rows = session.exec(_q_trend).all()

    # Accumulate per-day counts
    _daily: dict[str, dict[str, int]] = {}
    for _r in _trend_rows:
        try:
            _day = (_r.created_at.date() if _r.created_at.tzinfo is None
                    else _r.created_at.astimezone(_tz.utc).date()).isoformat()
        except Exception:
            continue
        _d = _daily.setdefault(_day, {"total": 0, "allow": 0, "warn": 0, "block": 0})
        _d["total"] += 1
        _dec = (_r.decision or "allow").lower()
        if _dec in _d:
            _d[_dec] += 1

    # Zero-fill missing days
    for _i in range(days):
        _day_s = (_now - _td(days=_i)).date().isoformat()
        _daily.setdefault(_day_s, {"total": 0, "allow": 0, "warn": 0, "block": 0})

    _trend_points: list[ReportTrendPoint] = []
    for _day_s in sorted(_daily.keys()):
        _d = _daily[_day_s]
        _t = _d["total"]
        _blk = _d["block"]
        _trend_points.append(ReportTrendPoint(
            date=_day_s,
            total=_t,
            allow=_d["allow"],
            warn=_d["warn"],
            block=_blk,
            block_rate=round(_blk / _t, 4) if _t else 0.0,
        ))

    _total_scans  = sum(p.total for p in _trend_points)
    _total_allows = sum(p.allow for p in _trend_points)
    _total_warns  = sum(p.warn  for p in _trend_points)
    _total_blocks = sum(p.block for p in _trend_points)
    _rates = [p.block_rate for p in _trend_points if p.total > 0]
    _avg_block_rate = round(sum(_rates) / len(_rates), 4) if _rates else 0.0

    # Top categories (from GuardScanRecord.categories_json)
    _cat_counts: dict[str, int] = {}
    for _r in _trend_rows:
        try:
            _cats = json.loads(_r.categories_json or "[]")
        except Exception:
            continue
        for _c in _cats:
            _cat_counts[_c] = _cat_counts.get(_c, 0) + 1
    _top_cats = dict(
        sorted(_cat_counts.items(), key=lambda kv: kv[1], reverse=True)[:10]
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Section 2 — Anomalies (reuse analytics module)
    # ─────────────────────────────────────────────────────────────────────────
    _anomalies: list[Any] = []
    try:
        for _metric in ["scans", "block_rate"]:
            _series = compute_daily_series(session, _scope_org, _metric, days)
            _anomalies.extend(detect_anomalies(_series, _metric, days))
        # Also check top categories
        for _cat in list(_top_cats.keys())[:5]:
            _series = compute_daily_series(session, _scope_org, f"category:{_cat}", days)
            _anomalies.extend(detect_anomalies(_series, f"category:{_cat}", days))
    except Exception:
        pass
    # Deduplicate (same metric+date from multiple passes is unlikely but safe)
    _seen: set[tuple] = set()
    _unique_anomalies = []
    for _a in _anomalies:
        _key = (_a.metric, _a.date)
        if _key not in _seen:
            _seen.add(_key)
            _unique_anomalies.append(_a)
    _unique_anomalies.sort(key=lambda a: (-abs(a.z_score), a.date))
    _crit_count = sum(1 for _a in _unique_anomalies if _a.severity == "critical")

    # ─────────────────────────────────────────────────────────────────────────
    # Section 3 — Top Clusters (sketch clusters via ThreatCluster)
    # ─────────────────────────────────────────────────────────────────────────
    _cluster_q = (
        select(_TC)
        .order_by(_TC.member_count.desc(), _TC.updated_at.desc())  # type: ignore[union-attr]
        .limit(cluster_limit)
    )
    _cluster_rows = session.exec(_cluster_q).all()
    _top_clusters: list[ReportCluster] = [
        ReportCluster(
            centroid_hash=_c.centroid_hash,
            member_count=_c.member_count,
            top_category=_c.top_category,
            first_seen_at=_c.created_at,
            last_seen_at=_c.updated_at,
            example_snippet=_c.example_snippet,
        )
        for _c in _cluster_rows
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # Section 4 — Top Signatures
    # ─────────────────────────────────────────────────────────────────────────
    _sig_q = (
        select(_AS)
        .order_by(_AS.count.desc(), _AS.last_seen_at.desc())  # type: ignore[union-attr]
        .limit(sig_limit)
    )
    _sig_rows = session.exec(_sig_q).all()
    _top_sigs: list[ReportSignature] = [
        ReportSignature(
            signature_hash=_s.signature_hash,
            count=_s.count,
            top_category=_s.top_category,
            first_seen_at=_s.first_seen_at,
            last_seen_at=_s.last_seen_at,
            example_snippet=_s.example_snippet,
        )
        for _s in _sig_rows
    ]

    # ─────────────────────────────────────────────────────────────────────────
    # Section 5 — Usage
    # ─────────────────────────────────────────────────────────────────────────
    _plan_str: str = getattr(_user_obj, "plan", "free")
    if _scope_org:
        # Use org plan from Organization table
        from .models import Organization as _Org
        _org_row = session.get(_Org, _scope_org)
        if _org_row:
            _plan_str = _org_row.plan

    _limits = limits_for_plan(_plan_str)
    _g_limit = _limits.get("guard_scans", 300)
    _c_limit = _limits.get("campaigns",   20)

    # Read actual usage from MonthlyUsage (org) or OrgUsageMonth
    _g_used = 0
    _c_used = 0
    try:
        if _scope_org:
            _u_rows = session.exec(
                select(_MU).where(
                    _MU.org_id == _scope_org,
                    _MU.period_yyyymm == period,
                )
            ).all()
            _g_used = sum(r.guard_scans for r in _u_rows)
            _c_used = sum(r.campaigns_started for r in _u_rows)
        elif _scope_user:
            _u_row = session.exec(
                select(_MU).where(
                    _MU.user_id == _scope_user,
                    _MU.period_yyyymm == period,
                )
            ).first()
            if _u_row:
                _g_used = _u_row.guard_scans
                _c_used = _u_row.campaigns_started
    except Exception:
        pass

    # Unlimited plans use -1 convention
    _unlimited = _plan_str in ("pro", "enterprise")
    _g_lim_out = -1 if _unlimited else _g_limit
    _c_lim_out = -1 if _unlimited else _c_limit
    _g_rem = -1 if _unlimited else max(0, _g_limit - _g_used)
    _c_rem = -1 if _unlimited else max(0, _c_limit - _c_used)
    _g_pct = 0.0 if _unlimited else (round(_g_used / _g_limit, 4) if _g_limit else 0.0)
    _c_pct = 0.0 if _unlimited else (round(_c_used / _c_limit, 4) if _c_limit else 0.0)

    _usage = ReportUsage(
        period=period,
        plan=_plan_str,
        guard_scans_used=_g_used,
        guard_scans_limit=_g_lim_out,
        guard_scans_remaining=_g_rem,
        campaigns_used=_c_used,
        campaigns_limit=_c_lim_out,
        campaigns_remaining=_c_rem,
        guard_pct_used=_g_pct,
        campaigns_pct_used=_c_pct,
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Section 6 — Risk Percentile distribution
    # ─────────────────────────────────────────────────────────────────────────
    _mean, _std = 0.0, 0.0
    _sorted_scores: list[float] = []
    try:
        _mean, _std = compute_risk_baseline(session, _scope_org)
        _sorted_scores = compute_risk_percentiles(session, _scope_org, window_days=days)
    except Exception:
        pass

    def _pct(p: float) -> float:
        """Return the p-th percentile (0–100) of _sorted_scores, or 0.0."""
        if not _sorted_scores:
            return 0.0
        idx = p / 100 * (len(_sorted_scores) - 1)
        lo, hi = int(idx), min(int(idx) + 1, len(_sorted_scores) - 1)
        return round(_sorted_scores[lo] + (_sorted_scores[hi] - _sorted_scores[lo]) * (idx - lo), 2)

    _risk_pct = ReportRiskPercentile(
        sample_size=len(_sorted_scores),
        mean=round(_mean, 2),
        std=round(_std, 2),
        p50=_pct(50),
        p75=_pct(75),
        p90=_pct(90),
        p95=_pct(95),
        p99=_pct(99),
    )

    # ─────────────────────────────────────────────────────────────────────────
    # Assemble and return
    # ─────────────────────────────────────────────────────────────────────────
    return MonthlyReportResponse(
        generated_at=_now,
        period=period,
        window_days=days,
        format="json",
        trends=_trend_points,
        total_scans=_total_scans,
        total_allows=_total_allows,
        total_warns=_total_warns,
        total_blocks=_total_blocks,
        avg_block_rate=_avg_block_rate,
        top_categories=_top_cats,
        anomalies=_unique_anomalies,
        anomaly_count=len(_unique_anomalies),
        critical_anomaly_count=_crit_count,
        top_clusters=_top_clusters,
        top_signatures=_top_sigs,
        usage=_usage,
        risk_percentile=_risk_pct,
    )


# ── PHASE 2.5 — Enterprise Monthly Security Report ────────────────────────────

@app.get("/analytics/report/monthly", response_model=MonthlyEnterpriseReportResponse)
async def enterprise_report_monthly(
    ym: str = Query(
        default=None,
        pattern=r"^\d{4}-\d{2}$",
        description="Report month YYYY-MM (defaults to current month)",
    ),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    user: object = Depends(get_current_user),
    _rl: None = Depends(require_rate_limit),
) -> MonthlyEnterpriseReportResponse:
    """Executive monthly security report: totals, categories, signatures, model risk."""
    import json as _json
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    from calendar import monthrange as _mr
    from .models import GuardScanRecord as _GSR, AttackSignature as _AS
    from .models import ModelRiskProfile as _MRP, User as _UserM

    # ── Resolve scope ─────────────────────────────────────────────────────────
    _org_id: int | None = getattr(user, "org_id", None) if isinstance(user, _UserM) else None
    _user_id: int | None = getattr(user, "id", None) if isinstance(user, _UserM) else None

    # ── Parse month window ────────────────────────────────────────────────────
    from .usage import current_ym as _cym
    _period = ym or _cym()
    try:
        _year, _mon = int(_period[:4]), int(_period[5:7])
        _start = _dt(_year, _mon, 1, tzinfo=_tz.utc)
        _end   = _dt(_year, _mon, _mr(_year, _mon)[1], 23, 59, 59, tzinfo=_tz.utc)
    except (ValueError, IndexError):
        raise HTTPException(status_code=422, detail="ym must be YYYY-MM")

    # ── Query scan records for the month ─────────────────────────────────────
    _q = select(_GSR).where(_GSR.created_at >= _start, _GSR.created_at <= _end)
    if _org_id is not None:
        _q = _q.where(_GSR.org_id == _org_id)
    elif _user_id is not None:
        _q = _q.where(_GSR.user_id == _user_id)
    _scans = session.exec(_q).all()

    _total   = len(_scans)
    _blocked = sum(1 for r in _scans if r.decision == "block")
    _warned  = sum(1 for r in _scans if r.decision == "warn")
    _allowed = _total - _blocked - _warned   # PHASE 2.20
    _block_rate = round(_blocked / _total, 4) if _total > 0 else 0.0

    # ── Top categories ────────────────────────────────────────────────────────
    _cat_counts: dict[str, int] = {}
    for r in _scans:
        for cat in _json.loads(r.categories_json or "[]"):
            _cat_counts[cat] = _cat_counts.get(cat, 0) + 1
    _top_cats = dict(
        sorted(_cat_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    )

    # ── Top signatures (by hit count from AttackSignature registry) ───────────
    _sig_q = select(_AS).order_by(_AS.count.desc()).limit(10)
    _top_sigs = [
        {"hash": s.signature_hash, "count": s.count, "category": s.top_category}
        for s in session.exec(_sig_q).all()
    ]

    # ── Model risk summary (org-scoped) ───────────────────────────────────────
    _mrp_q = select(_MRP).where(_MRP.org_id == _org_id)
    _model_risk = [
        {
            "model_name":           r.model_name,
            "sample_count":         r.sample_count,
            "avg_risk_score":       round(r.avg_risk_score, 2),
            "avg_consensus_score":  round(r.avg_consensus_score, 2),
            "block_rate":           round(r.block_rate, 4),
            "warn_rate":            round(r.warn_rate, 4),
        }
        for r in sorted(session.exec(_mrp_q).all(),
                        key=lambda x: x.avg_risk_score, reverse=True)
    ]

    # ── PHASE 2.20 — anomaly_count (best-effort) ──────────────────────────────
    _anomaly_count: int = 0
    try:
        from .analytics import compute_daily_series, detect_anomalies
        _month_days = max(1, (_end - _start).days + 1)
        for _metric in ("scans", "block_rate"):
            _series = compute_daily_series(session, _org_id, _metric, _month_days)
            _anomaly_count += sum(
                1 for a in detect_anomalies(_series, _metric, _month_days)
                if a.severity in ("warning", "critical")
            )
    except Exception:
        pass

    # ── PHASE 2.20 — usage_summary (best-effort) ──────────────────────────────
    _usage_summary: dict = {}
    try:
        _counter = get_or_create_counter(session, _user_id, _period)
        _quotas  = plan_quotas(getattr(user, "plan", "free"))
        _usage_summary = {
            "guard_scans_used":      getattr(_counter, "guard_scans", 0),
            "guard_scans_limit":     _quotas.guard_scans,
            "campaign_runs_used":    getattr(_counter, "campaign_iterations", 0),
            "campaign_runs_limit":   _quotas.campaign_iterations,
        }
    except Exception:
        pass

    return MonthlyEnterpriseReportResponse(
        month=_period,
        org_id=_org_id,
        total_scans=_total,
        blocked_scans=_blocked,
        warn_scans=_warned,
        block_rate=_block_rate,
        top_categories=_top_cats,
        top_signatures=_top_sigs,
        model_risk_summary=_model_risk,
        allow_scans=_allowed,
        anomaly_count=_anomaly_count,
        usage_summary=_usage_summary,
    )


# ── PHASE 2.37 — Customer-Facing Trust Score / Maturity Index ────────────────

@app.get("/analytics/trust-score", response_model=TrustScoreResponse)
async def analytics_trust_score(
    days: int = Query(default=30, ge=1, le=90),
    session: Session = Depends(get_session),
    _: None = Depends(require_api_key),
    user: object = Depends(get_current_user),
) -> TrustScoreResponse:
    """Deterministic trust / maturity index for the calling user's org.

    Four dimensions (each 0–100):
    - **protection_coverage**: breadth of attack-surface monitoring
    - **control_maturity**: hardening flags (strict_mode, zero_trust, webhook)
    - **threat_pressure**: intensity of incoming attacks (higher = more threatened)
    - **response_readiness**: alerting + visibility posture

    ``trust_score`` = weighted composite; ``maturity_level`` = tier label.
    """
    import json as _json
    from datetime import datetime as _dt, timezone as _tz, timedelta as _td
    from .models import Organization as _Org, GuardScanRecord as _GSR, OrgWebhook as _OW, User as _UserM

    _org_id: int | None = getattr(user, "org_id", None) if isinstance(user, _UserM) else None
    _user_id: int | None = getattr(user, "id", None) if isinstance(user, _UserM) else None
    _since = _dt.now(_tz.utc) - _td(days=days)
    _notes: list[str] = []

    # ── control_maturity ─────────────────────────────────────────────────────
    _cm = 10  # base
    _org = session.get(_Org, _org_id) if _org_id else None
    if _org is not None:
        if _org.zero_trust_mode:
            _cm += 35
        elif _org.strict_mode:
            _cm += 25
        elif _org.strict_mode_default:
            _cm += 15
    _wh = session.exec(select(_OW).where(_OW.org_id == _org_id)).first() if _org_id else None
    if _wh and _wh.is_active:
        _cm += 20
    _cm = min(100, _cm)

    # ── fetch scan window ────────────────────────────────────────────────────
    _sq = select(_GSR).where(_GSR.created_at >= _since)
    if _org_id is not None:
        _sq = _sq.where(_GSR.org_id == _org_id)
    elif _user_id is not None:
        _sq = _sq.where(_GSR.user_id == _user_id)
    _rows = list(session.exec(_sq).all())
    _total = len(_rows)

    # ── protection_coverage ──────────────────────────────────────────────────
    _pc = 0
    if _total > 0:
        _pc += 30                                    # active scanning
        _pc += min(20, _total // 10)                 # volume bonus (1pt per 10 scans, cap 20)
        _cats: set[str] = set()
        for r in _rows:
            try:
                _cats.update(_json.loads(r.categories_json or "[]"))
            except Exception:
                pass
        _pc += min(20, len(_cats) * 5)               # category diversity (5pt each, cap 20)
        if any(c in _cats for c in ("rag_injection", "tool_abuse")):
            _pc += 15                                 # advanced vector coverage
        if _total >= 100:
            _pc += 15                                 # high-volume bonus
    _pc = min(100, _pc)

    # ── threat_pressure ──────────────────────────────────────────────────────
    _tp = 0
    if _total > 0:
        _blocked_n = sum(1 for r in _rows if r.blocked)
        _block_rate = _blocked_n / _total
        if _block_rate > 0.5:
            _tp += 30
        elif _block_rate > 0.2:
            _tp += 15
        _avg_risk = sum(r.risk_score for r in _rows) / _total
        if _avg_risk > 60:
            _tp += 25
        elif _avg_risk > 35:
            _tp += 12
        if _total > 200:
            _tp += 15
    # anomaly pressure (best-effort)
    try:
        from .analytics import compute_daily_series, detect_anomalies as _da
        for _met in ("scans", "block_rate"):
            _series = compute_daily_series(session, _org_id, _met, days)
            _crit = sum(1 for a in _da(_series, _met, days) if a.severity in ("warning", "critical"))
            _tp += min(20, _crit * 7)
    except Exception:
        pass
    _tp = min(100, _tp)

    # ── response_readiness ───────────────────────────────────────────────────
    _rr = 10  # base
    if _wh and _wh.is_active:
        _rr += 35
    if _total > 0:
        _rr += 20  # has scan data → visibility
    _recent_sq = select(_GSR).where(_GSR.created_at >= (_dt.now(_tz.utc) - _td(days=7)))
    if _org_id is not None:
        _recent_sq = _recent_sq.where(_GSR.org_id == _org_id)
    elif _user_id is not None:
        _recent_sq = _recent_sq.where(_GSR.user_id == _user_id)
    _recent_count = len(list(session.exec(_recent_sq).all()))
    if _recent_count > 0:
        _rr += 25
    if _total >= 10:
        _rr += 10
    _rr = min(100, _rr)

    # ── composite trust_score ────────────────────────────────────────────────
    _ts = round(
        0.25 * _pc
        + 0.30 * _cm
        + 0.20 * (100 - _tp)
        + 0.25 * _rr
    )
    _ts = max(0, min(100, _ts))

    # ── maturity_level ───────────────────────────────────────────────────────
    if _ts >= 76:
        _level = "hardened"
    elif _ts >= 51:
        _level = "advanced"
    elif _ts >= 26:
        _level = "developing"
    else:
        _level = "starter"

    # ── notes (top 3 gaps) ───────────────────────────────────────────────────
    _gaps: list[tuple[int, str]] = [
        (_cm, "Enable strict mode or zero-trust to improve control maturity."),
        (_pc, "Increase scan coverage — run guard scans across more attack categories."),
        (_rr, "Configure a SIEM webhook to improve response readiness."),
        (100 - _tp, "High threat pressure detected — review recent anomalies."),
    ]
    _gaps.sort(key=lambda x: x[0])  # lowest score first
    _notes = [msg for _, msg in _gaps[:3]]

    return TrustScoreResponse(
        org_id=_org_id,
        trust_score=_ts,
        maturity_level=_level,
        protection_coverage=_pc,
        control_maturity=_cm,
        threat_pressure=_tp,
        response_readiness=_rr,
        notes=_notes,
    )


# ── PHASE 2.36 — Cross-Model Consensus Engine ─────────────────────────────────

@app.post("/analytics/consensus", response_model=CrossModelConsensusResponse)
async def analytics_consensus(
    payload: CrossModelConsensusRequest,
    session: Session = Depends(get_session),
    _: None = Depends(require_api_key),
) -> CrossModelConsensusResponse:
    """Run the same input through N model labels and return a consensus risk summary.

    Each entry in ``payload.models`` is a string label (e.g. ``"gpt-4o"``,
    ``"claude-3-5-sonnet"``).  The guard pipeline is identical for every run;
    the label is used for risk-profile bookkeeping only.  Results are
    deterministic for the same input regardless of model order.
    """
    from collections import Counter as _Counter
    from .guard import run_guard_scan as _rgs
    from .model_risk import update_model_profile as _ump

    model_results: list[dict] = []

    for label in payload.models:
        result = _rgs(
            input_text=payload.input,
            output_text=payload.output,
            policy=None,
            context=payload.context,
            session=session,
        )
        if result is None:
            continue

        model_results.append({
            "model":      label,
            "decision":   result.decision,
            "severity":   result.severity,
            "risk_score": result.risk_score,
        })

        # optional: update per-model risk profile (best-effort, never raises)
        try:
            _ump(session, None, label, result.risk_score, result.consensus_score, result.decision)
        except Exception:
            pass

    if not model_results:
        return CrossModelConsensusResponse(
            models=[],
            consensus_risk=0.0,
            majority_decision="allow",
            disagreement_score=0.0,
        )

    scores = [r["risk_score"] for r in model_results]
    consensus_risk = round(sum(scores) / len(scores), 2)

    decision_counts = _Counter(r["decision"] for r in model_results)
    majority_decision = decision_counts.most_common(1)[0][0]

    n = len(model_results)
    if n == 1:
        disagreement_score = 0.0
    else:
        unique_d = len(set(r["decision"] for r in model_results))
        unique_s = len(set(r["severity"] for r in model_results))
        # normalise: (unique_d-1 + unique_s-1) / (2*(n-1)), clamped to [0, 1]
        disagreement_score = round(
            min(1.0, (unique_d - 1 + unique_s - 1) / (2 * (n - 1))),
            4,
        )

    return CrossModelConsensusResponse(
        models=model_results,
        consensus_risk=consensus_risk,
        majority_decision=majority_decision,
        disagreement_score=disagreement_score,
    )


@app.post("/guard/scan", response_model=None)  # Union[GuardScanResponse, GuardScanQueuedResponse] — response_model=None kept intentionally because FastAPI cannot discriminate Union types on runtime dispatch; response schema is validated manually in tests
async def guard_scan(
    payload: GuardScanAsyncRequest,
    request: Request,
    response: Response,
    async_mode: bool = Query(default=False, alias="async"),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("analyst")),
    _rl: None = Depends(require_rate_limit_guard),
) -> GuardScanResponse | GuardScanQueuedResponse | JSONResponse:
    """Runtime guard scan. Auth required in production (PROMPTSENTINEL_API_KEY set); bypassed in dev. Optional X-API-Key selects plan-tier policy.

    Async mode: pass ``?async=true`` (query param) or ``async_mode=true`` in
    the JSON body. Returns GuardScanQueuedResponse with a scan_id; poll
    GET /guard/scans/{scan_id} for the result.
    """
    from .models import User as _User
    user_plan: str | None = None
    metered_user: _User | None = None
    admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
    if x_api_key and admin_key and x_api_key != admin_key:
        _user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
        if _user and _user.is_active:
            user_plan = _user.plan
            metered_user = _user

    # Phase 1.3 — plan-based monthly limit (MonthlyUsage table).
    # Returns a GuardScanResponse with block=True so SDK consumers get a
    # uniform response shape regardless of whether the block is policy- or
    # quota-driven.
    if metered_user is not None:
        _plan_tier = resolve_plan_tier(metered_user.plan)
        _period = current_period()
        _guard_lim, _camp_lim = get_monthly_limits(_plan_tier)
        if _guard_lim is not None:
            _gs, _cs = (
                org_total_usage(session, _period, metered_user.org_id)
                if metered_user.org_id
                else read_usage(session, _period, metered_user.id)
            )
            if _gs >= _guard_lim:
                return GuardScanResponse(
                    risk_score=100,
                    severity="high",
                    categories=["usage_limit"],
                    confidence=1.0,
                    block=True,
                    decision="block",
                    reasons=[
                        f"Monthly guard scan limit ({_guard_lim}) reached. "
                        "Upgrade to Pro for unlimited scans."
                    ],
                )

    # PHASE 2.35 — detect sandbox mode early so every side-effect block can skip it.
    _sandbox_mode: bool = bool(getattr(payload.policy, "sandbox_mode", False)) if payload.policy else False

    # E6 — Org-scoped OrgUsageMonth quota: check + increment BEFORE scan runs.
    # Public / anonymous callers (no metered_user) are not metered here —
    # the rate-limiter dependency already protects unauthenticated traffic.
    # PHASE 2.35 — sandbox scans never count against quota.
    if metered_user is not None and metered_user.org_id is not None and not _sandbox_mode:
        _org_plan = resolve_plan_tier(metered_user.plan)
        increment_guard(session, metered_user.org_id, _org_plan)
        # increment_guard raises HTTPException(402) if limit exceeded.

    # Set plan quota response headers (all paths)
    try:
        from .models import OrgUsageMonth as _OUM
        _h_plan = normalize_plan(metered_user.plan) if metered_user else "public"
        _h_ym   = current_ym()
        _h_lims = limits_for_plan(_h_plan)
        _h_glim = _h_lims["guard_scans"]
        if metered_user is not None and metered_user.org_id is not None:
            _h_row = session.exec(
                select(_OUM)
                .where(_OUM.org_id == metered_user.org_id)
                .where(_OUM.ym == _h_ym)
            ).first()
            _h_used = _h_row.guard_scans if _h_row else 0
        else:
            _h_used = 0
        response.headers["X-Plan"]             = _h_plan
        response.headers["X-Usage-Period"]     = _h_ym
        response.headers["X-Guard-Limit"]      = str(_h_glim) if _h_glim != -1 else "unlimited"
        response.headers["X-Guard-Used"]       = str(_h_used)
        response.headers["X-Guard-Remaining"]  = str(max(0, _h_glim - _h_used)) if _h_glim != -1 else "unlimited"
    except Exception:
        pass  # never let header logic abort the scan

    # Audit: policy override — log when authenticated caller explicitly overrides defaults.
    if metered_user is not None and payload.policy is not None and payload.policy.model_fields_set:
        from .audit_log import write_audit_log as _wal
        _wal(session, action="policy.override", resource_type="guard_scan",
             org_id=metered_user.org_id, user_id=metered_user.id,
             metadata={"overridden_fields": sorted(payload.policy.model_fields_set)})

    # Determine effective async flag (body field OR query param).
    do_async = payload.async_mode or async_mode

    if do_async:
        # ── Async path ────────────────────────────────────────────────────────
        from .guard_async import create_scan_record

        _uid = metered_user.id if metered_user is not None else None
        _plan = metered_user.plan if metered_user is not None else (user_plan or "public")
        _policy_json = payload.policy.model_dump_json() if payload.policy else "{}"

        scan_row = create_scan_record(
            session,
            user_id=_uid,
            plan=_plan,
            input_text=payload.input,
            output_text=payload.output,
            context_text=payload.context,
            policy_json=_policy_json,
            org_id=metered_user.org_id if metered_user is not None else None,  # E4
            model_name=(payload.model or "unknown").strip() or "unknown",
        )

        # Decrement quota before dispatching (consistent with sync path).
        # PHASE 2.35 — sandbox scans never increment usage.
        if metered_user is not None and not _sandbox_mode:
            incr_guard_scans(session, metered_user.id, 1)
            try:
                bump_usage(session, org_id=metered_user.org_id, user_id=metered_user.id,
                           field="guard_scans", plan=metered_user.plan)
            except Exception:
                pass

        # Row is status='queued' — the dedicated worker (app/worker.py) will
        # pick it up, run the pipeline, and flip the status to completed/failed.
        # The API process no longer processes scans in-band.
        return GuardScanQueuedResponse(scan_id=scan_row.id, status="queued")

    # ── Synchronous path (original behavior) ─────────────────────────────────
    result = run_guard_scan(
        payload.input, payload.output, payload.policy, payload.context,
        user_plan=user_plan, session=session,
        async_mode=False,
        user_id=metered_user.id if metered_user is not None else None,
        org_id=metered_user.org_id if metered_user is not None else None,
        retrieved_docs=payload.retrieved_docs,      # Phase 3.3
        tool_calls=payload.tool_calls,             # Phase 3.4
        baseline_output=payload.baseline_output,   # Phase 3.5
    )

    # Count quota regardless of sync/async so the budget is always decremented.
    # PHASE 2.35 — sandbox scans never increment usage.
    if metered_user is not None and not _sandbox_mode:
        incr_guard_scans(session, metered_user.id, 1)
        try:
            bump_usage(session, org_id=metered_user.org_id, user_id=metered_user.id, field="guard_scans", plan=metered_user.plan)
        except Exception:
            pass

    # PHASE 2.35 — sandbox scans emit a single "sandbox_guard_scan" audit event
    # instead of the normal "guard_scan" event (no other audit side effects).
    _audit_action = "sandbox_guard_scan" if _sandbox_mode else "guard_scan"
    log_event(session, _audit_action, metered_user.id if metered_user is not None else None, {
        "decision": result.decision,
        "severity": result.severity,
        "categories": result.categories,
        "elapsed_ms": result.elapsed_ms,
        "signature_hash": result.signature_hash,
    }, ip=request.client.host if request.client else None)

    # Push security event to org webhook on warn/block (best-effort)
    # PHASE 2.35 — skip webhook in sandbox mode.
    if result.decision in ("warn", "block") and metered_user is not None and metered_user.org_id is not None and not _sandbox_mode:
        from datetime import datetime as _dt, timezone as _tz
        fire_guard_event(session, metered_user.org_id, {
            "type": "guard_scan",
            "created_at": _dt.now(_tz.utc).isoformat(),
            "decision": result.decision,
            "severity": result.severity,
            "categories": result.categories,
            "signature_hash": result.signature_hash,
            "cluster_id": result.cluster_id,
            "elapsed_ms": result.elapsed_ms,
        })

    # Update per-model risk profile (PHASE 2.0 — org-scoped).
    _model_name = (payload.model or "unknown").strip() or "unknown"
    try:
        from .model_risk import update_model_profile as _ump
        _org_id_mr = metered_user.org_id if metered_user is not None else None
        _ump(session, _org_id_mr, _model_name, result.risk_score,
             result.consensus_score, result.decision)
    except Exception:
        pass

    return result


# ── ADVANCED — Simulation Mode ────────────────────────────────────────────────

# Maximally strict policy preset used as default when no strict_policy is supplied.
_STRICT_POLICY_PRESET = None  # built lazily to avoid import-time circular issues


def _get_strict_preset():
    """Return the maximally strict GuardPolicy singleton."""
    global _STRICT_POLICY_PRESET
    if _STRICT_POLICY_PRESET is None:
        from .schemas import GuardPolicy as _GP
        _STRICT_POLICY_PRESET = _GP(
            block_injection=True,
            block_pii=True,
            block_high_risk=True,
            allow_medium=False,
            block_hallucination=True,
            block_rag_injection=True,
            block_tool_abuse=True,
            block_on_low_consensus=True,
            min_consensus_to_allow=60,
            deterministic=True,
        )
    return _STRICT_POLICY_PRESET


_SEVERITY_ORDER: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@app.post("/guard/simulate", response_model=GuardSimulateResponse)
async def guard_simulate(
    payload: GuardSimulateRequest,
    x_api_key: str | None = Header(default=None),
    _role: object = Depends(require_min_role("analyst")),
    _rl: None = Depends(require_rate_limit_guard),
) -> GuardSimulateResponse:
    """Dry-run simulation — compare current policy vs a stricter policy.

    Runs the full detection pipeline **twice** with no side effects:
    no DB writes, no usage counter increments, no SIEM webhook delivery.

    **current** — result under the caller's effective policy (``policy`` field,
    or plan-tier defaults when omitted).

    **simulated** — result under ``strict_policy`` (caller-supplied), or the
    built-in maximally strict preset when omitted:
    all detectors enabled, ``allow_medium=False``, ``block_on_low_consensus=True``
    with ``min_consensus_to_allow=60``, ``block_hallucination=True``.

    **would_block** — ``True`` when the stricter policy would block a request
    that the current policy allows through.  Use this to audit the gap between
    your production policy and maximum protection.
    """
    # Resolve caller plan for current-policy defaults (no DB access needed).
    user_plan: str | None = None
    if x_api_key:
        from sqlmodel import Session as _Session
        from .db import engine as _engine
        from .models import User as _User
        admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
        if admin_key and x_api_key != admin_key:
            with _Session(_engine) as _s:
                _u = _s.exec(select(_User).where(_User.api_key == x_api_key)).first()
                if _u and _u.is_active:
                    user_plan = _u.plan

    strict_pol = payload.strict_policy or _get_strict_preset()

    # Both calls use session=None — no DB writes, no usage tracking, no webhooks.
    current_result = run_guard_scan(
        payload.input, payload.output, payload.policy, payload.context,
        user_plan=user_plan, session=None,
        retrieved_docs=payload.retrieved_docs,
        tool_calls=payload.tool_calls,
        baseline_output=payload.baseline_output,
    )
    simulated_result = run_guard_scan(
        payload.input, payload.output, strict_pol, payload.context,
        user_plan=user_plan, session=None,
        retrieved_docs=payload.retrieved_docs,
        tool_calls=payload.tool_calls,
        baseline_output=payload.baseline_output,
    )

    would_block = simulated_result.block and not current_result.block
    would_escalate = (
        _SEVERITY_ORDER.get(simulated_result.severity, 0)
        > _SEVERITY_ORDER.get(current_result.severity, 0)
    )

    return GuardSimulateResponse(
        current=current_result,
        simulated=simulated_result,
        would_block=would_block,
        would_escalate_severity=would_escalate,
        risk_delta=simulated_result.risk_score - current_result.risk_score,
    )


# ── ADVANCED — Auto Hardening Suggestions v2 ─────────────────────────────────

@app.post("/guard/harden", response_model=HardeningSuggestionsResponse)
async def guard_harden(
    payload: GuardScanRequest,
    x_api_key: str | None = Header(default=None),
    _role: object = Depends(require_min_role("analyst")),
    _rl: None = Depends(require_rate_limit_guard),
) -> HardeningSuggestionsResponse:
    """Return structured hardening suggestions for a given scan context.

    Runs the full detection pipeline with ``session=None`` (no DB writes, no
    usage increment) and maps detected categories to three remediation buckets:

    - **system_prompt** — instruction template improvements (injection guards,
      anti-override clauses, PII prohibitions, persona boundary definitions).
    - **tool_schema** — tool allowlist, JSON Schema validation, permission
      tiers, outbound URL blocking, secret-pattern auditing on tool output.
    - **retrieval** — document sanitization, trust scoring, metadata filtering,
      citation enforcement, grounding validation.

    Each suggestion carries: ``category``, ``severity``, ``title``,
    ``description``, and an optional ``example`` code/template snippet.

    Suggestions are ordered critical → high → medium → low within each bucket.
    Nothing is recorded; counters are not incremented.
    """
    from .suggestions import generate_structured_suggestions

    user_plan: str | None = None
    if x_api_key:
        from sqlmodel import Session as _Session
        from .db import engine as _engine
        from .models import User as _User
        admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
        if admin_key and x_api_key != admin_key:
            with _Session(_engine) as _s:
                _u = _s.exec(select(_User).where(_User.api_key == x_api_key)).first()
                if _u and _u.is_active:
                    user_plan = _u.plan

    # Run pipeline with no session — pure detection, zero side effects.
    result = run_guard_scan(
        payload.input, payload.output, payload.policy, payload.context,
        user_plan=user_plan, session=None,
        retrieved_docs=payload.retrieved_docs,
        tool_calls=payload.tool_calls,
        baseline_output=payload.baseline_output,
    )

    raw = generate_structured_suggestions(
        categories=set(result.categories),
        risk_score=result.risk_score,
        has_tool_calls=bool(payload.tool_calls),
        has_retrieved_docs=bool(payload.retrieved_docs),
    )

    return HardeningSuggestionsResponse(
        system_prompt=[HardeningSuggestion(**s) for s in raw["system_prompt"]],
        tool_schema=[HardeningSuggestion(**s) for s in raw["tool_schema"]],
        retrieval=[HardeningSuggestion(**s) for s in raw["retrieval"]],
        risk_score=raw["risk_score"],
        category_count=raw["category_count"],
        total_count=raw["total_count"],
    )


@app.get("/guard/scans/{scan_id}", response_model=GuardScanResultResponse)
async def get_guard_scan_result(
    scan_id: int,
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> GuardScanResultResponse:
    """Poll the result of an async guard scan.

    If the scan was attributed to a user_id, the same user (or an admin)
    must supply the matching X-API-Key. Anonymous scans are world-readable.
    """
    from .models import GuardScan, User as _User

    scan = session.get(GuardScan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Ownership check — only when scan was made by an authenticated user.
    if scan.user_id is not None:
        caller: _User | None = None
        if x_api_key:
            caller = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
        if caller is None or (caller.id != scan.user_id and not caller.is_admin):
            raise HTTPException(status_code=403, detail="Access denied")

    result: GuardScanResponse | None = None
    if scan.status == "completed" and scan.result_json not in ("", "{}"):
        try:
            result = GuardScanResponse.model_validate_json(scan.result_json)
        except Exception:
            pass

    return GuardScanResultResponse(
        scan_id=scan.id,  # type: ignore[arg-type]
        status=scan.status,
        result=result,
        error_message=scan.error_message,
    )


@app.post("/guard/replay/{scan_id}", response_model=GuardReplayResponse)
async def guard_replay(
    scan_id: int,
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("analyst")),
    _rl: None = Depends(require_rate_limit_guard),
) -> GuardReplayResponse:
    """Re-run a previous scan deterministically using its stored random seed.

    - ``scan_id`` is the ``GuardScanRecord`` id (returned in guard history).
    - The pipeline is run with ``deterministic=True`` + the original random seed
      so the result should match the original unless detectors have been updated.
    - **Nothing is written**: no scan record is created and no usage counters
      are incremented.
    - Access: the caller must own the scan (same user_id or same org_id).
      Admin API key bypasses the check.
    """
    import random as _rng
    from datetime import datetime as _dt, timezone as _tz
    from .models import GuardScanRecord, GuardScanReplayStore
    from .schemas import GuardPolicy as _GP
    from .guard import run_guard_scan as _rgs

    # ── 1. Load the scan record ──────────────────────────────────────────────
    rec: GuardScanRecord | None = session.get(GuardScanRecord, scan_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Scan record not found")

    # ── 2. Ownership check ───────────────────────────────────────────────────
    from .models import User as _User
    caller: _User | None = None
    if x_api_key:
        caller = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    admin_env = os.environ.get("PROMPTSENTINEL_API_KEY")
    is_admin_call = x_api_key and admin_env and x_api_key == admin_env
    if not is_admin_call:
        if caller is None:
            raise HTTPException(status_code=403, detail="Authentication required for replay")
        # Must share user_id or org_id with the original scan
        uid_match = rec.user_id is not None and caller.id == rec.user_id
        oid_match = rec.org_id is not None and caller.org_id == rec.org_id
        if not uid_match and not oid_match and not getattr(caller, "is_admin", False):
            raise HTTPException(status_code=403, detail="Access denied — not your scan")

    # ── 3. Load the replay store (full payload + seed) ───────────────────────
    store: GuardScanReplayStore | None = session.exec(
        select(GuardScanReplayStore).where(GuardScanReplayStore.scan_record_id == scan_id)
    ).first()
    if store is None:
        raise HTTPException(
            status_code=409,
            detail="No replay data available for this scan (only scans made after "
                   "replay support was enabled can be replayed)",
        )

    # ── 4. Reconstruct policy — force deterministic mode ────────────────────
    try:
        _pol_dict = json.loads(store.policy_json or "{}")
    except Exception:
        _pol_dict = {}
    _pol_dict["deterministic"] = True   # stable detector order
    replay_policy = _GP(**{k: v for k, v in _pol_dict.items() if k in _GP.model_fields})

    # ── 5. Seed random and run pipeline (no session → no DB writes) ──────────
    _rng.seed(store.random_seed)
    replay_result = _rgs(
        input_text=store.input_text,
        output_text=store.output_text or None,
        policy=replay_policy,
        context=store.context_text,
        user_plan=rec.plan,
        session=None,               # dry-run: no persistence, no usage increment
        async_mode=False,
        user_id=None,
        org_id=None,
        retrieved_docs=None,
        tool_calls=None,
        baseline_output=None,
    )

    if replay_result is None:
        raise HTTPException(status_code=500, detail="Replay pipeline returned no result")

    _match = rec.decision == replay_result.decision

    # ── 6. Audit log (PHASE 2.4) ─────────────────────────────────────────────
    try:
        log_audit_event(session,
            event_type="guard_replay",
            org_id=rec.org_id,
            user_id=caller.id if caller else None,
            resource_type="guard_scan",
            resource_id=str(scan_id),
            metadata={"scan_id": scan_id, "match": _match,
                      "original_decision": rec.decision,
                      "replay_decision": replay_result.decision},
        )
    except Exception:
        pass

    return GuardReplayResponse(
        original_scan_id=scan_id,
        random_seed=store.random_seed,
        replayed_at=_dt.now(_tz.utc),
        result=replay_result,
        original_decision=rec.decision,
        replay_decision=replay_result.decision,
        match=_match,
        # PHASE 2.10 — extended comparison fields
        replay_match=_match,
        original_severity=rec.severity,
        replay_severity=replay_result.severity,
        original_signature_hash=rec.signature_hash,
        replay_signature_hash=replay_result.signature_hash,
    )


@app.get("/guard/history", response_model=GuardScanHistoryResponse)
async def guard_history(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    decision: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    sig: str | None = Query(default=None),
    days: int | None = Query(default=7, ge=1, le=90),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> GuardScanHistoryResponse:
    """Return paginated, filtered guard scan history (org-scoped)."""
    from .models import GuardScanRecord, User as _User
    from sqlalchemy import desc, func as sa_func
    from datetime import datetime as _dt, timedelta, timezone as tz

    _empty = GuardScanHistoryResponse(items=[], total=0, page=page, page_size=page_size)

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        return _empty

    _, _org_id, _is_admin = get_request_user_org(request, session)

    # Build base filter predicates
    filters = []
    if not _is_admin:
        if _org_id is not None:
            filters.append(GuardScanRecord.org_id == _org_id)
        else:
            filters.append(GuardScanRecord.user_id == user.id)
    if days is not None:
        cutoff = _dt.now(tz.utc) - timedelta(days=days)
        filters.append(GuardScanRecord.created_at >= cutoff)
    if decision:
        filters.append(GuardScanRecord.decision == decision)
    if severity:
        filters.append(GuardScanRecord.severity == severity)
    if sig:
        filters.append(GuardScanRecord.signature_hash == sig)

    # Total count
    count_q = select(sa_func.count(GuardScanRecord.id))
    for f in filters:
        count_q = count_q.where(f)
    total: int = session.execute(count_q).scalar_one()

    # Paginated rows
    offset = (page - 1) * page_size
    row_q = select(GuardScanRecord)
    for f in filters:
        row_q = row_q.where(f)
    row_q = row_q.order_by(desc(GuardScanRecord.created_at)).offset(offset).limit(page_size)
    rows = session.exec(row_q).all()

    items = [
        GuardScanItem(
            id=r.id,
            created_at=r.created_at,
            decision=r.decision,
            severity=r.severity,
            categories=json.loads(r.categories_json or "[]"),
            signature_hash=r.signature_hash,
            elapsed_ms=r.elapsed_ms,
            input_len=getattr(r, "input_len", 0),
            output_len=getattr(r, "output_len", 0),
            input_snippet=getattr(r, "input_snippet", ""),
            output_snippet=getattr(r, "output_snippet", ""),
            attacker_pattern_score=getattr(r, "attacker_pattern_score", 0),  # ADVANCED
        )
        for r in rows
    ]
    return GuardScanHistoryResponse(items=items, total=total, page=page, page_size=page_size)


@app.get("/usage/me")
async def usage_me(
    period: str | None = Query(default=None),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> JSONResponse:
    """Return the caller's monthly guard_scans + campaigns_started counts."""
    from .models import MonthlyUsage, User as _User

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Valid user API key required")

    p = period or current_period()
    row = session.exec(
        select(MonthlyUsage)
        .where(MonthlyUsage.period_yyyymm == p)
        .where(MonthlyUsage.user_id == user.id)
    ).first()

    return JSONResponse({
        "period": p,
        "plan": user.plan,
        "guard_scans": row.guard_scans if row else 0,
        "campaigns_started": row.campaigns_started if row else 0,
        "limits": {},  # populated in Phase 1.3
    })


@app.get("/usage/org", response_model=OrgUsageResponse)
async def usage_org(
    ym: str | None = Query(default=None, description="Month in YYYY-MM format; defaults to current month"),
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> OrgUsageResponse:
    """Return org-level monthly usage from OrgUsageMonth (org-scoped counter)."""
    from .models import OrgUsageMonth, User as _User

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None or not user.org_id:
        raise HTTPException(status_code=403, detail="No organization")

    _ym = ym or current_ym()
    row = session.exec(
        select(OrgUsageMonth)
        .where(OrgUsageMonth.org_id == user.org_id)
        .where(OrgUsageMonth.ym == _ym)
    ).first()

    return OrgUsageResponse(
        ym=_ym,
        org_id=user.org_id,
        guard_scans=row.guard_scans if row else 0,
        campaigns_created=row.campaigns_created if row else 0,
    )


@app.get("/usage/status", response_model=UsageStatusResponse)
async def usage_status(
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> UsageStatusResponse:
    """Rich usage + quota status for the dashboard upgrade banner."""
    from .models import User as _User

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Valid user API key required")

    plan = resolve_plan_tier(user.plan)
    p = current_period()

    # Prefer org-level totals so org members share one quota view.
    if user.org_id:
        scans, camps = org_total_usage(session, p, user.org_id)
    else:
        scans, camps = read_usage(session, p, user.id)

    guard_limit, camps_limit = get_monthly_limits(plan)

    guard_rem = None if guard_limit is None else max(0, guard_limit - scans)
    camps_rem = None if camps_limit is None else max(0, camps_limit - camps)

    guard_pct = (
        None if guard_limit is None
        else (scans / guard_limit if guard_limit > 0 else 0.0)
    )
    camps_pct = (
        None if camps_limit is None
        else (camps / camps_limit if camps_limit > 0 else 0.0)
    )

    return UsageStatusResponse(
        period=p,
        plan=plan,
        guard_scans=scans,
        campaigns_started=camps,
        limits={"guard_scans": guard_limit, "campaigns_started": camps_limit},
        remaining={"guard_scans": guard_rem, "campaigns_started": camps_rem},
        pct_used={"guard_scans": guard_pct, "campaigns_started": camps_pct},
    )


# ── Phase E6 — /usage/remaining ───────────────────────────────────────────────

@app.get("/usage/remaining", response_model=OrgRemainingResponse)
async def usage_remaining(
    request: Request,
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> OrgRemainingResponse:
    """Org monthly quota snapshot: used / limit / remaining for scans and campaigns.

    Org-scoped (all members share one counter via OrgUsageMonth).
    For solo users without an org, org_id 0 is used as a sentinel so the
    response shape is always identical — callers don't need to branch.
    """
    from .models import User as _User

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Valid user API key required")

    _, _org_id, _ = get_request_user_org(request, session)
    # Solo users (no org) get a personal bucket keyed on user.id negated.
    bucket_org_id: int = _org_id if _org_id is not None else -(user.id)

    plan = resolve_plan_tier(user.plan)
    ym = current_ym()
    row = get_or_create_usage(session, bucket_org_id, ym)
    lim = limits_for_plan(plan)

    return OrgRemainingResponse(
        plan=plan,
        ym=ym,
        guard_scans_used=row.guard_scans,
        guard_scans_limit=lim["guard_scans"],
        guard_scans_remaining=max(0, lim["guard_scans"] - row.guard_scans),
        campaigns_used=row.campaigns_created,
        campaigns_limit=lim["campaigns"],
        campaigns_remaining=max(0, lim["campaigns"] - row.campaigns_created),
    )


# ── Phase 3.16 — /usage/summary ───────────────────────────────────────────────

@app.get("/usage/summary", response_model=UsageSummaryResponse)
async def usage_summary(
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
) -> UsageSummaryResponse:
    """Flat usage summary with date-bounded period and percent_used (Phase 3.16)."""
    from datetime import date as _date
    import calendar
    from .models import User as _User

    user: _User | None = None
    if x_api_key:
        user = session.exec(select(_User).where(_User.api_key == x_api_key)).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Valid user API key required")

    plan = resolve_plan_tier(user.plan)
    p = current_period()  # "YYYY-MM"
    yr, mo = int(p[:4]), int(p[5:7])
    period_start = _date(yr, mo, 1)
    period_end = _date(yr, mo, calendar.monthrange(yr, mo)[1])

    if user.org_id:
        scans, camps = org_total_usage(session, p, user.org_id)
    else:
        scans, camps = read_usage(session, p, user.id)

    guard_limit, camps_limit = get_monthly_limits(plan)

    # Pro → unlimited represented as -1
    if guard_limit is None:
        return UsageSummaryResponse(
            plan=plan,
            period_start=period_start,
            period_end=period_end,
            guard_used=scans,
            guard_limit=-1,
            guard_remaining=-1,
            campaigns_used=camps,
            campaigns_limit=-1,
            campaigns_remaining=-1,
            percent_used=0.0,
        )

    guard_rem = max(0, guard_limit - scans)
    camps_rem = max(0, camps_limit - camps) if camps_limit is not None else -1
    guard_pct = scans / guard_limit if guard_limit > 0 else 0.0
    camps_pct = (camps / camps_limit if camps_limit and camps_limit > 0 else 0.0)
    percent_used = round(max(guard_pct, camps_pct), 4)

    return UsageSummaryResponse(
        plan=plan,
        period_start=period_start,
        period_end=period_end,
        guard_used=scans,
        guard_limit=guard_limit,
        guard_remaining=guard_rem,
        campaigns_used=camps,
        campaigns_limit=camps_limit if camps_limit is not None else -1,
        campaigns_remaining=camps_rem,
        percent_used=percent_used,
    )


@app.get("/me", response_model=MeResponse)
async def get_me(
    x_api_key: str | None = Header(default=None),
    session: Session = Depends(get_session),
    _rl: None = Depends(require_rate_limit),
) -> MeResponse:
    """Return session info for the caller.

    No auth required — unauthenticated callers receive 'public' plan defaults.
    """
    from sqlalchemy import func as safunc
    from .models import AuditEvent, User as UserModel

    plan = get_user_plan(session, x_api_key)

    # Resolve the User row so we can count per-user audit events.
    user: UserModel | None = None
    admin_key = os.environ.get("PROMPTSENTINEL_API_KEY")
    if x_api_key and (not admin_key or x_api_key != admin_key):
        _u = session.exec(select(UserModel).where(UserModel.api_key == x_api_key)).first()
        if _u and _u.is_active:
            user = _u

    if user is not None:
        campaigns_total = int(session.exec(
            select(safunc.count()).select_from(AuditEvent)
            .where(AuditEvent.user_id == user.id)
            .where(AuditEvent.event_type == "campaign_created")
        ).one())
        guard_scans_total = int(session.exec(
            select(safunc.count()).select_from(AuditEvent)
            .where(AuditEvent.user_id == user.id)
            .where(AuditEvent.event_type == "guard_scan")
        ).one())
    else:
        campaigns_total = 0
        guard_scans_total = 0

    # Rate-limit setting: None when disabled (0 or unset).
    try:
        _rl_val = int(os.environ.get("PROMPTSENTINEL_RATE_LIMIT_PER_MIN", "0"))
    except ValueError:
        _rl_val = 0
    rate_limit_per_min = _rl_val if _rl_val > 0 else None

    return MeResponse(
        email=user.email if user else None,
        plan=plan,
        max_iterations=max_iterations_for(plan),
        allow_export=allow_export_for(plan),
        rate_limit_per_min=rate_limit_per_min,
        campaigns_total=campaigns_total,
        guard_scans_total=guard_scans_total,
    )


@app.get("/me/usage", response_model=UsageResponse)
async def get_me_usage(
    session: Session = Depends(get_session),
    _role: object = Depends(require_min_role("viewer")),
    user: object = Depends(get_current_user),
) -> UsageResponse:
    """Return current month's usage counters and plan quotas for the authenticated user."""
    from .models import User as UserModel
    if not isinstance(user, UserModel):
        raise HTTPException(status_code=403, detail="User account required")
    ym = current_period_ym()
    counter = get_or_create_counter(session, user.id, ym)
    quotas = plan_quotas(user.plan)
    return UsageResponse(
        period_ym=ym,
        plan=user.plan,
        guard_scans_used=counter.guard_scans,
        guard_scans_limit=quotas.guard_scans,
        guard_scans_remaining=max(0, quotas.guard_scans - counter.guard_scans),
        campaign_iterations_used=counter.campaign_iterations,
        campaign_iterations_limit=quotas.campaign_iterations,
        campaign_iterations_remaining=max(0, quotas.campaign_iterations - counter.campaign_iterations),
    )


@app.get("/health")
async def health(session: Session = Depends(get_session)) -> dict:
    """Health check with DB connectivity probe."""
    try:
        session.exec(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False
    status = "ok" if db_ok else "degraded"

    # DB-backed rate limiter is always active (org-scoped sliding window)
    rate_limit_enabled = True

    try:
        workers = int(os.environ.get("WEB_CONCURRENCY") or os.environ.get("UVICORN_WORKERS") or "1")
    except ValueError:
        workers = 1

    cfg = get_settings()
    return {
        "status": status,
        "service": "PromptSentinel",
        "db": db_ok,
        "rate_limit_enabled": rate_limit_enabled,
        "rate_limit_reason": MULTI_WORKER_REASON if MULTI_WORKER else "",
        "workers": workers,
        "stripe_configured": bool(cfg["stripe_secret_key"]),
        "demo_mode": cfg["demo_mode"],
        "app_url": cfg["app_url"],
    }


# ── PHASE 2.16 — SIEM / SOC Export ───────────────────────────────────────────

@app.get("/export/security-events")
async def export_security_events(
    format: str = Query("json", pattern="^(json|cef)$"),
    limit: int = Query(100, ge=1, le=5000),
    days: int = Query(7, ge=1, le=90),
    session: Session = Depends(get_session),
    user: object = Depends(require_min_role("viewer")),
    _rl: None = Depends(require_rate_limit),
):
    """Export security events (guard scans + audit log) for SIEM/SOC pipelines (PHASE 2.16).

    format=json  → JSON array wrapped in SecurityExportResponse envelope.
    format=cef   → text/plain newline-delimited CEF 0 rows.
    Results are org-scoped; no raw payloads included.
    """
    from datetime import datetime, timedelta
    from .models import GuardScanRecord, AuditEvent, User as _UserM
    from .export import guard_history_to_export_items, audit_to_export_items, to_cef

    _plan = normalize_plan(getattr(user, "plan", None))
    if not allow_export_for(_plan):
        raise HTTPException(
            status_code=403,
            detail={"type": "plan_limit_exceeded", "message": f"Export is not available on the '{_plan}' plan."},
        )

    _org_id = getattr(user, "org_id", None) if isinstance(user, _UserM) else None
    _since = datetime.utcnow() - timedelta(days=days)

    # ── Guard scan records ────────────────────────────────────────────────────
    gsr_q = (
        select(GuardScanRecord)
        .where(GuardScanRecord.created_at >= _since)
        .order_by(GuardScanRecord.created_at.desc())
    )
    if _org_id is not None:
        gsr_q = gsr_q.where(GuardScanRecord.org_id == _org_id)
    gsr_rows = session.exec(gsr_q.limit(limit)).all()

    # ── Audit events ──────────────────────────────────────────────────────────
    ae_q = (
        select(AuditEvent)
        .where(AuditEvent.created_at >= _since)
        .order_by(AuditEvent.created_at.desc())
    )
    if _org_id is not None:
        ae_q = ae_q.where(AuditEvent.org_id == _org_id)
    ae_rows = session.exec(ae_q.limit(limit)).all()

    # Merge, sort newest-first, cap at limit
    events = guard_history_to_export_items(gsr_rows) + audit_to_export_items(ae_rows)
    events.sort(key=lambda e: e["created_at"], reverse=True)
    events = events[:limit]

    if format == "cef":
        lines = "\n".join(to_cef(e) for e in events)
        return PlainTextResponse(content=lines, media_type="text/plain")

    return SecurityExportResponse(
        total=len(events),
        events=[SecurityEventExportItem(**e) for e in events],
    ).model_dump()
