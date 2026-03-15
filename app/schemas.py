from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── PHASE 2.39 — Billing Error Response (standardised shape) ─────────────────

class BillingErrorResponse(BaseModel):
    """Structured billing error returned inside ``{"error": {...}}`` JSON body.

    type:  "billing_unavailable" | "already_subscribed" | "billing_error"
    code:  machine-readable slug (e.g. "already_pro", "no_customer", "stripe_missing_config")
    """
    type: str
    message: str
    code: str = ""


# ── B3.2 — Stripe Checkout ────────────────────────────────────────────────────

class CheckoutSessionRequest(BaseModel):
    email: Optional[str] = None   # optional override; defaults to current user email


class CheckoutSessionResponse(BaseModel):
    checkout_url: str
    session_id: str = ""


# ── Guard Policy ──────────────────────────────────────────────────────────────

class GuardPolicy(BaseModel):
    block_injection: bool = True
    block_pii: bool = True
    block_high_risk: bool = True
    allow_medium: bool = False
    block_hallucination: bool = False           # opt-in; default keeps existing behaviour
    block_rag_injection: bool = True            # Phase 3.3 — on by default
    block_tool_abuse: bool = True               # Phase 3.4 — on by default
    tool_allowlist: Optional[List[str]] = None  # Phase 3.4 — if set, deny unlisted tools
    max_elapsed_ms: Optional[int] = None        # Phase 3.6 — hard time budget (ms)
    deterministic: bool = False                 # Phase 3.6 — stable ordering + no randomness
    block_on_low_consensus: bool = False        # Phase 3.7 — block when consensus is too low
    min_consensus_to_allow: int = 0             # Phase 3.7 — threshold (0–100) for low-consensus block
    max_detector_runtime_ms: Optional[int] = None  # ADVANCED — per-request detector CPU budget;
                                                    # when exceeded the pipeline aborts and
                                                    # decision is escalated to "warn" (unless blocking)
    strict_mode: bool = False                       # PHASE 2.3 — any medium+ → block
    sandbox_mode: bool = False                      # PHASE 2.35 — full pipeline, no side effects


class GuardScanRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=200_000)
    output: Optional[str] = Field(default=None, max_length=200_000)
    context: Optional[str] = Field(default=None, max_length=200_000)
    policy: Optional[GuardPolicy] = None
    model: Optional[str] = Field(default=None, max_length=120, description="Name of the model being protected (used for risk profiling)")
    retrieved_docs: Optional[List[str]] = Field(          # Phase 3.3
        default=None,
        max_length=50,
        description="Retrieved context documents to scan for RAG poisoning (max 50)",
    )
    tool_calls: Optional[List[Dict[str, Any]]] = Field(   # Phase 3.4
        default=None,
        max_length=50,
        description="Tool/function calls to inspect for argument injection (max 50)",
    )
    baseline_output: Optional[str] = Field(              # Phase 3.5
        default=None,
        max_length=200_000,
        description="Previous/baseline output to diff against (optional)",
    )


class GuardScanResponse(BaseModel):
    risk_score: int
    severity: str          # "low" | "medium" | "high" | "critical"
    categories: List[str]
    confidence: float
    block: bool
    reasons: List[str]
    hallucination_score: int = 0
    grounding_score: float = 0.0
    hallucination_reasons: List[str] = Field(default_factory=list)
    applied_policy: Dict[str, Any] = Field(default_factory=dict)
    signature_hash: str = ""
    signature_count: int = 0
    elapsed_ms: int = 0
    decision: str = "allow"  # "allow" | "warn" | "block"
    rag_doc_hits: int = 0                                   # Phase 3.3
    rag_reasons: List[str] = Field(default_factory=list)    # Phase 3.3
    rag_risk_score: int = 0                                 # composite RAG risk (0–100)
    rag_docs: List[Dict[str, Any]] = Field(default_factory=list)  # PHASE 2.1 per-doc scores
    tool_risk_score: int = 0                                # Phase 3.4 (legacy max per-call score)
    tool_reasons: List[str] = Field(default_factory=list)   # Phase 3.4
    tool_violation_score: int = 0                           # Policy engine composite score (0–100)
    tool_violations: List[str] = Field(default_factory=list)  # Violation type labels
    diff: Optional[Dict[str, Any]] = None                   # Phase 3.5
    timed_out: bool = False                                 # Phase 3.6
    performance_flags: List[str] = Field(default_factory=list)  # Phase 3.6
    consensus_score: int = 0                                # Phase 3.7
    consensus_reasons: List[str] = Field(default_factory=list)  # Phase 3.7
    normalized_risk: float = 0.0                            # Phase 3.12.C  z-score vs 30d baseline
    calibrated_risk: int = 0                               # Percentile rank in 30d window (0–100)
    suggestions: List[str] = Field(default_factory=list)   # Phase 3.12.D (plain, kept for compat)
    hardening_suggestions: List[Dict[str, str]] = Field(default_factory=list)  # PHASE 2.2 structured
    cluster_id: str = ""                                   # Phase 3.15 patch
    attacker_pattern_score: int = 0                        # ADVANCED — attacker behaviour profiling
    attacker_signals: Dict[str, Any] = Field(default_factory=dict)  # per-signal breakdown
    strict_mode_triggered: bool = False                    # PHASE 2.3
    policy_source: str = ""                                # PHASE 2.18: "request"|"org_default"|"forced"
    detection_signals: List[Dict[str, Any]] = Field(default_factory=list)  # PHASE 2.6
    stage_timings: Dict[str, int] = Field(default_factory=dict)            # PHASE 2.8
    zero_trust_triggered: bool = False                     # PHASE 2.27
    sandbox_mode_applied: bool = False                     # PHASE 2.35


class RiskTrendItem(BaseModel):
    campaign_id: int
    created_at: datetime
    avg_risk: float
    max_risk: int


class ThreatSignatureItem(BaseModel):
    signature_hash: str
    count: int
    top_category: Optional[str]
    first_seen_at: datetime
    last_seen_at: datetime
    example_snippet: str
    cluster_id: Optional[str] = None  # Phase 3.15 — sketch cluster_id


class ThreatClusterItem(BaseModel):
    """PHASE 2.15 — one ThreatCluster row returned by GET /threats/clusters."""
    cluster_id: str                          # centroid_hash (MinHash fingerprint)
    first_seen_at: datetime                  # = ThreatCluster.created_at
    last_seen_at: datetime                   # = ThreatCluster.updated_at
    count: int                               # = ThreatCluster.member_count
    top_category: Optional[str]
    example_signature_hash: Optional[str] = None
    example_snippet: str


class ThreatClusterListResponse(BaseModel):
    """PHASE 2.15 — paginated list of threat clusters."""
    clusters: List[ThreatClusterItem]
    total: int


# ── PHASE 2.37 — Customer-Facing Trust Score / Maturity Index ────────────────

class TrustScoreResponse(BaseModel):
    org_id: Optional[int]
    trust_score: int              # composite 0–100
    maturity_level: str           # starter | developing | advanced | hardened
    protection_coverage: int      # 0–100 — attack surface monitored
    control_maturity: int         # 0–100 — org security config hardening
    threat_pressure: int          # 0–100 — attack intensity (higher = more pressure)
    response_readiness: int       # 0–100 — alerting + visibility posture
    notes: List[str]              # 2–3 actionable human-readable insights


# ── PHASE 2.36 — Cross-Model Consensus Engine ─────────────────────────────────

class CrossModelConsensusRequest(BaseModel):
    input: str = Field(..., min_length=1, max_length=200_000)
    output: Optional[str] = Field(default=None, max_length=200_000)
    context: Optional[str] = Field(default=None, max_length=200_000)
    models: List[str] = Field(..., min_length=1, max_length=20,
                              description="Model labels to run the same scan under (1–20)")


class CrossModelConsensusResponse(BaseModel):
    models: List[Dict[str, Any]]   # [{model, decision, severity, risk_score}]
    consensus_risk: float          # mean risk_score across all model runs
    majority_decision: str         # most frequent decision
    disagreement_score: float      # 0.0–1.0; 0 = full agreement, 1 = max divergence


class SketchClusterItem(BaseModel):
    """Sketch-based cluster item (Phase 3.15)."""
    centroid_hash: str        # = sketch cluster_id string
    member_count: int
    top_category: Optional[str]
    first_seen_at: datetime
    last_seen_at: datetime
    example_snippet: str


class ClusterTrendPoint(BaseModel):
    """Daily cluster activity point for /analytics/clusters (Phase 3.15)."""
    date: str          # YYYY-MM-DD
    unique_clusters: int
    total_scans: int


class TrendPoint(BaseModel):
    date: str    # "YYYY-MM-DD"
    scans: int
    blocked: int


class ThreatTrendsResponse(BaseModel):
    window_days: int
    points: List[TrendPoint]
    top_categories: Dict[str, int]


class ThreatAnalyticsResponse(BaseModel):
    """Combined guard analytics: time-series + top categories + top signatures (Phase 3.11)."""
    window_days: int
    points: List[TrendPoint]
    top_categories: Dict[str, int]          # category -> count, top 10
    top_signatures: List["ThreatSignatureItem"]  # top 10 by recency in window


class TestLLMRequest(BaseModel):
    """Request payload for the synchronous /test-llm endpoint."""

    system_prompt: str = Field(..., min_length=1, max_length=500_000, description="The system prompt to defend and test.")
    model: str = Field(..., min_length=1, max_length=200, description="Identifier for the target LLM model (for metadata only).")


class SimulatedLLMTest(BaseModel):
    """Internal representation of a single simulated attack + response."""

    id: int
    attack_prompt: str
    llm_response: str


class TestResult(SimulatedLLMTest):
    """Annotated result for a single simulated attack."""

    leakage_detected: bool
    override_detected: bool
    risk_score: int
    confidence: float = 0.0


class TestLLMResponse(BaseModel):
    """Response payload for /test-llm."""

    risk_score: int
    summary: str
    tests: List[TestResult]


class SignupRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=8, max_length=128)


class PasswordLoginRequest(BaseModel):
    """Payload for the legacy email+password login endpoint."""

    email: str = Field(..., min_length=3, max_length=254)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    token: str


# ---------------------------------------------------------------------------
# Magic-link auth (B4.1 / B4.2)
# ---------------------------------------------------------------------------

class LoginRequest(BaseModel):
    """Initiate a magic-link login (email only)."""

    email: str = Field(..., min_length=3, max_length=320)


class LoginResponse(BaseModel):
    """Response from POST /auth/login."""

    ok: bool
    dev_token: Optional[str] = None   # only present in dev mode


class RedeemRequest(BaseModel):
    """Payload for POST /auth/redeem."""

    token: str = Field(..., min_length=1, max_length=200)


class RedeemResponse(BaseModel):
    """Returned on successful token redemption."""

    api_key: str
    email: str
    plan: str


class CampaignStatus(str, Enum):
    """Lifecycle state for a long-running campaign."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class CampaignCreateRequest(BaseModel):
    """Request body for creating a new campaign."""

    system_prompt: str = Field(..., min_length=1, max_length=500_000)
    model: str = Field(..., min_length=1, max_length=200)
    iterations: int = Field(50, ge=1, le=5000)
    categories: Optional[List[str]] = Field(
        default=None,
        description=(
            "Optional subset of categories to enable for this campaign: "
            "role_confusion, instruction_override, policy_leakage, data_exfiltration, tool_misuse"
        ),
    )


class CampaignCreateResponse(BaseModel):
    """Response after queuing a new campaign."""

    campaign_id: int
    status: CampaignStatus


class CampaignStatusResponse(BaseModel):
    """Current status and high-level metrics for a campaign."""

    campaign_id: int
    status: CampaignStatus
    iterations_total: int
    iterations_done: int
    progress: float
    metrics: Dict[str, Any]
    error_message: Optional[str] = None


class FindingResponse(BaseModel):
    """Single finding as exposed via the public API."""

    id: int
    created_at: datetime
    iteration: int
    category: str
    attack_prompt: str
    llm_response: str
    leakage_detected: bool
    override_detected: bool
    risk_score: int
    notes: Optional[str] = None
    turn_count: Optional[int] = None
    transform_name: Optional[str] = None
    confidence_score: Optional[float] = None


class PaginatedFindingsResponse(BaseModel):
    """Paginated list of findings."""

    items: List[FindingResponse]
    page: int
    page_size: int
    total: int


class CreateUserRequest(BaseModel):
    email: str = Field(..., min_length=1, max_length=254)


class CreateUserResponse(BaseModel):
    email: str
    api_key: str


class UserSafeResponse(BaseModel):
    """User record without api_key — safe to return in list/deactivate responses."""

    id: int
    email: str
    created_at: datetime
    is_active: bool
    plan: str


class MeResponse(BaseModel):
    """Session info returned by GET /me — works for authenticated and public callers."""

    email: Optional[str]
    plan: str
    max_iterations: int
    allow_export: bool
    rate_limit_per_min: Optional[int]
    campaigns_total: int
    guard_scans_total: int


class UserKeyResponse(BaseModel):
    """Returned only by rotate-key — includes the newly generated api_key."""

    id: int
    email: str
    api_key: str


class RecentCampaignItem(BaseModel):
    id: int
    created_at: datetime
    status: str
    iterations_total: int
    iterations_done: int
    progress: float
    max_risk: int
    avg_risk: float


class DashboardSummaryResponse(BaseModel):
    total_users: int
    total_campaigns: int
    running_campaigns: int
    completed_campaigns: int
    failed_campaigns: int
    total_findings: int
    avg_risk_global: float
    high_risk_campaign_ratio: float


class UsageResponse(BaseModel):
    period_ym: str
    plan: str
    guard_scans_used: int
    guard_scans_limit: int
    guard_scans_remaining: int
    campaign_iterations_used: int
    campaign_iterations_limit: int
    campaign_iterations_remaining: int


class GuardAnalyticsResponse(BaseModel):
    """Per-user guard scan analytics derived from audit events."""

    total_scans: int
    allows: int
    warns: int
    blocks: int
    avg_latency_ms: float
    top_category_counts: Dict[str, int]


class AdminGlobalAnalyticsResponse(BaseModel):
    """System-wide analytics returned by GET /admin/analytics."""

    total_users: int
    active_users: int
    pro_users: int
    total_campaigns: int
    campaigns_completed: int
    campaigns_failed: int
    guard_total_scans: int
    guard_blocks: int
    guard_warns: int
    guard_allows: int
    avg_guard_latency_ms: float


class AuditEventItem(BaseModel):
    """Single audit log entry returned by GET /admin/audit and GET /audit/events."""

    id: int
    created_at: datetime
    org_id: Optional[int] = None
    user_id: Optional[int] = None
    event_type: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    metadata: Dict[str, Any]


class AuditEventListResponse(BaseModel):
    """Paginated audit event list returned by GET /audit/events."""

    items: List[AuditEventItem]
    total: int
    page: int
    page_size: int


class AdminUserUsageItem(BaseModel):
    """Per-user usage summary returned by GET /admin/users/usage."""

    id: int
    email: str
    is_active: bool
    plan: str
    period_ym: str
    guard_scans_used: int
    guard_scans_limit: int
    guard_scans_remaining: int
    campaign_iterations_used: int
    campaign_iterations_limit: int
    campaign_iterations_remaining: int


# ---------------------------------------------------------------------------
# B8.1 — Organizations
# ---------------------------------------------------------------------------

class CreateOrgRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)


class OrgResponse(BaseModel):
    id: int
    name: str
    plan: str
    created_at: datetime
    retention_days: Optional[int] = None
    strict_mode: bool = False          # ADVANCED — Strict Mode flag


class UpdateOrgRetentionRequest(BaseModel):
    """PATCH /admin/orgs/{org_id}/retention — set or clear data-retention window."""
    retention_days: Optional[int] = Field(default=None, ge=7, le=3650)


class SetStrictModeRequest(BaseModel):
    """PATCH /admin/orgs/{org_id}/strict-mode — enable or disable Strict Mode."""
    strict_mode: bool


class OrgSecurityConfigRequest(BaseModel):
    """PUT /org/security-config — PHASE 2.18: set org-level strict mode policy."""
    strict_mode_default: bool           # applied when request doesn't set strict_mode
    force_strict_mode: Optional[bool] = None  # if True, request cannot override to False


class OrgSecurityConfigResponse(BaseModel):
    """PHASE 2.18 — current security config for the caller's org."""
    org_id: int
    strict_mode: bool           # existing force flag (admin-managed)
    strict_mode_default: bool   # new default flag
    policy_resolution: str      # "forced" | "default" | "request"
    zero_trust_mode: bool = False   # PHASE 2.27


class ZeroTrustConfigRequest(BaseModel):
    """PHASE 2.27 — PUT /org/security-config/zero-trust body."""
    zero_trust_mode: bool


class AssignUserOrgRequest(BaseModel):
    user_id: int
    org_id: int
    is_admin: bool = False


class AddOrgMemberRequest(BaseModel):
    """POST /admin/orgs/{org_id}/members — add a user to an org via OrgMember (E3)."""
    user_id: int
    role: str = "member"  # member | admin


class SetUserOrgRequest(BaseModel):
    """POST /admin/users/{user_id}/set-org — set a user's default_org_id (E3)."""
    org_id: int


class GuardScanHistoryItem(BaseModel):
    """One row returned by GET /guard/history — no raw input/output."""

    id: int
    created_at: datetime
    severity: str
    decision: str
    categories: List[str]
    elapsed_ms: int
    blocked: bool
    plan: str
    signature_hash: str


class GuardScanItem(BaseModel):
    """Paginated history row with snippet + length fields."""

    id: int
    created_at: datetime
    decision: str
    severity: str
    categories: List[str]
    signature_hash: str
    elapsed_ms: int
    input_len: int
    output_len: int
    input_snippet: str
    output_snippet: str
    attacker_pattern_score: int = 0     # ADVANCED — 0 if anonymous or no signal


class GuardScanHistoryResponse(BaseModel):
    """Paginated response for GET /guard/history."""

    items: List[GuardScanItem]
    total: int
    page: int
    page_size: int


# ── ADVANCED — Attacker Behavior Profiling ────────────────────────────────────

class AttackerProfileItem(BaseModel):
    """One attacker identity in the top-attackers list."""
    user_id: Optional[int]
    org_id: Optional[int]
    max_score: int                  # highest attacker_pattern_score observed
    avg_score: float                # running average over flagged scans
    scan_count: int                 # total scans from this identity with score >= threshold
    last_seen_at: datetime
    dominant_signals: List[str]     # which signal(s) drove the highest score


class AttackerProfileResponse(BaseModel):
    """Response for GET /analytics/attackers."""
    items: List[AttackerProfileItem]
    total: int
    min_score_threshold: int


class UsageStatusResponse(BaseModel):
    """Rich usage + limit status returned by GET /usage/status.

    ``limits``/``remaining``/``pct_used`` values are ``None`` for unlimited plans.
    """

    period: str
    plan: str
    guard_scans: int
    campaigns_started: int
    limits: Dict[str, Optional[int]]       # {guard_scans, campaigns_started}
    remaining: Dict[str, Optional[int]]    # None = unlimited
    pct_used: Dict[str, Optional[float]]   # None = unlimited


# ── Phase 3.12.A ─────────────────────────────────────────────────────────────

class AnomalyItem(BaseModel):
    metric: str           # "scans" | "block_rate" | "category:<n>" | "cluster:<id>"
    date: str             # YYYY-MM-DD
    value: float
    baseline_mean: float
    baseline_std: float
    z_score: float
    severity: str         # "warning" | "critical"


class AnomalyResponse(BaseModel):
    window_days: int
    anomalies: List[AnomalyItem]


# ── Phase 3.12.B ──────────────────────────────────────────────────────────────

class EmergingThreatItem(BaseModel):
    fingerprint: str
    day: str             # YYYY-MM-DD
    count: int
    top_category: Optional[str]


class EmergingThreatResponse(BaseModel):
    window_days: int
    threats: List[EmergingThreatItem]


# ── Phase 3.16 — Usage Summary ────────────────────────────────────────────────

class UsageSummaryResponse(BaseModel):
    plan: str
    period_start: date
    period_end: date
    guard_used: int
    guard_limit: int        # -1 = unlimited (pro)
    guard_remaining: int    # -1 = unlimited (pro)
    campaigns_used: int
    campaigns_limit: int    # -1 = unlimited (pro)
    campaigns_remaining: int  # -1 = unlimited (pro)
    percent_used: float     # max(guard_pct, camps_pct); 0.0 for pro


# ── Phase 3.14 — SIEM Webhook ─────────────────────────────────────────────────

class WebhookConfigRequest(BaseModel):
    url: str
    secret: str
    is_active: bool = True


class WebhookConfigResponse(BaseModel):
    url: str
    is_active: bool
    created_at: datetime
    last_error: Optional[str]
    last_sent_at: Optional[datetime]


# ── B3.3 — Stripe Webhook Ack ─────────────────────────────────────────────────

class WebhookAck(BaseModel):
    received: bool


# ── E1 — Webhook Reliability ──────────────────────────────────────────────────

class WebhookDeliveryItem(BaseModel):
    id: int
    org_id: int
    status: str                         # pending | success | dead_lettered | processing
    retry_count: int
    next_retry_at: datetime
    last_error: Optional[str]
    created_at: datetime
    delivered_at: Optional[datetime]


class WebhookDeadLetterItem(BaseModel):
    id: int
    org_id: int
    error_summary: str
    retry_count: int
    created_at: datetime


class WebhookDeliveryListResponse(BaseModel):
    items: list[WebhookDeliveryItem]
    total: int


class WebhookDeadLetterListResponse(BaseModel):
    items: list[WebhookDeadLetterItem]
    total: int


# ── Phase E2 — Guard trend analytics ─────────────────────────────────────────

class DailyCountPoint(BaseModel):
    day: str    # YYYY-MM-DD
    total: int
    blocked: int


class ThreatTrendResponse(BaseModel):
    days: int
    points: List[DailyCountPoint]


# ── Phase E7 — Upgrade banner ─────────────────────────────────────────────────

class UpgradeBannerResponse(BaseModel):
    """Returned by GET /billing/upgrade-banner; tells the UI whether + why to show a banner."""

    show: bool
    reason: str          # "near_limit" | "limit_reached" | "plan_feature_locked" | ""
    plan: str
    ym: str
    scans_used: int
    scans_limit: int
    scans_remaining: int
    campaigns_used: int
    campaigns_limit: int
    campaigns_remaining: int
    scans_pct: float     # 0.0 – 1.0
    campaigns_pct: float


# ── Phase 1.4 — Org Usage Metering ───────────────────────────────────────────

class OrgUsageResponse(BaseModel):
    """Monthly org-level usage returned by GET /usage/org."""
    ym: str                  # "YYYY-MM"
    org_id: int
    guard_scans: int
    campaigns_created: int


# ── Phase 1.6 — Threat + Usage Trend Analytics ────────────────────────────────

class DailyTrendPoint(BaseModel):
    day: str               # YYYY-MM-DD
    scans_total: int
    scans_blocked: int
    campaigns_created: int


class OrgTrendResponse(BaseModel):
    days: int
    points: List[DailyTrendPoint]
    top_categories: Dict[str, int]
    current_month_guard_scans: int
    current_month_campaigns_created: int


# ── Phase E6 — Org usage remaining ───────────────────────────────────────────

class OrgRemainingResponse(BaseModel):
    """Org monthly quota snapshot returned by GET /usage/remaining."""

    plan: str
    ym: str                      # "YYYY-MM"
    guard_scans_used: int
    guard_scans_limit: int
    guard_scans_remaining: int
    campaigns_used: int
    campaigns_limit: int
    campaigns_remaining: int


# ── Phase E5 — Org threat trend analytics ────────────────────────────────────

class DailyCount(BaseModel):
    """Per-day scan counts broken down by decision."""

    day: str    # YYYY-MM-DD
    total: int
    allow: int
    warn: int
    block: int


class OrgThreatTrendResponse(BaseModel):
    """Org-scoped SOC analytics: daily scan breakdown + categories + campaigns."""

    days: int
    scans: List[DailyCount]
    top_categories: List[Dict[str, int]]   # [{"prompt_injection": 12}, ...]
    campaigns_per_day: List[Dict[str, int]]  # [{"2026-03-01": 3}, ...]
    total_scans: int
    total_campaigns: int


# ── Async guard scan (Phase E1) ───────────────────────────────────────────────

class GuardScanAsyncRequest(GuardScanRequest):
    """GuardScanRequest extended with an optional async_mode body flag."""
    async_mode: bool = False


class GuardScanQueuedResponse(BaseModel):
    scan_id: int
    status: str   # always "queued"


# ── Simulation Mode (ADVANCED) ────────────────────────────────────────────────

class GuardSimulateRequest(BaseModel):
    """POST /guard/simulate — dry-run comparison between current and stricter policy.

    Runs the full detection pipeline twice (no DB writes, no usage increment):
    once under ``policy`` (caller's current policy, or plan defaults) and once
    under ``strict_policy`` (maximally strict preset, or caller-supplied override).
    """
    input: str = Field(..., min_length=1, max_length=200_000)
    output: Optional[str] = Field(default=None, max_length=200_000)
    context: Optional[str] = Field(default=None, max_length=200_000)
    # Current policy to evaluate against (defaults to plan-tier defaults).
    policy: Optional[GuardPolicy] = None
    # Policy to simulate under (defaults to maximally strict preset).
    strict_policy: Optional[GuardPolicy] = None
    model: Optional[str] = Field(default=None, max_length=120)
    retrieved_docs: Optional[List[str]] = Field(default=None, max_length=50)
    tool_calls: Optional[List[Dict[str, Any]]] = Field(default=None, max_length=50)
    baseline_output: Optional[str] = Field(default=None, max_length=200_000)


class GuardSimulateResponse(BaseModel):
    """Simulation result — nothing is recorded, no counters are incremented."""
    current: GuardScanResponse          # result under caller's effective policy
    simulated: GuardScanResponse        # result under stricter policy
    would_block: bool                   # stricter blocks when current does not
    would_escalate_severity: bool       # stricter produces a higher severity level
    risk_delta: int                     # simulated.risk_score − current.risk_score
    simulated_mode: bool = True         # sentinel — reminds caller nothing was recorded


# ── Auto Hardening Suggestions v2 (ADVANCED) ─────────────────────────────────

class HardeningSuggestion(BaseModel):
    """Single actionable hardening recommendation."""
    category: str           # detected category that triggered this suggestion
    severity: str           # low | medium | high | critical
    title: str              # short headline (≤ 80 chars)
    description: str        # actionable prose
    example: Optional[str] = None   # template snippet or code example


class HardeningSuggestionsResponse(BaseModel):
    """Structured hardening output from POST /guard/harden.

    Three buckets correspond to distinct remediation surfaces:
    - system_prompt  — instruction template improvements
    - tool_schema    — tool/function call schema recommendations
    - retrieval      — RAG / retrieval hygiene recommendations

    Nothing is recorded; no usage counters are incremented.
    """
    system_prompt: List[HardeningSuggestion]
    tool_schema: List[HardeningSuggestion]
    retrieval: List[HardeningSuggestion]
    risk_score: int          # echo of detected risk score
    category_count: int      # number of active threat categories
    total_count: int         # total suggestions across all buckets


class GuardScanResultResponse(BaseModel):
    scan_id: int
    status: str   # queued | completed | failed
    result: Optional[GuardScanResponse] = None
    error_message: Optional[str] = None


# ── ADVANCED — Replay Testing ─────────────────────────────────────────────────

class GuardReplayResponse(BaseModel):
    """Result of POST /guard/replay/{scan_id}.

    Wraps the full re-run GuardScanResponse alongside replay metadata.
    Nothing is written to the database during replay — no counters are
    incremented and no scan record is created.
    """
    original_scan_id: int           # GuardScanRecord.id that was replayed
    random_seed: int                # seed used for both original and this replay
    replayed_at: datetime           # UTC timestamp of the replay run
    result: GuardScanResponse       # full re-run result
    # PHASE 2.4 — decision comparison
    original_decision: str          # decision stored in GuardScanRecord
    replay_decision: str            # decision from this replay run
    match: bool                     # original_decision == replay_decision (kept for compat)
    # PHASE 2.10 — extended comparison
    replay_match: bool = False                  # alias for match with explicit name
    original_severity: str = ""                 # severity from stored scan record
    replay_severity: str = ""                   # severity produced by replay run
    original_signature_hash: str = ""           # signature hash from stored scan record
    replay_signature_hash: str = ""             # signature hash produced by replay run


# ── Audit Trail ───────────────────────────────────────────────────────────────

class AuditLogItem(BaseModel):
    id: int
    created_at: datetime
    org_id: Optional[int]
    user_id: Optional[int]
    action: str
    resource_type: str
    resource_id: Optional[str]
    metadata: Dict[str, Any]


class AuditLogResponse(BaseModel):
    logs: List[AuditLogItem]
    total: int
    days: int


# ── Model Risk Analytics ───────────────────────────────────────────────────────

class ModelRiskProfileItem(BaseModel):
    model_name: str
    org_id: Optional[int] = None
    sample_count: int
    avg_risk_score: float
    avg_consensus_score: float
    block_rate: float
    warn_rate: float
    updated_at: datetime


class ModelRiskProfileResponse(BaseModel):
    profiles: List[ModelRiskProfileItem]
    total: int


# Backward-compat alias
ModelRiskResponse = ModelRiskProfileResponse


# ── Phase ADVANCED — Signature Graph Mapping ─────────────────────────────────

class ThreatGraphNode(BaseModel):
    """Single cluster node in the threat graph."""
    id: int
    centroid_hash: str
    member_count: int
    top_category: Optional[str]
    example_snippet: str


class ThreatGraphEdge(BaseModel):
    """Undirected edge between two clusters with Jaccard similarity weight."""
    source: int    # cluster id
    target: int    # cluster id
    similarity: float  # Jaccard similarity [0, 1]


class ThreatGraphResponse(BaseModel):
    """Adjacency-list graph of threat clusters.

    nodes      — one entry per ThreatCluster row (up to *limit*)
    edges      — pairs whose Jaccard similarity >= *threshold*
    threshold  — the similarity cutoff used to build edges
    node_count / edge_count — convenience totals
    """
    nodes: List[ThreatGraphNode]
    edges: List[ThreatGraphEdge]
    threshold: float
    node_count: int
    edge_count: int


# ── Phase ENTERPRISE — SIEM Export ───────────────────────────────────────────

class ThreatFeedItem(BaseModel):
    """Single event record in the JSON threat feed.

    Field names mirror the CEF extension keys where possible so that callers
    can map between the two formats without a lookup table.
    """
    id: int
    timestamp: str           # ISO-8601 UTC, e.g. "2026-03-05T12:00:00+00:00"
    severity: str            # low | medium | high | critical
    decision: str            # allow | warn | block
    risk_score: int          # 0–100
    blocked: bool
    categories: List[str]
    signature_hash: str
    org_id: Optional[int]
    input_snippet: str       # first 200 chars, already redacted by guard pipeline
    elapsed_ms: int


class ThreatFeedResponse(BaseModel):
    """Envelope for the JSON-format SIEM threat feed.

    ``events`` are ordered newest-first.
    ``total`` is the number of events returned (may be < limit if fewer exist).
    """
    format: str              # always "json"
    hours: int               # lookback window requested
    min_severity: str        # filter applied
    total: int
    events: List[ThreatFeedItem]


# ── ENTERPRISE — Monthly Security Report ─────────────────────────────────────

class ReportTrendPoint(BaseModel):
    """One day of scan activity in the monthly report."""
    date: str            # YYYY-MM-DD
    total: int
    allow: int
    warn: int
    block: int
    block_rate: float    # blocked / total, 0.0 when total == 0


class ReportUsage(BaseModel):
    """Monthly quota consumption for the report subject (user or org)."""
    period: str                      # YYYY-MM
    plan: str
    guard_scans_used: int
    guard_scans_limit: int           # -1 = unlimited
    guard_scans_remaining: int       # -1 = unlimited
    campaigns_used: int
    campaigns_limit: int             # -1 = unlimited
    campaigns_remaining: int         # -1 = unlimited
    guard_pct_used: float            # 0.0–1.0; 0.0 for unlimited plans
    campaigns_pct_used: float


class ReportRiskPercentile(BaseModel):
    """Distribution statistics for risk scores in the report window."""
    sample_size: int
    mean: float
    std: float
    p50: float     # median
    p75: float
    p90: float
    p95: float
    p99: float


class ReportCluster(BaseModel):
    """One attack cluster summary in the monthly report."""
    centroid_hash: str
    member_count: int
    top_category: Optional[str]
    first_seen_at: Optional[datetime]
    last_seen_at: Optional[datetime]
    example_snippet: str


class ReportSignature(BaseModel):
    """Top attack signature summary."""
    signature_hash: str
    count: int
    top_category: Optional[str]
    first_seen_at: datetime
    last_seen_at: datetime
    example_snippet: str


class MonthlyReportResponse(BaseModel):
    """Full monthly security posture report.

    All sections are org-scoped (if the caller belongs to an org) or
    user-scoped otherwise.  The ``format`` field is always ``"json"``
    in this version; future versions may add ``"pdf"`` and ``"csv"``.

    Sections
    --------
    trends          — daily scan breakdown (total / allow / warn / block / block_rate)
    anomalies       — Z-score anomalies detected in the window
    top_clusters    — top attack clusters by member count
    top_signatures  — top threat signatures by hit count
    usage           — quota consumption for the billing period
    risk_percentile — statistical distribution of risk scores
    """
    generated_at: datetime          # UTC timestamp of report generation
    period: str                     # "YYYY-MM" of the primary month reported
    window_days: int                # actual lookback window used
    format: str = "json"

    # ── Section 1: Trends ────────────────────────────────────────────────────
    trends: List[ReportTrendPoint]
    total_scans: int
    total_allows: int
    total_warns: int
    total_blocks: int
    avg_block_rate: float           # mean of daily block_rate values
    top_categories: Dict[str, int]  # category → scan count, top 10

    # ── Section 2: Anomalies ─────────────────────────────────────────────────
    anomalies: List[AnomalyItem]
    anomaly_count: int
    critical_anomaly_count: int

    # ── Section 3: Top Clusters ───────────────────────────────────────────────
    top_clusters: List[ReportCluster]

    # ── Section 4: Top Signatures ─────────────────────────────────────────────
    top_signatures: List[ReportSignature]

    # ── Section 5: Usage ─────────────────────────────────────────────────────
    usage: ReportUsage

    # ── Section 6: Risk Percentile ────────────────────────────────────────────
    risk_percentile: ReportRiskPercentile


# ── PHASE 2.7 — Signature Clustering ─────────────────────────────────────────

class SignatureClusterItem(BaseModel):
    """One signature cluster returned by GET /threats/clusters (PHASE 2.7)."""
    cluster_id: str
    signature_count: int
    top_category: Optional[str]


# ── PHASE 2.5 — Enterprise Monthly Security Report ────────────────────────────

class EnterpriseReportResponse(BaseModel):
    """Executive-level monthly security report (PHASE 2.5).

    Aggregates guard scan activity for a calendar month, enriched with
    model-risk profiling.  Scoped to the caller's org (or user when no org).
    """
    month: str                              # YYYY-MM
    org_id: Optional[int]
    total_scans: int
    blocked_scans: int
    warn_scans: int
    block_rate: float                       # blocked / total (0.0 when no scans)
    top_categories: Dict[str, int]          # category → scan count, up to 10
    top_signatures: List[Dict[str, Any]]    # [{hash, count, category}] up to 10
    model_risk_summary: List[Dict[str, Any]]  # ModelRiskProfileItem-shaped dicts


# ── PHASE 2.20 — Monthly Enterprise Report ────────────────────────────────────

class MonthlyEnterpriseReportResponse(EnterpriseReportResponse):
    """PHASE 2.20 — full monthly enterprise export (superset of EnterpriseReportResponse).

    Adds the missing fields required for a self-contained enterprise export:
    allow_scans, anomaly_count, usage_summary.
    """
    allow_scans: int = 0                        # scans that resulted in "allow"
    anomaly_count: int = 0                      # z-score anomalies detected in the month
    usage_summary: Dict[str, Any] = Field(default_factory=dict)  # quota/usage for the period


# ── PHASE 2.16 — SIEM / SOC Export ───────────────────────────────────────────

class SecurityEventExportItem(BaseModel):
    """One security event row for SIEM/SOC export (PHASE 2.16).

    Sourced from GuardScanRecord (event_type='guard_scan') or AuditEvent.
    No raw payloads — only metadata safe for external pipelines.
    """
    created_at: str                          # ISO-8601 UTC timestamp
    event_type: str                          # 'guard_scan' | audit event type
    decision: str                            # allow | warn | block | ""
    severity: str                            # low | medium | high | critical | ""
    categories: List[str]
    signature_hash: str
    cluster_id: str
    elapsed_ms: int
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None


class SecurityExportResponse(BaseModel):
    """PHASE 2.16 — JSON export envelope."""
    total: int
    events: List[SecurityEventExportItem]


class PerformanceAnalyticsResponse(BaseModel):
    """PHASE 2.22 — guard latency and stage-timing summary."""
    window_days: int
    total_scans: int
    avg_elapsed_ms: float
    p95_elapsed_ms: float
    slow_scan_count: int                                     # elapsed_ms > 50 ms
    avg_stage_timings: Dict[str, float] = Field(default_factory=dict)


class AttackerPatternMetricItem(BaseModel):
    """PHASE 2.26 — one row from AttackerPatternMetric table."""
    id: int
    created_at: datetime
    org_id: Optional[int]
    user_id: Optional[int]
    pattern_type: str
    score: float
    metadata_json: str = "{}"


class AttackerPatternMetricResponse(BaseModel):
    """PHASE 2.26 — recent attacker pattern events."""
    items: List[AttackerPatternMetricItem]
    total: int
    window_days: int


class ExecutiveSummaryResponse(BaseModel):
    """PHASE 2.28 — executive / investor monthly summary."""
    month: str
    total_scans: int
    blocked_scans: int
    warn_scans: int
    block_rate: float
    avg_elapsed_ms: float
    top_categories: Dict[str, int] = Field(default_factory=dict)
    top_signatures: List[Dict[str, Any]] = Field(default_factory=list)
    active_org_count: int
    total_campaigns: int
    summary_text: str


class SecurityScorecardResponse(BaseModel):
    """PHASE 2.29 — security scorecard for an org."""
    org_id: int
    exposure_score: int           # 0–100; higher = more exposed
    control_maturity_score: int   # 0–100; higher = more mature controls
    threat_pressure_score: int    # 0–100; higher = more active threats
    overall_grade: str            # A / B / C / D / F
    contributing_factors: List[str]


class PublicTrustStatusResponse(BaseModel):
    """PHASE 2.30 — customer-facing trust / status response (no tenant data)."""
    service_status: str               # ok | degraded
    guard_enabled: bool
    billing_configured: bool
    rate_limit_mode: str              # memory | redis | disabled
    supported_capabilities: List[str]
    version: str


# ── PHASE 2.41 — Trust Center capabilities list ───────────────────────────────

class TrustCapabilityItem(BaseModel):
    name: str
    description: str


class TrustCapabilitiesResponse(BaseModel):
    capabilities: List[TrustCapabilityItem]


# ── PHASE 2.33 — Prompt Mutation Engine ───────────────────────────────────────

class PromptMutationRequest(BaseModel):
    base_prompt: str = Field(..., min_length=1, max_length=10_000)
    count: int = Field(default=10, ge=1, le=50)
    deterministic: bool = True


class PromptMutationResponse(BaseModel):
    base_prompt: str
    variants: List[str]


# ── PHASE 2.34 — Adversarial Red-Team Generator ───────────────────────────────

class RedTeamGenerateRequest(BaseModel):
    category: str = Field(..., min_length=1, max_length=64)
    target_count: int = Field(default=20, ge=1, le=100)
    deterministic: bool = True


class RedTeamGenerateResponse(BaseModel):
    category: str
    prompts: List[str]

