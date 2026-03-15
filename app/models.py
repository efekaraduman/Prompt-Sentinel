from __future__ import annotations

from datetime import date, datetime
from typing import Optional

from sqlalchemy import Index, UniqueConstraint
from sqlmodel import Field, SQLModel


class Organization(SQLModel, table=True):
    """Team / organisation that owns a plan and groups users."""

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True, unique=True, nullable=False, max_length=120)
    plan: str = Field(default="free", nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    # B12 — org-scoped Stripe billing
    stripe_customer_id: Optional[str] = Field(default=None, index=True, unique=True, nullable=True)
    stripe_subscription_id: Optional[str] = Field(default=None, index=True, nullable=True)
    # ENTERPRISE — data retention window in days (None = no purge)
    retention_days: Optional[int] = Field(default=None, nullable=True)
    # ADVANCED — Strict Mode: forces block on medium severity + override attempts
    strict_mode: bool = Field(default=False, nullable=False)
    # PHASE 2.18 — org-level default; applied when request doesn't set strict_mode
    strict_mode_default: bool = Field(default=False, nullable=False)
    # PHASE 2.27 — zero-trust: maximal posture, all medium+ blocked, no request override
    zero_trust_mode: bool = Field(default=False, nullable=False)


class User(SQLModel, table=True):
    """API user with a unique generated key."""

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, nullable=False, unique=True)
    api_key: str = Field(index=True, nullable=False, unique=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    is_active: bool = Field(default=True)
    password_hash: Optional[str] = Field(default=None, nullable=True)
    plan: str = Field(default="free", index=True, nullable=False)
    plan_expires_at: Optional[datetime] = Field(default=None, nullable=True)
    stripe_customer_id: Optional[str] = Field(default=None, index=True, unique=True, nullable=True)
    stripe_subscription_id: Optional[str] = Field(default=None, index=True, nullable=True)
    stripe_current_period_end: Optional[datetime] = Field(default=None, nullable=True)
    # B8.1 — org membership (nullable: existing users have no org)
    org_id: Optional[int] = Field(default=None, foreign_key="organization.id", nullable=True, index=True)
    # E3 — preferred org when user belongs to multiple orgs via OrgMember
    default_org_id: Optional[int] = Field(default=None, index=True)
    is_admin: bool = Field(default=False, nullable=False)


class SessionToken(SQLModel, table=True):
    """Short-lived opaque session token issued on email/password login."""

    id: Optional[int] = Field(default=None, primary_key=True)
    token: str = Field(index=True, unique=True, nullable=False)
    user_id: int = Field(foreign_key="user.id", nullable=False, index=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    expires_at: datetime = Field(nullable=False)
    is_active: bool = Field(default=True)


class OrgMember(SQLModel, table=True):
    """Many-to-many: users ↔ organisations with an explicit role (E3)."""

    __table_args__ = (
        UniqueConstraint("org_id", "user_id", name="uq_orgmember_org_user"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(foreign_key="organization.id", index=True, nullable=False)
    user_id: int = Field(foreign_key="user.id", index=True, nullable=False)
    # RBAC — viewer | analyst | admin | owner (legacy: member → analyst)
    role: str = Field(default="analyst", nullable=False)


class Campaign(SQLModel, table=True):
    """Persistent representation of a long-running prompt-injection campaign."""

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)

    status: str = Field(
        default="queued",
        nullable=False,
        index=True,
        description="queued | running | completed | failed | stopped",
    )

    system_prompt: str
    model: str

    iterations_total: int
    iterations_done: int = 0

    metrics_json: str = Field(
        default="{}",
        nullable=False,
        description="JSON-encoded aggregate metrics for the campaign.",
    )
    error_message: Optional[str] = None
    # E4 — org-scoped access control
    org_id: Optional[int] = Field(default=None, index=True, nullable=True)


class AttackSignature(SQLModel, table=True):
    """Deduplicated registry of seen input/output pairs for threat intel."""

    id: Optional[int] = Field(default=None, primary_key=True)
    signature_hash: str = Field(index=True, unique=True, nullable=False)
    first_seen_at: datetime = Field(nullable=False)
    last_seen_at: datetime = Field(nullable=False)
    count: int = Field(default=1, nullable=False)
    top_category: Optional[str] = Field(default=None, nullable=True)
    example_snippet: str = Field(default="", nullable=False)  # first 200 chars of normalised input
    cluster_id: Optional[str] = Field(default=None, nullable=True, index=True)  # PHASE 2.7


class ThreatCluster(SQLModel, table=True):
    """Representative cluster of similar attack signatures (Phase 3.2 / PHASE 2.15)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    updated_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    centroid_hash: str = Field(index=True, unique=True, nullable=False)  # = cluster_id string
    member_count: int = Field(default=1, nullable=False)
    top_category: Optional[str] = Field(default=None, nullable=True)
    example_snippet: str = Field(default="", nullable=False)
    example_signature_hash: Optional[str] = Field(default=None, nullable=True)  # PHASE 2.15


class ThreatClusterMember(SQLModel, table=True):
    """Maps each signature_hash to exactly one ThreatCluster (Phase 3.2)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    cluster_id: int = Field(foreign_key="threatcluster.id", index=True, nullable=False)
    signature_hash: str = Field(index=True, unique=True, nullable=False)


class Finding(SQLModel, table=True):
    """Single simulated attack attempt and its evaluated risk."""

    id: Optional[int] = Field(default=None, primary_key=True)

    campaign_id: int = Field(
        foreign_key="campaign.id",
        index=True,
    )

    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    iteration: int

    category: str
    attack_prompt: str
    llm_response: str

    leakage_detected: bool
    override_detected: bool
    risk_score: int = Field(index=True)

    notes: Optional[str] = None

    # Multi-turn attack chain (A)
    attack_chain_json: Optional[str] = Field(default=None)
    turn_count: Optional[int] = Field(default=None)

    # Obfuscation transform applied (B)
    transform_name: Optional[str] = Field(default=None)

    # Confidence score 0..1 (C)
    confidence_score: Optional[float] = Field(default=None)


class LoginToken(SQLModel, table=True):
    """Single-use email magic-link token (only the sha256 hash is stored)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, nullable=False)
    token_hash: str = Field(index=True, unique=True, nullable=False)
    expires_at: datetime = Field(nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)


class AuditEvent(SQLModel, table=True):
    """Append-only audit log for key platform actions."""

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False, index=True)
    user_id: Optional[int] = Field(default=None, nullable=True, index=True)
    org_id: Optional[int] = Field(default=None, nullable=True, index=True)
    event_type: str = Field(nullable=False, index=True)
    resource_type: Optional[str] = Field(default=None, nullable=True, index=True)
    resource_id: Optional[str] = Field(default=None, nullable=True, index=True)
    ip: Optional[str] = Field(default=None, nullable=True)
    metadata_json: str = Field(default="{}", nullable=False)


class UsageCounter(SQLModel, table=True):
    """Per-user monthly usage counters (one row per user per YYYY-MM period)."""

    __table_args__ = (
        UniqueConstraint("user_id", "period_ym", name="uq_usagecounter_user_period"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id", index=True, nullable=False)
    period_ym: str = Field(nullable=False)          # "YYYY-MM"
    guard_scans: int = Field(default=0, nullable=False)
    campaign_iterations: int = Field(default=0, nullable=False)
    updated_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)


class MonthlyUsage(SQLModel, table=True):
    """Org-aware per-user monthly usage (Phase 1.2+). One row per user per period."""

    __table_args__ = (
        UniqueConstraint("period_yyyymm", "user_id", name="uq_monthlyusage_period_user"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    period_yyyymm: str = Field(index=True, nullable=False)   # "YYYY-MM"
    org_id: Optional[int] = Field(default=None, nullable=True, index=True)
    user_id: int = Field(index=True, nullable=False)
    guard_scans: int = Field(default=0, nullable=False)
    campaigns_started: int = Field(default=0, nullable=False)
    updated_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)


class UsageNotification(SQLModel, table=True):
    """Dedup log for threshold-crossing usage notifications (Phase 2.3).

    One row per (period, user_id, kind) — unique constraint prevents re-sending
    the same notification twice in the same billing period.

    kind values: "usage_80_guard" | "usage_80_campaigns"
                 | "usage_100_guard" | "usage_100_campaigns"
    """

    __table_args__ = (
        UniqueConstraint(
            "period_yyyymm", "user_id", "kind",
            name="uq_usagenotif_period_user_kind",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    period_yyyymm: str = Field(index=True, nullable=False)
    org_id: Optional[int] = Field(default=None, nullable=True, index=True)
    user_id: Optional[int] = Field(default=None, nullable=True, index=True)
    kind: str = Field(index=True, nullable=False)


class StripeEvent(SQLModel, table=True):
    """Idempotency log for Stripe webhook events.

    One row per Stripe event ID.  The unique index on ``event_id`` is the
    guard: a duplicate delivery hits an IntegrityError and is silently
    acknowledged without re-processing.

    status values: received | processed | ignored | failed
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    event_id: str = Field(index=True, unique=True, nullable=False, max_length=64)
    event_type: str = Field(index=True, nullable=False, max_length=80)
    received_at: datetime = Field(nullable=False)
    processed_at: Optional[datetime] = Field(default=None, nullable=True)
    # Nullable FKs — no cascade; events survive user deletion
    user_id: Optional[int] = Field(default=None, nullable=True)
    org_id: Optional[int] = Field(default=None, nullable=True)
    status: str = Field(default="received", nullable=False)
    error_message: Optional[str] = Field(default=None, nullable=True)


class GuardScanRecord(SQLModel, table=True):
    """Privacy-safe log of every /guard/scan invocation (no raw input/output stored)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False, index=True)
    user_id: Optional[int] = Field(default=None, nullable=True, index=True)
    org_id: Optional[int] = Field(default=None, nullable=True, index=True)
    input_hash: str = Field(index=True, nullable=False)       # sha256 of raw input text
    signature_hash: str = Field(index=True, nullable=False)   # from threat-intel pipeline
    severity: str = Field(nullable=False)
    decision: str = Field(nullable=False)
    categories_json: str = Field(default="[]", nullable=False)
    elapsed_ms: int = Field(default=0, nullable=False)
    blocked: bool = Field(default=False, nullable=False)
    plan: str = Field(default="public", nullable=False)
    timed_out: bool = Field(default=False, nullable=False)      # Phase 3.6
    detector_count: int = Field(default=0, nullable=False)      # Phase 3.6
    consensus_score: int = Field(default=0, nullable=False)     # Phase 3.7
    risk_score: int = Field(default=0, nullable=False)          # Phase 3.12.C
    sketch_cluster_id: Optional[str] = Field(default=None, index=True, nullable=True)  # Phase 3.15
    # ADVANCED — attacker behaviour profiling score (0–100); 0 = no pattern detected
    attacker_pattern_score: int = Field(default=0, nullable=False)
    rag_risk_score: int = Field(default=0, nullable=False)          # PHASE 2.1
    stage_timings_json: str = Field(default="{}", nullable=False)   # PHASE 2.8
    # ADVANCED — Replay Testing: seed used for any random operations during the scan
    random_seed: int = Field(default=0, nullable=False)
    # Audit/history fields — safe snippets, never full payload
    input_len: int = Field(default=0, nullable=False)
    output_len: int = Field(default=0, nullable=False)
    input_snippet: str = Field(default="", nullable=False)    # first 500 chars, redacted
    output_snippet: str = Field(default="", nullable=False)   # first 500 chars, redacted
    sandbox_mode: bool = Field(default=False, nullable=False)  # PHASE 2.35 — sandboxed scan flag


class AttackerPatternMetric(SQLModel, table=True):
    """PHASE 2.26 — event-level attacker pattern row (one per triggered signal per scan)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, index=True)
    org_id: Optional[int] = Field(default=None, index=True)
    user_id: Optional[int] = Field(default=None, index=True)
    pattern_type: str = Field(index=True)       # rapid_variant_mutation | encoding_cycling | near_miss_attacks
    score: float = Field(default=0.0)           # per-signal contribution (0–40 / 0–35 / 0–25)
    metadata_json: str = Field(default="{}")    # full attacker_signals dict, JSON-encoded


class OrgWebhook(SQLModel, table=True):
    """Per-org SIEM/SOAR webhook configuration (Phase 3.14)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(index=True, unique=True, nullable=False)
    url: str = Field(max_length=500, nullable=False)
    secret: str = Field(max_length=100, nullable=False)       # HMAC signing key
    is_active: bool = Field(default=True, nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False)
    last_error: Optional[str] = Field(default=None, nullable=True)
    last_sent_at: Optional[datetime] = Field(default=None, nullable=True)


class ThreatFingerprint(SQLModel, table=True):
    """Daily anonymized cross-org threat fingerprint (Phase 3.12.B).

    fingerprint = sha256(signature_hash + YYYY-MM-DD) — no raw data stored.
    """

    __table_args__ = (UniqueConstraint("day", "fingerprint"),)

    id: Optional[int] = Field(default=None, primary_key=True)
    day: date = Field(index=True, nullable=False)
    fingerprint: str = Field(index=True, nullable=False)
    count: int = Field(default=1, nullable=False)
    top_category: Optional[str] = Field(default=None, nullable=True)


class GuardScan(SQLModel, table=True):
    """Full async guard scan record — stores raw payload + complete result JSON.

    GuardScanRecord (privacy-safe log) is written by guard.py for every scan.
    GuardScan is written only for async requests and holds the full result so
    the client can poll GET /guard/scans/{id}.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False, index=True)
    user_id: Optional[int] = Field(default=None, nullable=True, index=True)
    org_id: Optional[int] = Field(default=None, nullable=True, index=True)   # E4
    plan: str = Field(default="public", nullable=False)
    # Truncated payload (50 k chars each)
    input_text: str = Field(default="", nullable=False)
    output_text: str = Field(default="", nullable=False)
    context_text: Optional[str] = Field(default=None, nullable=True)
    policy_json: str = Field(default="{}", nullable=False)
    # Result
    result_json: str = Field(default="{}", nullable=False)
    status: str = Field(default="queued", nullable=False, index=True)   # queued|completed|failed
    error_message: Optional[str] = Field(default=None, nullable=True)
    elapsed_ms: int = Field(default=0, nullable=False)
    decision: str = Field(default="allow", nullable=False)
    severity: str = Field(default="low", nullable=False)
    signature_hash: str = Field(default="", nullable=False, index=True)
    cluster_id: str = Field(default="", nullable=False, index=True)
    model_name: str = Field(default="unknown", nullable=False, max_length=120)


class OrgUsageMonth(SQLModel, table=True):
    """Org-scoped monthly usage counters — one row per (org_id, ym).

    Written by increment_guard / increment_campaign in usage.py.
    The unique constraint makes the upsert race-safe via IntegrityError retry.
    """

    __table_args__ = (
        UniqueConstraint("org_id", "ym", name="uq_orgusagemonth_org_ym"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(index=True, nullable=False)
    ym: str = Field(index=True, nullable=False)          # "YYYY-MM"
    guard_scans: int = Field(default=0, nullable=False)
    campaigns_created: int = Field(default=0, nullable=False)
    updated_at: datetime = Field(default_factory=datetime.utcnow, nullable=False, index=True)


class RateLimitEvent(SQLModel, table=True):
    """Sliding-window rate-limit log — one row per accepted request.

    bucket_id encodes the scope:
      org user            → org_id   (positive; all org members share quota)
      non-org user        → -user_id (negative; individual quota)
      anonymous / public  → derived from client IP (large negative int)

    The composite index (org_id, endpoint, created_at) covers the
    sliding-window COUNT query exactly, keeping it O(log n).
    """

    __table_args__ = (
        Index("ix_ratelimitevent_org_ep_ts", "org_id", "endpoint", "created_at"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(index=True, nullable=False)          # bucket_id (see docstring)
    endpoint: str = Field(index=True, nullable=False, max_length=20)  # "guard"|"campaigns"|"general"
    created_at: datetime = Field(index=True, nullable=False)


class DistributedLock(SQLModel, table=True):
    """DB-backed distributed lock — one row per currently held lock.

    acquire_lock() inserts a row; release_lock() deletes it.
    expires_at allows stale-lock eviction: a lock that outlived its TTL
    is forcibly deleted before the next INSERT attempt so crashed workers
    never permanently block a key.
    """

    key: str = Field(primary_key=True, max_length=120)
    owner: str = Field(nullable=False, max_length=80)      # PID + object-id token
    expires_at: datetime = Field(index=True, nullable=False)


class AuditLog(SQLModel, table=True):
    """Structured, append-only audit trail for security-relevant platform actions.

    action vocabulary (open-ended string, dotted namespacing):
      plan.changed        — plan upgraded or downgraded
      webhook.received    — Stripe webhook successfully dispatched
      member.added        — user joined an org
      member.updated      — org member role changed
      user.org_assigned   — user's org_id / default_org_id updated
      limit.breach        — monthly quota exceeded (402 raised)
      policy.override     — caller supplied non-default policy fields

    resource_type vocabulary: user | organization | org_member | quota |
                              webhook | guard_scan

    All columns nullable (except id, action, resource_type, created_at) so
    rows can be written safely even when partial context is available.
    """

    __table_args__ = (
        Index(
            "ix_auditlog_org_created",
            "org_id", "created_at",
        ),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(
        default_factory=datetime.utcnow, nullable=False, index=True
    )
    org_id: Optional[int] = Field(default=None, nullable=True, index=True)
    user_id: Optional[int] = Field(default=None, nullable=True, index=True)
    action: str = Field(nullable=False, index=True, max_length=60)
    resource_type: str = Field(nullable=False, index=True, max_length=40)
    resource_id: Optional[str] = Field(default=None, nullable=True, max_length=80)
    metadata_json: str = Field(default="{}", nullable=False)


class ModelRiskProfile(SQLModel, table=True):
    """Org-scoped running-average risk profile per model name (PHASE 2.0).

    Updated after every guard scan and campaign completion.
    Unique per (org_id, model_name); org_id=None means global/public callers.
    """

    __table_args__ = (
        UniqueConstraint("org_id", "model_name", name="uq_modelriskprofile_org_model"),
    )

    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: Optional[int] = Field(default=None, index=True)
    model_name: str = Field(index=True, max_length=120)
    sample_count: int = Field(default=0)
    avg_risk_score: float = Field(default=0.0)
    avg_consensus_score: float = Field(default=0.0)
    block_rate: float = Field(default=0.0)
    warn_rate: float = Field(default=0.0)
    updated_at: datetime = Field(default_factory=datetime.utcnow, index=True)


# ---------------------------------------------------------------------------
# E1 — Webhook Reliability
# ---------------------------------------------------------------------------

class WebhookDelivery(SQLModel, table=True):
    """Queued/retried SIEM webhook delivery attempt (E1).

    status values: pending | success | dead_lettered

    Retry schedule (exponential backoff, max 5 retries):
      retry 0  → now (first attempt)
      retry 1  → +30s
      retry 2  → +2min
      retry 3  → +10min
      retry 4  → +1h
      retry 5  → +6h  (after this → dead_lettered)
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(index=True, nullable=False)
    event_json: str = Field(nullable=False)                           # serialised event dict
    status: str = Field(default="pending", index=True, nullable=False)
    retry_count: int = Field(default=0, nullable=False)               # attempts made so far
    next_retry_at: datetime = Field(index=True, nullable=False)       # when worker should next attempt
    last_error: Optional[str] = Field(default=None, nullable=True, max_length=400)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False, index=True)
    delivered_at: Optional[datetime] = Field(default=None, nullable=True)


class WebhookDeadLetter(SQLModel, table=True):
    """Permanently failed webhook deliveries — exhausted all retries (E1).

    Stored for admin inspection and potential manual re-queueing.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    org_id: int = Field(index=True, nullable=False)
    event_json: str = Field(nullable=False)
    error_summary: str = Field(default="", nullable=False, max_length=800)
    retry_count: int = Field(default=0, nullable=False)
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False, index=True)


# ---------------------------------------------------------------------------
# ADVANCED — Replay Testing
# ---------------------------------------------------------------------------

class GuardScanReplayStore(SQLModel, table=True):
    """Full-payload store for deterministic scan replay (ADVANCED — Replay Testing).

    One row per GuardScanRecord.  Holds the raw inputs and the random seed
    that was used during the original scan so that ``POST /guard/replay/{scan_id}``
    can re-run the detection pipeline and produce the exact same result.

    Privacy note: this table intentionally stores the full (un-redacted) payload.
    Rows are subject to the same org-level data-retention window as GuardScanRecord
    and are purged by the worker retention pass.
    """

    id: Optional[int] = Field(default=None, primary_key=True)
    # 1-to-1 with GuardScanRecord.id
    scan_record_id: int = Field(index=True, unique=True, nullable=False)
    user_id: Optional[int] = Field(default=None, nullable=True, index=True)
    org_id: Optional[int] = Field(default=None, nullable=True, index=True)
    random_seed: int = Field(nullable=False)               # seed used during original scan
    input_text: str = Field(nullable=False)                # full raw input (up to 200 k)
    output_text: str = Field(default="", nullable=False)   # full raw output (may be empty)
    context_text: Optional[str] = Field(default=None, nullable=True)
    policy_json: str = Field(default="{}", nullable=False)  # effective policy at scan time
    created_at: datetime = Field(default_factory=datetime.utcnow, nullable=False, index=True)