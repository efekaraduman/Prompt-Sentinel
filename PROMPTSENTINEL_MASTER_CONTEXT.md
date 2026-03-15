# PromptSentinel — Internal Architecture Brief

> Classification: Internal Engineering Document — Not for External Distribution
> Version: 0.3.0 | Updated: 2026-03-10

---

## 1. Project Overview

**PromptSentinel** is an LLM security platform that combines offensive red-team testing with defensive runtime protection, delivered as a multi-tenant SaaS product.

**Problem statement.** LLM applications accept natural-language input with no compile-time guarantees. Adversarial prompts can override system instructions, leak confidential context, exfiltrate secrets via tool calls, or poison RAG pipelines. These attack surfaces are unbounded, model-agnostic, and invisible to traditional application security tooling.

**What PromptSentinel does.** It provides two complementary capabilities:
1. **Pre-deployment red-teaming** — automated campaign engine that systematically probes a system prompt across five attack categories with adaptive strategies and obfuscation.
2. **Runtime guard** — stateless detector pipeline that scores and blocks malicious inputs/outputs in production, with policy-driven enforcement per plan tier.

Both capabilities feed a shared **threat intelligence layer** that clusters attack patterns, detects anomalies, and exports to enterprise SIEM systems.

---

## 2. Product Positioning

PromptSentinel occupies the same problem space as Lakera Guard (runtime LLM firewall) and Lakera Red (automated red-teaming), but differs in several architectural and product decisions:

| Dimension | Lakera Guard / Red | PromptSentinel |
|-----------|-------------------|----------------|
| **Deployment** | Cloud-hosted API, vendor-managed | Self-hostable single binary, SQLite-backed, no external dependencies required |
| **Detection approach** | ML classifiers (proprietary models) | Rule-based detector pipeline (regex, n-gram, pattern matching) — deterministic, auditable, no model dependency |
| **Red-teaming** | Separate product (Lakera Red) | Unified platform — campaigns and guard share the same threat model, signatures, and analytics |
| **Threat intelligence** | Proprietary threat feed | Built-in signature registry, MinHash clustering, z-score anomaly detection, SIEM export (CEF + JSON) |
| **Multi-tenancy** | Per-API-key isolation | Org/team model with role-based access, org-scoped usage pools, per-org SIEM webhooks |
| **Pricing model** | Per-request usage-based | Tiered plans (free/pro) with monthly quotas and Stripe billing |
| **Customization** | Limited policy toggles | Full policy objects per scan — toggle individual detectors, set consensus thresholds, define tool allowlists, configure timeout budgets |

**Key differentiator:** PromptSentinel is a single deployable artifact that runs red-team campaigns and runtime guard from the same codebase, sharing signatures, risk models, and analytics. No ML inference dependency means latency is bounded and behavior is reproducible.

---

## 3. Design Principles

### Privacy-Safe Storage
Guard scan records store only truncated snippets (first 500 characters). Full payloads exist only in the async `GuardScan` table with hard size limits. PII redaction runs before audit logs and exports. No scan content leaves the system unless explicitly exported by the user.

### Minimal Coupling
Each subsystem (guard, campaigns, billing, analytics) is a separate Python module with no circular imports. The guard pipeline uses a detector protocol — detectors are callables that receive a request and return reasons. Adding a detector does not require modifying the pipeline. Billing is optional (disabled when Stripe keys are unset). Redis is optional (single-worker mode uses DB-backed rate limiting).

### Deterministic Behavior
When `policy.deterministic=true`, detectors execute in stable order and produce identical results for identical inputs. Signature hashing uses SHA-256 over normalized text. MinHash clustering uses FNV-32 with no random seeds. Risk scoring is pure arithmetic — no stochastic components.

### Model-Agnostic Guard
The guard pipeline does not call any LLM. Detection is entirely rule-based: regex patterns, n-gram overlap, secret-pattern matching, allowlist enforcement. This means guard latency is bounded (sub-millisecond per detector), there is no inference cost, and behavior does not drift with model updates. The `model` field in scan requests is metadata for analytics, not a routing decision.

### Plan-Aware Enforcement
Every request passes through identity middleware that resolves the caller's plan (public/free/pro) from their API key, user record, or org membership. Plan resolution happens once per request and propagates to rate limiting, quota enforcement, policy defaults, and feature gating. Pro plans get permissive defaults (medium-risk passthrough, higher rate limits); free/public plans get strict defaults.

---

## 4. System Architecture

### Four Pillars

The platform is organized into four distinct capability layers:

```
┌─────────────────────────────────────────────────────────┐
│                   SaaS Platform Layer                    │
│  Auth · Billing · Orgs · Usage Metering · Rate Limiting │
├──────────────────┬──────────────────┬───────────────────┤
│ Runtime          │ Red-Team         │ Enterprise        │
│ Protection       │ Testing          │ Analytics         │
│                  │                  │                   │
│ Guard pipeline   │ Campaign engine  │ Signatures        │
│ Detectors (7)    │ Red agent        │ Clustering        │
│ Policy engine    │ Attack strategies│ Anomaly detection │
│ Risk scoring     │ Obfuscation      │ SIEM export       │
│ Sync + async     │ Multi-turn chains│ Threat graphs     │
│ Decision logic   │ Metrics + export │ Model profiling   │
├──────────────────┴──────────────────┴───────────────────┤
│                    Storage Layer                         │
│         SQLite (WAL) · 20+ tables · SQLModel ORM        │
└─────────────────────────────────────────────────────────┘
```

### Backend Stack
| Component | Technology |
|-----------|-----------|
| Framework | FastAPI 0.133, Uvicorn |
| Language | Python 3.12 |
| ORM | SQLModel 0.0.24 (Pydantic v2 + SQLAlchemy) |
| Database | SQLite, WAL mode |
| Billing | Stripe 14.x (optional) |
| Rate limiting | DB-backed sliding window; Redis 5.x for multi-worker |
| Email | SMTP (optional, for magic-link auth) |

### Frontend Stack
| Component | Technology |
|-----------|-----------|
| Framework | Next.js 16.1 (App Router) |
| Language | TypeScript 5 |
| UI | React 19.2, Tailwind CSS 4 |
| HTTP client | Axios with X-API-Key injection |

### Auth Model
Three methods, resolved in priority order:
1. **API key** (`X-API-Key`) — master admin key or per-user key, looked up in `User` table.
2. **Email/password** — PBKDF2-SHA256 (600k iterations). Returns `SessionToken`.
3. **Magic link** — hashed token emailed via SMTP, redeemed for `SessionToken`.

Identity middleware runs on every request, populating `request.state.{user_id, org_id, user_plan}`. Plan is resolved as: org plan (if member) > user plan > `'public'`.

### Rate Limiting
DB-backed 60-second sliding window. One `RateLimitEvent` row per accepted request. Bucket resolution:
- Org member → `bucket_id = org_id` (shared pool)
- Individual user → `bucket_id = -user_id`
- Unauthenticated → `bucket_id = -(1_000_000 + ip_hash % 1_000_000)`

Limits: public 30/min, free 60/min, pro 300/min. Probabilistic cleanup (1-in-50, prunes rows > 5 min). Redis mode available via `REDIS_URL` for multi-worker deployments.

---

## 5. Runtime Protection

The guard is a stateless detector pipeline invoked via `POST /guard/scan`. It accepts input text, output text, optional context, retrieved documents, tool calls, and a baseline output. It returns a risk score, decision, matched categories, per-detector reasons, and optional mitigation suggestions.

### Detector Pipeline

Detectors implement a protocol: receive scan request, return `list[Reason]` with severity. Pipeline runs all active detectors (sequential by default, stable-ordered when `deterministic=true`), merges results, and feeds them to the risk analyzer.

| Detector | Input | Detection Logic |
|----------|-------|----------------|
| **Injection** | `input_text` | Regex for injection markers, role-override phrases, system-prompt disclosure patterns |
| **PII / Secrets** | `input_text` + `output_text` | Pattern library: AWS keys, GitHub tokens, JWTs, SSNs, Google/OpenAI API keys, generic key formats |
| **RAG** | `retrieved_docs` | Injection markers in documents, conflicting facts, high-entropy insertions |
| **Tool** | `tool_calls` | Allowlist enforcement, argument schema deviation, exfiltration URLs (ngrok, Base64-encoded), system override in args |
| **Hallucination** | `output_text` vs `baseline_output` | Consistency divergence detection (opt-in) |
| **Consensus** | aggregate scores | Cross-detector agreement metric (0-100); low consensus can trigger block |
| **Performance** | meta | Per-detector `elapsed_ms` tracking; flags timeout against `max_elapsed_ms` budget |

### Risk Scoring (0-100)
- **Leakage confidence:** system-prompt markers, delimiter patterns, n-gram overlap with system prompt, secret pattern hits.
- **Override confidence:** override marker phrases, instruction hierarchy manipulation.
- **Detector score weights** (applied in `run_pipeline` before accumulation): `injection` 1.5x, `rag` 1.4x, `pii` 1.3x, `hallucination` 1.2x, `tool` 1.15x. Unregistered detectors default to 1.0x. Defined in `guard_pipeline.DETECTOR_WEIGHTS`.
- **Category multipliers** (applied post-pipeline in `run_guard_scan`): `data_exfiltration` 1.3x, `policy_leakage` 1.2x, `tool_misuse` 1.15x, `instruction_override` 1.1x, `role_confusion` 1.0x.
- **Normalization:** z-score against 30-day scan baseline.
- **Calibration:** percentile rank within the 30-day window → calibrated 0-100 score.

### Decision Logic
```
critical flag from any detector  → block
risk_score ≥ high_threshold      → block  (if policy.block_high_risk)
injection detected               → block  (if policy.block_injection)
PII detected                     → block  (if policy.block_pii)
RAG injection detected           → block  (if policy.block_rag_injection)
tool abuse detected              → block  (if policy.block_tool_abuse)
consensus < min_consensus        → block  (if policy.block_on_low_consensus)
risk_score ≥ medium_threshold    → block on free/public; allow on pro
else                             → allow
```

### Policy Object
Policies are per-request. Fields include: `block_injection`, `block_pii`, `block_high_risk`, `allow_medium`, `block_hallucination`, `block_rag_injection`, `block_tool_abuse`, `tool_allowlist`, `max_elapsed_ms`, `deterministic`, `block_on_low_consensus`, `min_consensus_to_allow`. Plan-tier defaults are applied when no explicit policy is provided.

### Async Mode
When `async_mode=true`, the scan is queued as a `GuardScan` row (status `queued`). A background worker claims batches via CAS update, runs `run_scan_sync()`, writes `result_json`, and flips status to `completed`. Clients poll `GET /guard/scans/{id}`.

---

## 6. Red-Team Testing

The campaign engine runs automated, multi-iteration attack simulations against a target system prompt.

### Attack Taxonomy
| Category | Description | Example Vectors |
|----------|-------------|-----------------|
| `role_confusion` | Identity/role assumption | DAN prompts, admin impersonation, maintenance mode claims |
| `instruction_override` | System prompt suppression | Priority override, emergency patch, authorization bypass |
| `policy_leakage` | System prompt disclosure | Debug output requests, config summaries, encoding tricks |
| `data_exfiltration` | Secret/credential extraction | Credential enumeration, Base64/hex encoding exfil |
| `tool_misuse` | Unauthorized tool invocation | Shell injection in args, SQL in args, tool chaining |

### Red Agent
Adaptive attacker implemented in `red_agent.py`:
- **Seed prompts:** 5-8 base templates per category.
- **Pretexts:** 8 social-engineering wrappers (`[DEBUG]`, `[AUDIT]`, `[COMPLIANCE]`, etc.).
- **Output formats:** json, bullet_list, stepwise, code_block, roleplay.
- **Obfuscation transforms:** base64 (single/nested), zero-width Unicode, homoglyph substitution, HTML comment injection, mixed encoding.

### Multi-Turn Strategies
| Strategy | Approach |
|----------|---------|
| `trust_then_exploit` | Build rapport with benign exchanges, then escalate |
| `role_escalation` | Gradual admin privilege claims over turns |
| `incremental_disclosure` | Extract secrets byte-by-byte across turns |
| `rag_injection` | Poison retrieved context to trigger leakage |
| `tool_argument_injection` | Smuggle payloads in tool call arguments |

### Campaign Lifecycle
1. `POST /campaigns` — queue campaign (system_prompt, model, iterations 1-5000, optional category filter).
2. Worker claims via CAS (`UPDATE ... WHERE status='queued'`).
3. Per iteration: generate attack → simulate response → run guard → store `Finding`.
4. Metrics aggregated in `Campaign.metrics_json`: max/avg risk, success rate, per-category breakdowns, per-transform counts.
5. Supports `stop`, `retry`, paginated `findings`, `export` (JSON/CSV), and `diff` between two campaigns.

---

## 7. Enterprise Analytics

### Attack Signatures
Every guard scan produces a signature: SHA-256 of normalized input (lowercase, strip invisible chars, collapse whitespace). `AttackSignature` deduplicates by hash, tracks count, first/last seen, top category, and example snippet.

### MinHash Sketch Clustering
Deterministic, no-randomness clustering:
1. Extract word trigrams from normalized text.
2. Hash each trigram with FNV-32.
3. Take K=16 smallest hashes → sketch vector.
4. `cluster_id = SHA-256("|".join(sketch))`.

Similar inputs share sketch-derived cluster IDs. `ThreatCluster` + `ThreatClusterMember` store the mapping. Exposed via `/threats/clusters/top` and `/analytics/clusters`.

### Anomaly Detection
- **Baseline:** 14-day rolling window of daily scan counts, block rates, per-category activity.
- **Z-score thresholds:** warning at 2.5σ, critical at 4.0σ.
- **Granularity:** per-org, per-category, and per-cluster anomaly tracking.
- **Endpoint:** `GET /analytics/anomalies`.

### Emerging Threats
Daily fingerprints: `SHA-256(signature_hash + YYYY-MM-DD)`. Anonymized for cross-org trend detection. Endpoint: `GET /analytics/emerging`.

### Model Risk Profiling
Running-average risk score and block rate per model name, updated after every guard scan. Exposed via `GET /analytics/models`.

### SIEM Export
- **CEF v25** (ArcSight Common Event Format) with RFC-5424 syslog wrapping.
- **JSON** per-org threat feed.
- **Endpoint:** `GET /threats/feed` — params: `format` (cef/json), `hours` (1-168), `min_severity`, `limit` (1-10000), `syslog` (boolean).
- **Per-org webhooks:** `OrgWebhook` table stores URL + HMAC secret. Events are signed and POSTed to the org's endpoint.

### Threat Graph
`GET /threats/graph` returns nodes (signatures) and edges (Jaccard similarity between sketch vectors). Useful for visualizing attack cluster topology.

---

## 8. SaaS Platform

### Plan Matrix
| | Public | Free | Pro |
|---|--------|------|-----|
| Authentication | None | Required | Required |
| Guard scans/month | 100 | 100 | Unlimited |
| Campaign iterations/month | 20 | 20 | Unlimited |
| Rate limit | 30 req/min | 60 req/min | 300 req/min |
| Export (JSON/CSV) | No | Yes | Yes |
| Org/team support | No | No | Yes |
| Medium-risk passthrough | No | No | Yes |
| SIEM webhooks | No | No | Yes |

### Billing (Stripe)
- **Checkout:** `POST /billing/checkout-session` → Stripe-hosted checkout → webhook on success.
- **Portal:** `POST /billing/portal-session` → Stripe Customer Portal for plan management.
- **Webhooks:** signature-verified, idempotent (`StripeEvent.event_id` unique index). Handles `subscription.created` (upgrade), `.updated` (renewal), `.deleted` (downgrade).
- **Scope:** both `User` and `Organization` carry `stripe_customer_id` + `stripe_subscription_id`.

### Organizations
`Organization` has its own plan and Stripe fields. `OrgMember` maps users to orgs with RBAC roles (`viewer` < `analyst` < `admin` < `owner`). Org-scoped isolation: campaigns, scans, usage, and audit logs are filtered by `org_id`. Role hierarchy enforced per endpoint via `require_min_role(min_role)` dependency factory in `auth.py`. Global admins (master API key) always bypass to owner level.

### Usage Metering
- **Tables:** `MonthlyUsage` (per-user), `OrgUsageMonth` (per-org aggregate).
- **Counters:** `guard_scans`, `campaigns_started`, keyed by `period_yyyymm`.
- **Enforcement:** checked before processing; returns HTTP 402 when quota exceeded.
- **Notifications:** threshold alerts at 80% and 100% consumption, deduplicated per `(period, user, kind)` via `UsageNotification`.
- **Upgrade banner:** `GET /billing/upgrade-banner` returns `near_limit` / `reached` / `feature_locked` / `null`.

### Audit
Append-only `AuditLog` table: `created_at`, `org_id`, `user_id`, `action`, `resource_type`, `metadata_json`. Tracks plan changes, member additions, webhook deliveries, quota breaches. Queryable via `GET /admin/audit` (global) and `GET /audit/logs` (org-scoped).

---

## 9. Data Model Summary

### Identity & Access
| Table | Purpose | Key Fields |
|-------|---------|-----------|
| `User` | Platform user | `id`, `email`, `api_key`, `plan`, `is_active`, `is_admin`, `org_id`, `stripe_customer_id` |
| `Organization` | Team account | `id`, `name`, `plan`, `stripe_customer_id`, `stripe_subscription_id` |
| `OrgMember` | User-org mapping | `org_id`, `user_id`, `role` (viewer/analyst/admin/owner) |
| `SessionToken` | Login session | `token`, `user_id`, `expires_at` (30-day TTL), `is_active` |
| `LoginToken` | Magic-link token | `email`, `token_hash`, `expires_at` |

### Red-Team Testing
| Table | Purpose | Key Fields |
|-------|---------|-----------|
| `Campaign` | Attack campaign | `id`, `status`, `system_prompt`, `iterations_total`, `iterations_done`, `metrics_json`, `org_id` |
| `Finding` | Single attack result | `campaign_id`, `iteration`, `category`, `attack_prompt`, `llm_response`, `risk_score`, `leakage_detected`, `override_detected` |

### Runtime Guard
| Table | Purpose | Key Fields |
|-------|---------|-----------|
| `GuardScan` | Full async scan payload | `id`, `input_text`, `output_text`, `policy_json`, `result_json`, `status`, `decision`, `severity` |
| `GuardScanRecord` | Privacy-safe scan log | `created_at`, `user_id`, `org_id`, `signature_hash`, `severity`, `decision`, `categories_json`, `input_snippet`, `output_snippet` |

### Threat Intelligence
| Table | Purpose | Key Fields |
|-------|---------|-----------|
| `AttackSignature` | Deduplicated threat signature | `signature_hash` (unique), `count`, `top_category`, `first_seen_at`, `last_seen_at`, `example_snippet` |
| `ThreatCluster` | Sketch-based cluster | `id`, `centroid_hash` (unique), `member_count`, `top_category` |
| `ThreatClusterMember` | Signature-to-cluster map | `cluster_id`, `signature_hash` |
| `ThreatFingerprint` | Daily anonymized fingerprint | `day`, `fingerprint`, `count`, `top_category` |
| `ModelRiskProfile` | Per-model running average | `model_name`, `avg_risk`, `block_rate`, `sample_size` |

### Billing & Usage
| Table | Purpose | Key Fields |
|-------|---------|-----------|
| `StripeEvent` | Webhook idempotency | `event_id` (unique), `event_type`, `status`, `user_id`, `org_id` |
| `MonthlyUsage` | Per-user monthly counters | `period_yyyymm`, `user_id`, `org_id`, `guard_scans`, `campaigns_started` |
| `OrgUsageMonth` | Org-level monthly totals | `org_id`, `ym`, `guard_scans`, `campaigns_created` |
| `UsageNotification` | Threshold alert dedup | `period_yyyymm`, `user_id`, `kind` |

### Operations
| Table | Purpose | Key Fields |
|-------|---------|-----------|
| `AuditLog` | Append-only action trail | `created_at`, `org_id`, `user_id`, `action`, `resource_type`, `metadata_json` |
| `RateLimitEvent` | Sliding-window rate limit | `org_id` (bucket), `endpoint`, `created_at` |
| `DistributedLock` | DB-backed mutex | `key`, `owner`, `expires_at` |
| `OrgWebhook` | Per-org SIEM webhook | `org_id`, `url`, `secret` (HMAC), `is_active` |

---

## 10. API Surface Summary

75+ endpoints organized into the following groups:

### Health & Identity
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/health` | Liveness probe |
| GET | `/me` | Current user info, plan, limits |
| GET | `/me/usage` | Per-user usage in current period |

### Runtime Guard
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/guard/scan` | Synchronous or async guard scan |
| POST | `/guard/simulate` | Dry-run: compare current vs stricter policy, no DB writes, no usage increment |
| POST | `/guard/harden` | Structured hardening suggestions in three buckets (system_prompt / tool_schema / retrieval), no DB writes |
| GET | `/guard/scans/{id}` | Poll async scan result |
| GET | `/guard/history` | Paginated privacy-safe scan log |
| GET | `/guard/history/export` | CSV export of scan history |

### Red-Team Campaigns
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/campaigns` | Create campaign (queued) |
| GET | `/campaigns/{id}` | Campaign status + metrics |
| GET | `/campaigns/{id}/findings` | Paginated findings |
| POST | `/campaigns/{id}/stop` | Stop running campaign |
| GET | `/campaigns/{id}/export` | JSON/CSV export |
| GET | `/campaigns/diff` | Diff two campaigns |

### Threat Intelligence
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/threats/feed` | SIEM feed (CEF/JSON) |
| GET | `/threats/trend` | Daily threat trend |
| GET | `/threats/top` | Top signatures by recency |
| GET | `/threats/clusters` | Sketch-based clusters |
| GET | `/threats/clusters/top` | Top clusters by member count |
| GET | `/threats/graph` | Signature similarity graph |

### Analytics
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/analytics/guard` | Guard scan summary |
| GET | `/analytics/guard/trend` | Daily guard trends |
| GET | `/analytics/guard/overview` | Combined analytics |
| GET | `/analytics/models` | Per-model risk profiles |
| GET | `/analytics/clusters` | Daily cluster activity |
| GET | `/analytics/anomalies` | Z-score anomaly alerts |
| GET | `/analytics/emerging` | Emerging threat fingerprints |
| GET | `/analytics/signatures/top` | Top signatures |
| GET | `/analytics/threat-trend` | Org-scoped daily trends |
| GET | `/analytics/attackers` | Top attackers by pattern score, org-scoped (ADVANCED) |

### Dashboard
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/dashboard/summary` | Global aggregate stats |
| GET | `/dashboard/recent` | Recent campaigns with metrics |
| GET | `/dashboard/risk-trend` | Risk trends over time |

### Billing
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/billing/checkout-session` | Create Stripe checkout |
| POST | `/billing/portal-session` | Stripe customer portal |
| POST | `/billing/webhook` | Stripe webhook receiver |
| GET | `/billing/upgrade-banner` | UI upgrade banner state |

### Authentication
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/auth/signup` | Email/password registration |
| POST | `/auth/login-password` | Email/password login |
| POST | `/auth/login` | Send magic-link email |
| POST | `/auth/redeem` | Redeem magic-link token |

### Admin
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/admin/users` | Create user |
| GET | `/admin/users` | List users |
| POST | `/admin/users/{id}/deactivate` | Deactivate user |
| POST | `/admin/users/{id}/rotate-key` | Rotate API key |
| POST | `/admin/orgs` | Create organization |
| GET | `/admin/orgs` | List organizations |
| POST | `/admin/orgs/{id}/members` | Add org member |
| GET | `/admin/analytics` | Global system analytics |
| GET | `/admin/audit` | Global audit log |
| PUT | `/admin/webhook` | Configure org SIEM webhook |
| GET | `/admin/webhook/deliveries` | Delivery history with status/retry info (E1) |
| GET | `/admin/webhook/dead-letters` | Dead-lettered delivery queue (E1) |

### Usage
| Method | Path | Purpose |
|--------|------|---------|
| GET | `/usage/status` | Combined usage + limits |
| GET | `/usage/remaining` | Org quota snapshot |
| GET | `/usage/summary` | Period summary with percentages |

---

## 11. Security Model

### Threat Coverage
| Threat | Detection Method |
|--------|-----------------|
| Prompt injection | Regex pattern library for injection markers, role-override phrases |
| System prompt leakage | N-gram overlap with system prompt, delimiter/marker detection |
| Data exfiltration | Secret pattern matching (AWS, GitHub, JWT, SSN, generic API keys) |
| Role confusion | Identity assumption pattern detection (DAN, admin impersonation) |
| Tool/function abuse | Allowlist enforcement, argument schema validation, exfiltration URL detection |
| RAG poisoning | Injection markers in retrieved docs, conflicting facts, entropy analysis |
| Hallucination drift | Baseline output divergence (opt-in) |

### Platform Hardening
- **Input validation:** Pydantic strict mode on all 80+ request models. Field size limits enforced (system_prompt 500KB, text fields 200KB).
- **Credential security:** API keys are unique random strings, never logged. Passwords hashed with PBKDF2-SHA256, 600k iterations (OWASP 2023). Session tokens are 32-byte cryptographically random.
- **RBAC:** `OrgMember.role` ∈ {`viewer`, `analyst`, `admin`, `owner`} — enforced via `require_min_role(min_role)` FastAPI dependency. Hierarchy: viewer(0) < analyst(1) < admin(2) < owner(3). Non-org users default to analyst. Admin env key bypasses to owner. Legacy role `"member"` auto-migrated to `"analyst"` on startup. Full enforcement matrix:
  - **viewer** — all read-only routes: dashboard, analytics, threats, guard history/export, audit logs, usage, billing banner, webhook config, campaign status/findings/diff
  - **analyst** — execution routes: `POST /guard/scan`, `POST /guard/simulate`, `POST /guard/harden`, `POST /campaigns`, `POST /campaigns/{id}/stop`, `GET /campaigns/{id}/export`
  - **admin** — org management: `PUT /admin/webhook`, `GET /admin/webhook/dead-letters`, org user CRUD (`POST/DELETE /org/users/*`)
  - **owner** — billing/plan changes: `POST /billing/checkout`, `POST /billing/checkout-session`, `POST /billing/checkout/pro`, `POST /billing/portal-session`
  - **global admin key** — platform admin only: all `/admin/*` endpoints, `POST /test-llm`
  - **public** — no auth required: `GET /health`, `GET /me`, auth flows, `POST /billing/webhook` (Stripe-signed), `GET /guard/scans/{id}` (anonymous scan polling)
- **Rate limiting:** enforced before any business logic. Per-IP for unauthenticated, per-user or per-org for authenticated.
- **Audit trail:** append-only, immutable. Covers all state mutations. Org-scoped and global visibility.
- **PII redaction:** applied before audit logs and data exports.
- **Privacy-safe logging:** `GuardScanRecord` stores truncated snippets only. Full payloads confined to async `GuardScan` table with size caps.
- **Billing isolation:** PCI compliance delegated to Stripe. Only customer IDs stored.

---

## 12. Known Constraints

| Constraint | Impact | Mitigation Path |
|------------|--------|-----------------|
| SQLite only | No clustering, serialized writes, no FTS | WAL mode for concurrent reads; PostgreSQL support planned |
| Single-worker default | One campaign at a time | Multi-worker with Redis + shared volume |
| No job queue | Polling-based campaign worker (CAS claiming) | Sufficient for current scale; Celery/RQ if needed |
| No WebSocket/SSE | Campaign progress via polling | Acceptable latency for current UX |
| No ML detection | Rule-based only, no learned classifiers | Deterministic and auditable by design; ML layer is a future option |
| Inline migrations | Schema changes in `db.py` on startup, no Alembic | Works for current velocity; versioned migrations for team scale |
| Single SMTP sender | One email origin for magic links | Sufficient for current auth flow |
| No reverse proxy config | Frontend :3000, backend :8000 in dev | Production deploys expected to bring their own ingress |

---

## 13. Current Development Stage

### Tier 1 — Production-Ready (Stable, Tested, Shipping)
- Guard scan pipeline: all 7 detectors, policy resolution, sync + async modes, risk scoring with calibration
- Campaign engine: full lifecycle (queue → run → stop → retry → export → diff), 5 categories, 5 strategies, 6 transforms
- Authentication: API key, email/password, magic link, 30-day sessions
- Stripe billing: checkout, portal, idempotent webhooks
- Rate limiting: DB-backed single-worker, Redis multi-worker
- Usage metering: per-user and per-org quotas with threshold notifications
- Audit logging: append-only, org-scoped
- Admin panel: user/org CRUD, key rotation, deactivation
- Frontend: dashboard, analytics, campaign management, pricing, auth flows
- Test suite: 52 golden vectors + ~180 parametrized variants; 34 SIEM unit tests

### Tier 2 — Enterprise-Hardening (Code Complete, Pending Production Validation)
Features in this tier are implemented and functional but have not yet been validated under production-scale load or multi-tenant stress testing.
- Org-scoped access control and multi-org membership
- SIEM export (CEF + JSON) with per-org HMAC-signed webhooks
- MinHash sketch clustering
- Z-score anomaly detection and emerging threat tracking
- Risk normalization and percentile calibration
- Consensus scoring across detectors
- Model risk profiling
- **Data retention** — org-level `retention_days` setting; worker purges `GuardScan`, `GuardScanRecord`, `AuditLog`, `AuditEvent` older than the window every 60 poll cycles. `PATCH /admin/orgs/{id}/retention`. Min 7 days.
- **Simulation mode** — `POST /guard/simulate` runs the full detection pipeline twice (current policy vs strict preset or caller-supplied policy). No DB writes, no usage increment. Returns `current`, `simulated`, `would_block`, `would_escalate_severity`, `risk_delta`.
- **Auto Hardening v2** — `POST /guard/harden` runs pipeline with `session=None` and returns structured `HardeningSuggestionsResponse` with three typed buckets: `system_prompt` (injection guards, anti-override clauses, PII prohibitions), `tool_schema` (allowlists, JSON Schema validation, URL blocking, secret-pattern auditing), `retrieval` (document sanitization, trust scoring, citation enforcement). Each suggestion carries `category`, `severity`, `title`, `description`, optional `example`. Ordered critical → high → medium within each bucket.
- **RBAC** — `OrgMember.role` expanded to `viewer | analyst | admin | owner` (hierarchy 0–3). `require_min_role(min_role)` factory in `auth.py` enforces per endpoint. Viewer: read-only (analytics, threats, history, dashboard, audit). Analyst: execute (guard/scan, guard/simulate, guard/harden, campaigns POST). Admin: org management (org/users write, webhook config, retention). Owner: reserved for billing/plan changes. Non-org users default to analyst. Admin env key → owner bypass. Legacy `"member"` role auto-migrated to `"analyst"` via startup data migration.
- **Attacker Behavior Profiling** — `app/attacker_profile.py` computes `attacker_pattern_score` (0–100) per scan using three signals: (1) **Rapid variant mutation** (0–40 pts) — ≥5 scans in 10 min, mean risk ≥40, ≥2 distinct category combos; (2) **Encoding cycling** (0–35 pts) — ≥2 distinct encoding types (base64, `\uXXXX`, `\xXX`, URL `%XX`, `0x` hex, invisible chars) across last 10 snippets; (3) **Repeated near-miss** (0–25 pts) — ≥3 scans with risk ∈ [50,99] not blocked in 15 min. Score stored on `GuardScanRecord.attacker_pattern_score`, returned in `GuardScanResponse` alongside `attacker_signals` dict. Score also included in SIEM webhook event payload and in `GET /guard/history` items. Anonymous scans score 0. Computed before `save_scan_record` (no circular contamination). `GET /analytics/attackers` — top attackers ranked by max score, org-scoped, filterable by `min_score` threshold and `days` window.
- **Max CPU Budget** — `GuardPolicy.max_detector_runtime_ms` (new field, `Optional[int]`, default `None`). When set, it replaces `max_elapsed_ms` as the effective hard time budget passed to `run_pipeline`. If the pipeline aborts early (detectors skipped), the existing `timed_out` flag is set and `"budget_exceeded"` is added to `performance_flags`. Additionally, when `max_detector_runtime_ms` is set and `timed_out=True`, the decision is escalated from `"allow"` to `"warn"` (blocking decisions are unchanged) and `"cpu budget exceeded — scan incomplete"` is appended to `reasons`. This ensures callers receive an explicit signal that the scan result is partial rather than silently allowing through.
- **Replay Testing** — Every sync guard scan generates a 32-bit `random_seed` via `random.randint(0, 2**31-1)`, seeds Python's `random` module before the pipeline, and stores the seed on `GuardScanRecord.random_seed`. A companion `GuardScanReplayStore` table (one row per scan, unique on `scan_record_id`) stores the full replay payload: `input_text`, `output_text`, `context_text`, `policy_json`, `random_seed`, `user_id`, `org_id`. `POST /guard/replay/{scan_id}` (analyst+) loads the store, reconstructs the policy with `deterministic=True`, re-seeds `random`, and re-runs the pipeline with `session=None` (no writes, no usage increment). Returns `GuardReplayResponse` with `original_scan_id`, `random_seed`, `replayed_at`, and the full `GuardScanResponse`. Ownership-checked (same user_id or org_id; admin bypass). Scans before replay support have no store → 409 with explanation. `GuardScanReplayStore` participates in org-level data retention cleanup.
- **Security Report Export** — `GET /report/monthly` (viewer+, rate-limited). Query params: `format=json` (only JSON in this version), `month=YYYY-MM` (defaults to current month), `days=7–90` (lookback window, default 30), `cluster_limit`, `sig_limit`. Scope: org if caller has `org_id`; individual user otherwise. Six sections in `MonthlyReportResponse`: (1) **Trends** — daily `ReportTrendPoint` (total/allow/warn/block/block_rate), plus totals and `top_categories` dict; (2) **Anomalies** — Z-score results from `detect_anomalies()` for `scans`, `block_rate`, and top-5 categories, deduplicated and sorted by `|z_score|`; (3) **Top Clusters** — `ThreatCluster` rows ordered by `member_count desc`; (4) **Top Signatures** — `AttackSignature` rows ordered by `count desc`; (5) **Usage** — `ReportUsage` with guard/campaign used/limit/remaining/pct, unlimited plans use `-1`; (6) **Risk Percentile** — P50/P75/P90/P95/P99 from `compute_risk_percentiles()` + mean/std from `compute_risk_baseline()`. New schemas: `ReportTrendPoint`, `ReportUsage`, `ReportRiskPercentile`, `ReportCluster`, `ReportSignature`, `MonthlyReportResponse`.
- **Strict Mode** — `Organization.strict_mode: bool` (default `False`). Inline migration `organization.strict_mode BOOLEAN NOT NULL DEFAULT 0`. Loaded once per scan in `run_guard_scan` via `session.get(Organization, org_id)` (best-effort; never raises). Two additional blocking rules applied **after** all regular policy checks: (1) **Medium severity → block** — if `severity == "medium"` and not already blocked, forces `block=True` + reason `"strict mode: medium severity blocked"` regardless of `allow_medium`; (2) **Override attempt → immediate block** — if `{"prompt_injection", "policy_leakage"} ∩ categories` and not already blocked, forces `block=True` + reason `"strict mode: override attempt blocked"` regardless of `block_injection` policy setting. Managed via `PATCH /admin/orgs/{org_id}/strict-mode` (admin key); body: `{"strict_mode": true/false}`. `OrgResponse` now includes `strict_mode: bool` field; all three OrgResponse construction sites updated.

### Tier 3 — Planned (Not Yet Implemented)
See **Section 14 — Future Hardening Roadmap** for scoped descriptions and priority order.

---

## 14. Future Hardening Roadmap

Ordered by priority. Each phase is independently shippable. Status reflects current state as of last update.

| Phase | Name | Status | Scope |
|-------|------|--------|-------|
| E1 | Webhook Reliability | **Complete** | Exponential backoff retry (6 attempts: 30s/2m/10m/1h/6h/dead-letter). `WebhookDelivery` queue table + `WebhookDeadLetter` table. Batch compression (≥3 pending events per org → single POST). Audit log on success (`webhook.delivered`) and dead-letter (`webhook.dead_lettered`). Worker runs `process_pending_deliveries()` every poll cycle. New endpoints: `GET /admin/webhook/deliveries`, `GET /admin/webhook/dead-letters`. |
| E2 | Org Analytics Dashboard | Not started | Org-level analytics page in frontend. Team member usage breakdown. Shared campaign library with org-wide visibility. Org-admin aggregate threat trends. |
| E3 | Performance Layer | Not started | Redis caching for analytics aggregations, signature lookups, and plan resolution. Cache invalidation tied to write events. Reduces SQLite read pressure at scale. |
| E4 | Parallel Detection | Not started | Run guard detectors concurrently (`asyncio.gather`) instead of sequentially. Reduces scan latency proportional to active detector count. Requires careful result merging. |
| E5 | Notification Integrations | Not started | Slack webhook for threshold alerts and anomaly notifications. PagerDuty incident creation for critical anomalies. Custom webhook templates for arbitrary endpoints. |
| E6 | PostgreSQL Support | Not started | Optional RDBMS backend for horizontal write scaling, full-text search, and versioned migrations. Feature-flagged — SQLite remains default for single-node deployments. |
| E7 | Custom Detector SDK | Not started | Plugin interface for user-defined detectors. Schema validation for input/output contracts. Sandboxed execution with timeout enforcement. |
| E8 | Compliance Reporting | Not started | Automated PDF/HTML security posture reports. Mappable to SOC 2, ISO 27001, and NIST AI RMF controls. Scheduled generation with org-scoped templates. |
