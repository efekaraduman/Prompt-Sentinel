# PromptSentinel — Claude Session Handoff

> Token-efficient continuation brief. Full architecture: `PROMPTSENTINEL_MASTER_CONTEXT.md`

---

## What This Is

LLM security SaaS. Two capabilities: (1) red-team campaign engine that attacks system prompts across 5 categories, (2) runtime guard pipeline that scores and blocks malicious inputs in production. Shared threat intelligence layer (signatures, clustering, anomaly detection, SIEM export). Multi-tenant with orgs, Stripe billing, usage quotas.

## Stack

- **Backend:** FastAPI 0.133, Python 3.12, SQLModel (SQLite WAL), Pydantic v2
- **Frontend:** Next.js 16 App Router, React 19, TypeScript 5, Tailwind CSS 4
- **Optional:** Stripe (billing), Redis (multi-worker rate limiting), SMTP (magic-link auth)

## What Is Built (Production-Ready)

- Guard pipeline: 7 detectors (injection, PII, RAG, tool, hallucination, consensus, performance), policy engine, risk scoring 0-100, sync + async modes
- Campaign engine: 5 attack categories, 5 multi-turn strategies, 6 obfuscation transforms, adaptive red agent, CAS-based worker, metrics aggregation, export, diff
- Auth: API key + email/password (PBKDF2-SHA256) + magic link, 30-day sessions
- Billing: Stripe checkout/portal/webhooks, idempotent event processing, 3-tier plans (public/free/pro)
- Rate limiting: DB-backed sliding window, per-IP/user/org buckets, Redis mode for multi-worker
- Usage metering: per-user + per-org monthly quotas, 402 on exceeded, 80%/100% notifications
- Audit: append-only log, org-scoped
- Admin: user/org CRUD, key rotation, deactivation
- Frontend: dashboard, analytics, campaigns, admin, pricing, auth pages
- Tests: 52 golden vectors + ~180 variants, 34 SIEM unit tests

## What Is Built (Enterprise-Hardening, Pending Validation)

Org-scoped access control, SIEM export (CEF + JSON), per-org HMAC webhooks, MinHash sketch clustering, z-score anomaly detection, emerging threat fingerprints, risk normalization/calibration, consensus scoring, model risk profiling.

## Constraints — Always Respect

- **SQLite only.** No PostgreSQL. WAL mode. Writes serialize. Inline migrations in `db.py`, no Alembic.
- **Single-worker default.** Multi-worker needs Redis + shared DB volume.
- **No job queue.** Campaign worker polls with CAS claiming.
- **No WebSocket/SSE.** UI polls for progress.
- **No ML.** All detection is rule-based (regex, n-gram, pattern). Deterministic by design.
- **Billing is optional.** Disabled when `STRIPE_SECRET_KEY` is unset.
- **Redis is optional.** Single-worker uses DB-backed rate limiting.

## Coding Style

### Python
- `from __future__ import annotations` in every file
- Type hints on all function signatures. Union via `str | None`.
- `snake_case` functions/vars, `PascalCase` classes, `UPPER_SNAKE_CASE` constants, `_leading_underscore` for private
- Minimal docstrings — single-line when present, not on every function
- Phase markers in comments: `# Phase 3.x`, `# E6 —`
- Section dividers: `# ---------------------------------------------------------------------------`
- Imports: stdlib → third-party → local relative (`. import`)
- Pydantic `BaseModel` for schemas, SQLModel for DB models
- Custom exceptions for business logic errors

### TypeScript / React
- `"use client"` directive on all page/component files
- Functional components with hooks. No class components.
- `camelCase` vars/functions, `PascalCase` components/types, `UPPER_SNAKE_CASE` constants
- `import type { ... }` separate from value imports
- Types centralized in `lib/types.ts`
- API client centralized in `lib/api.ts`
- `strict: true` in tsconfig

### General
- No verbose docstrings. Comment only complex logic.
- Don't add features, error handling, or abstractions beyond what's requested.
- Keep modules decoupled. Guard, campaigns, billing, analytics are separate modules.
- Use existing patterns — check neighboring code before writing new patterns.

## Next Roadmap (Priority Order)

| Phase | Name | Summary |
|-------|------|---------|
| E1 | Webhook Reliability | Retry + backoff + dead-letter for SIEM webhooks |
| E2 | Org Analytics Dashboard | Org-level frontend analytics + team usage |
| E3 | Performance Layer | Redis caching for analytics + signature lookups |
| E4 | Parallel Detection | `asyncio.gather` for guard detectors |
| E5 | Notification Integrations | Slack, PagerDuty, custom webhook templates |
| E6 | PostgreSQL Support | Optional RDBMS, feature-flagged |
| E7 | Custom Detector SDK | Plugin interface for user-defined detectors |
| E8 | Compliance Reporting | SOC 2 / ISO 27001 report generation |

## Key Files

| File | What It Does |
|------|-------------|
| `app/main.py` | FastAPI app, 75+ routes |
| `app/schemas.py` | 80+ Pydantic request/response models |
| `app/models.py` | 20+ SQLModel DB tables |
| `app/guard.py` | Runtime guard pipeline + policy resolution |
| `app/guard_pipeline.py` | Detector protocol + merging |
| `app/risk_analyzer.py` | Risk scoring engine (0-100) |
| `app/campaigns.py` | Campaign lifecycle + metrics |
| `app/runner.py` | Single attack executor |
| `app/red_agent.py` | Adaptive red-team prompt generator |
| `app/billing.py` | Stripe integration |
| `app/usage.py` | Monthly quota tracking |
| `app/ratelimit.py` | Sliding-window rate limiter |
| `app/analytics.py` | Anomaly detection + aggregation |
| `app/clustering.py` | MinHash sketch clustering |
| `app/siem.py` | CEF + JSON SIEM export |
| `app/auth.py` | Auth helpers |
| `app/db.py` | SQLite connection + inline migrations |
| `PROMPTSENTINEL_MASTER_CONTEXT.md` | Full architecture doc (canonical) |

## How To Avoid Wasting Tokens

1. **Read before writing.** Always read the target file and its neighbors before editing. Don't guess at patterns.
2. **Check `PROMPTSENTINEL_MASTER_CONTEXT.md` first** for architecture questions instead of exploring the codebase from scratch.
3. **Don't re-explore what's documented.** The master context covers all tables, endpoints, detectors, and plan logic.
4. **Patch, don't rewrite.** Edit the specific function/section that needs changing. Don't rewrite entire files.
5. **Skip redundant validation.** If the master context says a feature exists, trust it. Only verify if something seems inconsistent.
6. **After major changes, patch the master context.** Update only the affected section — don't regenerate the whole doc.
7. **Use the golden tests.** Run `python tests/run_golden.py` to validate guard/risk changes. Run `python -m pytest tests/test_siem.py` for SIEM changes.
