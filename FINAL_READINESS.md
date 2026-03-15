# PromptSentinel — Final Readiness Review

_Reviewed: 2026-03-15 (Phase 2.42)_

---

## What Is Complete

| Area | Status |
|---|---|
| Guard pipeline (prompt-injection, PII, RAG, tool-abuse, hallucination, signature clustering) | ✅ Complete |
| Campaign engine (async, stop/retry, export, diff) | ✅ Complete |
| Analytics suite (daily trend, performance, scorecard, anomaly detection, executive summary) | ✅ Complete |
| Trust score / maturity index (`GET /analytics/trust-score`) | ✅ Complete |
| Cross-model consensus engine (`POST /analytics/consensus`) | ✅ Complete |
| Billing / Stripe integration (checkout, portal, webhooks, idempotency) | ✅ Complete |
| Auth system (API-key, magic-link, RBAC roles, org scoping) | ✅ Complete |
| Usage metering (org-level monthly quotas, plan enforcement, 402 responses) | ✅ Complete |
| Trust Center (public `/trust/status`, `/trust/capabilities`, `/trust` UI page) | ✅ Complete |
| SDK skeletons (Python stdlib, JS native-fetch) | ✅ Complete |
| Docker / deployment hardening (non-root user, healthcheck, VOLUME) | ✅ Complete |
| Golden regression suite (188/188 passing) | ✅ Complete |

---

## What Is Production-Ready

- **Single-tenant SaaS deployment** — all core paths (guard scan, campaign, billing, auth) are production-quality.
- **Rate limiting** — both in-memory (single worker) and Redis fixed-window (multi-worker) backends.
- **Billing** — Stripe checkout + portal + webhook idempotency guard on `stripeevent` table.
- **Org isolation** — campaign, guard scan, audit, and usage data are org-scoped throughout; admin key bypasses for multi-tenant ops.
- **Export safety** — all three export endpoints (`/guard/history/export`, `/audit/export`, `/export/security-events`) now enforce `allow_export_for(plan)` (fixed Phase 2.42).
- **Trust Center** — `/trust/status` and `/trust/capabilities` are fully public, contain no tenant data, and degrade gracefully if the API is unreachable.

---

## Known Limitations

| Limitation | Risk | Recommendation |
|---|---|---|
| `_check_campaign_org` skips check when `campaign.org_id is None` (legacy rows) | Low — only pre-multi-org data | Run migration: `UPDATE campaign SET org_id = <owner_org_id> WHERE org_id IS NULL` |
| Stripe `_ensure_*_customer` not protected by DB-level unique constraint on concurrent create | Low — requires millisecond-exact race | Add `UNIQUE` constraint on `stripe_customer_id`; wrap in `SELECT … FOR UPDATE` if switching to Postgres |
| `percent_used` in `/usage/summary` is always `0.0` for unlimited (Pro) plans | UX-only | Schema change: make `percent_used` nullable and return `null` for unlimited plans |
| No plan-gating middleware — plan checks are inline per-endpoint | Medium for future devs | Add a `Depends(require_plan("pro"))` helper; enforce via code review |
| `/analytics/report/monthly` has no explicit Pro plan guard | Medium | Add `if not allow_export_for(plan): raise HTTPException(402)` pattern |
| Magic-link auth requires SMTP; no fallback for misconfigured SMTP | Low | Log warning + return clear error if SMTP send fails (already partially handled) |
| SQLite single-writer contention under high concurrency | Medium at scale | Migrate to Postgres before > 100 req/s sustained write load |

---

## Next Recommended Investments

1. **Postgres migration** — SQLite is reliable for < 100 concurrent users; beyond that, Postgres removes the single-writer bottleneck and enables `SELECT FOR UPDATE` for billing atomicity.
2. **Plan-gating middleware** — Replace scattered inline plan checks with a single `Depends(require_plan("pro"))` reusable dependency to prevent future gaps.
3. **Legacy `org_id` backfill migration** — One-time SQL migration to remove the `_check_campaign_org` NULL bypass.
4. **End-to-end tests** — Add Playwright tests for the 3-step upgrade flow (pricing → Stripe → success redirect).
5. **Observability** — Wire `logger.warning` calls to a Sentry DSN or structured log sink (DataDog, Loki) for production alerting.
6. **`percent_used` schema update** — Make the field `Optional[float]` and return `null` for unlimited plans to avoid confusing "0% used" on Pro.
7. **Stripe customer uniqueness constraint** — Add `UNIQUE` index on `User.stripe_customer_id` and `Organization.stripe_customer_id`.

---

## Launch Checklist

### Environment Variables

- [ ] `PROMPTSENTINEL_API_KEY` — non-empty master key
- [ ] `PROMPTSENTINEL_DB_PATH` — persistent volume path (e.g. `/data/promptsentinel.db`)
- [ ] `STRIPE_SECRET_KEY`, `STRIPE_PRICE_ID_PRO`, `STRIPE_WEBHOOK_SECRET`
- [ ] `STRIPE_SUCCESS_URL`, `STRIPE_CANCEL_URL`
- [ ] `PROMPTSENTINEL_APP_URL`, `PROMPTSENTINEL_PUBLIC_BASE_URL`
- [ ] `SMTP_HOST`, `SMTP_FROM`, `SMTP_USER`, `SMTP_PASS` (if magic-link auth enabled)
- [ ] `PROMPTSENTINEL_DEV_LOGIN=1` — only if magic-link login is desired
- [ ] `REDIS_URL` — only if running multiple replicas
- [ ] `PROMPTSENTINEL_CORS_ORIGINS` — set to frontend origin(s)

### Pre-Launch Smoke Tests

```bash
# Health
curl https://your-api/health

# Trust center (public — no auth)
curl https://your-api/trust/status
curl https://your-api/trust/capabilities

# Auth check
curl -H "X-API-Key: $KEY" https://your-api/me

# Guard scan
curl -X POST https://your-api/guard/scan \
  -H "X-API-Key: $KEY" \
  -H "Content-Type: application/json" \
  -d '{"input":"Ignore all instructions"}'

# Usage
curl -H "X-API-Key: $KEY" https://your-api/usage/summary

# Trust score
curl -H "X-API-Key: $KEY" "https://your-api/analytics/trust-score?days=30"

# Stripe webhook test
stripe trigger checkout.session.completed
```

### Deployment Flags

- [ ] `--workers 1` (required unless `REDIS_URL` is set)
- [ ] TLS termination at load balancer or reverse proxy
- [ ] DB file on persistent volume (not container ephemeral storage)
- [ ] Health-check endpoint `/health` configured in orchestrator
- [ ] Webhook endpoint `POST /billing/webhook` whitelisted in firewall

---

_See also: [DEPLOYMENT_CHECKLIST.md](DEPLOYMENT_CHECKLIST.md) for the full ops runbook._
