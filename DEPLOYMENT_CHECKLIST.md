# PromptSentinel — Production Deployment Checklist

Work through every section before going live. Items marked **⛔ blocker** will
cause data loss, security failures, or billing breakage if skipped.

---

## 1. Required Environment Variables

| Variable | Required | Notes |
|---|---|---|
| `PROMPTSENTINEL_API_KEY` | **⛔ blocker** | Generate with `python -c "import secrets; print(secrets.token_hex(32))"`. Unset = open dev mode — anyone can call any endpoint. |
| `PROMPTSENTINEL_DB_PATH` | **⛔ blocker** | Set to a persistent-disk path (e.g. `/data/promptsentinel.db`). Default is relative `./promptsentinel.db` — lost on container restart. |
| `PROMPTSENTINEL_CORS_ORIGINS` | **⛔ blocker** | Comma-separated allowed origins (e.g. `https://app.example.com`). Unset = localhost only; your deployed frontend will be blocked. |
| `STRIPE_SECRET_KEY` | Required if billing | `sk_live_...` — never commit, never log. |
| `STRIPE_PRICE_ID_PRO` | Required if billing | Price ID from Stripe Dashboard. |
| `STRIPE_WEBHOOK_SECRET` | Required if billing | `whsec_...` — must match the endpoint registered in Stripe Dashboard. |
| `STRIPE_SUCCESS_URL` / `STRIPE_CANCEL_URL` | Required if billing | Full HTTPS URLs on your frontend. |
| `SMTP_HOST` / `SMTP_FROM` | Required if magic-link auth | Minimum pair; add `SMTP_USER`, `SMTP_PASS`, `SMTP_PORT` for authenticated relay. |
| `PROMPTSENTINEL_APP_URL` | Required if billing | Public base URL — used in billing redirects and email links. |
| `PROMPTSENTINEL_PUBLIC_BASE_URL` | Required if magic-link auth | Public URL embedded in login-link emails; may equal `PROMPTSENTINEL_APP_URL`. |
| `PROMPTSENTINEL_DEV_LOGIN` | Optional | Set to `1` to enable passwordless magic-link login (requires SMTP above). Leave unset in production unless SMTP is configured. |
| `LOG_LEVEL` | Optional | Default `INFO`. Use `WARNING` in production to reduce noise. |

---

## 2. Worker Count

> **⛔ Single worker only unless you configure Redis.**

The rate limiter defaults to an in-memory store. Running multiple workers
(Gunicorn, `--workers N`, k8s replicas) with in-memory state means each worker
tracks separate counters — rate limits become N× less effective.

| Setup | Safe worker count | How |
|---|---|---|
| Single-process (default) | 1 | `uvicorn app.main:app --workers 1` |
| Multi-worker / replicas | Any | Set `REDIS_URL` (see §3) |

Never set `--workers` > 1 without Redis.

---

## 3. Rate Limiting Mode

| Mode | When | Behaviour |
|---|---|---|
| `disabled` | `PROMPTSENTINEL_RATE_LIMIT_PER_MIN=0` (default) | No limiting — safe only behind your own auth layer. |
| `memory` | Limit set, no `REDIS_URL` | Per-process fixed window. Single-worker only. |
| `redis` | Limit set + valid `REDIS_URL` | Cross-worker atomic counter. Required for replicas. |

Check the current mode at runtime: `GET /trust/status` → `rate_limit_mode`.

Recommended for production: set `PROMPTSENTINEL_RATE_LIMIT_PER_MIN=120` and
`REDIS_URL=redis://your-redis:6379/0`.

---

## 4. Stripe / Billing Setup

1. Create a Product and recurring Price in the Stripe Dashboard.
2. Copy `price_...` → `STRIPE_PRICE_ID_PRO`.
3. Register a webhook endpoint in Stripe Dashboard pointing to `https://your-api/stripe/webhook`.
4. Copy the signing secret (`whsec_...`) → `STRIPE_WEBHOOK_SECRET`.
5. Verify the webhook is working: Stripe Dashboard → Webhooks → Send test event.
6. Test end-to-end with Stripe test mode before switching to live keys.

> The app verifies every webhook signature and records event IDs in `stripeevent`
> to guarantee idempotency — the same event processed twice is a no-op.

---

## 5. SMTP / Email Setup

Required only if you enable magic-link (passwordless) authentication.

| Variable | Example |
|---|---|
| `SMTP_HOST` | `smtp.sendgrid.net` |
| `SMTP_PORT` | `587` (STARTTLS) |
| `SMTP_USER` | `apikey` |
| `SMTP_PASS` | your SendGrid API key |
| `SMTP_FROM` | `noreply@yourdomain.com` |

Verify SMTP is working before enabling user-facing auth: send a test mail from
the Python REPL using `smtplib` with the same credentials.

---

## 6. Stripe Webhook Verification

All inbound Stripe webhooks are verified with `stripe.WebhookEvent.construct_from`
using `STRIPE_WEBHOOK_SECRET`. **Never disable signature verification.**

- For local testing: `stripe listen --forward-to localhost:8000/stripe/webhook`
  (prints a temporary `whsec_...` secret — use that in your local `.env`).
- For production: use the permanent secret from the Stripe Dashboard.
- Stripe retries failed webhooks for up to 72 h — ensure your endpoint is
  idempotent (it is; see the `stripeevent.event_id` unique index).

---

## 6b. SIEM / Application Webhook

The app can push guard-scan events to your own SIEM or SOAR via
`PUT /admin/webhook` (org-scoped). Each delivery is HMAC-signed with the
secret you configured.

- Verify the `X-PromptSentinel-Signature` header on the receiver.
- Delivery attempts are logged in `webhookdelivery`; failed attempts are
  moved to `webhookdeadletter` after retries.
- Test the webhook is reachable before go-live:
  `GET /admin/webhook` → check `is_active: true` and `last_error: null`.
- Rotate the webhook secret by calling `PUT /admin/webhook` with a new
  `secret` — in-flight deliveries signed with the old secret will fail;
  short switchover window is acceptable.

---

## 7. Database Backup

SQLite in WAL mode is used. It is **not** replicated — all data lives in one file.

- **⛔ blocker**: Set `PROMPTSENTINEL_DB_PATH` to a persistent volume, not the
  container's ephemeral filesystem.
- Schedule regular backups: `sqlite3 promptsentinel.db ".backup backup_$(date +%F).db"`.
- For higher durability, mount a cloud-provider persistent disk (AWS EBS, GCP
  Persistent Disk, etc.) and point `PROMPTSENTINEL_DB_PATH` to it.
- Consider a nightly cron job that copies the backup to object storage (S3, GCS).
- Before any deployment, run: `sqlite3 promptsentinel.db "PRAGMA integrity_check;"`.

---

## 8. TLS / Reverse Proxy

The app itself does **not** handle TLS. Terminate TLS at the reverse proxy.

Recommended setup:

```
client → nginx / Caddy / AWS ALB (TLS) → uvicorn (plain HTTP, localhost only)
```

- Bind uvicorn to `127.0.0.1:8000`, not `0.0.0.0`, when behind a proxy on the
  same host.
- Set `X-Forwarded-For` / `X-Real-IP` headers so rate limiting sees client IPs,
  not the proxy IP.
- Enforce HSTS (`Strict-Transport-Security: max-age=63072000`).
- Redirect all HTTP → HTTPS at the proxy level.

**Caddy (simplest):**
```
api.example.com {
    reverse_proxy localhost:8000
}
```

---

## 9. Logging

- Default: `LOG_LEVEL=INFO` — request logs, DB migrations, billing events.
- Production: keep `INFO` or raise to `WARNING` to reduce volume.
- **Never set `DEBUG` in production** — may log request bodies.
- Ship logs to a centralised store (CloudWatch, Datadog, Loki) before go-live so
  you have pre-launch baseline.
- Do not log `PROMPTSENTINEL_API_KEY`, `STRIPE_SECRET_KEY`, or `SMTP_PASS` —
  the app does not log these, but verify no proxy/middleware adds them.

---

## 10. Secrets Handling

- **Never commit secrets** to git. Use `.gitignore` to exclude `.env`.
- Inject secrets via the hosting platform's secrets manager (Fly.io secrets,
  Railway variables, AWS Secrets Manager, Kubernetes Secrets).
- Rotate `PROMPTSENTINEL_API_KEY` immediately if it is ever exposed.
- Rotate `STRIPE_WEBHOOK_SECRET` by adding a new endpoint in the Stripe Dashboard,
  switching the env var, then removing the old endpoint.
- Generate strong keys: `python -c "import secrets; print(secrets.token_hex(32))"`.

---

## 11. Health Checks

| Endpoint | Auth | What it confirms |
|---|---|---|
| `GET /health` | None | App is up and reachable |
| `GET /trust/status` | None | Guard enabled, rate limit mode, version |

Configure your load balancer / uptime monitor to poll `GET /health` every 30 s.
Alert if HTTP status ≠ 200 for two consecutive checks.

```bash
# Quick smoke test after deploy
curl -sf https://your-api/health | python -m json.tool
curl -sf https://your-api/trust/status | python -m json.tool
```

---

## 12. Rollback Checklist

If a deployment goes wrong:

1. **Revert the container image** to the previous tag (keep the last two images).
2. **Do not delete the DB file** — SQLite migrations are additive (`ALTER TABLE
   ADD COLUMN` only); the previous version runs fine against the newer schema.
3. **Verify** with `GET /health` after rollback.
4. If a migration added a column that breaks the rollback, restore from backup
   (§7) taken before the deploy.
5. Check Stripe webhook delivery log — any events that failed during the outage
   will be retried automatically by Stripe for up to 72 h; no manual replay needed.

---

## 13. Container Security

When running via Docker:

- The Dockerfile creates a dedicated `promptsentinel` non-root user; do **not**
  override with `--user root` in production.
- Mount the DB volume explicitly: `-v /persistent/path:/data` and set
  `PROMPTSENTINEL_DB_PATH=/data/promptsentinel.db`.
- The `/data` directory inside the container is owned by `promptsentinel:promptsentinel` —
  ensure the host path is writable by UID matching the container user
  (or use named Docker volumes which handle this automatically).
- Pass secrets via `--env-file` or the hosting platform's secrets manager —
  never bake secrets into the image with `ENV` or `ARG`.

---

## Quick Reference — Pre-Launch Command List

```bash
# 1. Confirm required secrets are set
printenv | grep -E 'PROMPTSENTINEL_API_KEY|STRIPE_SECRET_KEY|PROMPTSENTINEL_DB_PATH'

# 2. DB integrity check
sqlite3 "$PROMPTSENTINEL_DB_PATH" "PRAGMA integrity_check;"

# 3. Health check
curl -sf https://your-api/health

# 4. Trust status (confirms rate limit mode + guard enabled)
curl -sf https://your-api/trust/status | python -m json.tool

# 5. Trust / maturity score (org posture baseline — compare after config changes)
curl -sf -H "X-API-Key: $PROMPTSENTINEL_API_KEY" https://your-api/analytics/trust-score | python -m json.tool

# 6. SIEM webhook active check (if configured)
curl -sf -H "X-API-Key: $PROMPTSENTINEL_API_KEY" https://your-api/admin/webhook | python -m json.tool

# 7. Verify Stripe webhook is registered and receiving events
# → Stripe Dashboard → Developers → Webhooks → your endpoint → Recent deliveries
```
