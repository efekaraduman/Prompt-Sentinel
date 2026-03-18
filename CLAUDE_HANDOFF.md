# PromptSentinel — Claude Handoff Document

_Last updated: 2026-03-18_

This document captures the key context an AI assistant (or new developer) needs to continue working on this project.

---

## Project Overview

**PromptSentinel** is an LLM security platform combining:
1. **Runtime Guard** — stateless detector pipeline that scores and blocks malicious inputs/outputs
2. **Red-Team Campaigns** — structured adversarial testing against system prompts
3. **Threat Intelligence** — signatures, clustering, anomaly detection, SIEM export

No external LLM API calls are made — all detection is rule-based and deterministic.

---

## Repo Layout

```
app/                    # Backend (FastAPI + SQLModel)
  main.py               # 75+ endpoints, startup logic, demo seed
  guard.py              # Runtime guard pipeline (sync)
  campaigns.py          # Campaign lifecycle
  auth.py               # API key + password + magic-link auth, RBAC
  config.py             # Centralized settings from env vars
  models.py             # 20+ SQLModel tables
  schemas.py            # 80+ Pydantic request/response models
  billing.py            # Stripe integration (optional)
  demo_seed.py          # Seeds sample data for demo mode
  frontend/             # Next.js 16 App Router
    src/app/            # Pages: dashboard, admin, pricing, trust, etc.
    src/lib/api.ts      # API client with parseOrThrow() error handling
sdk/                    # Python + JS client libraries
tests/                  # Golden tests (188) + SIEM tests (34)
```

---

## Key Patterns

### Error Handling (Frontend)
`lib/api.ts` → `parseOrThrow()` extracts `detail.message` from FastAPI error responses. Backend must return:
```python
raise HTTPException(status_code=4xx, detail={"type": "...", "message": "Human-readable message"})
```

### Auth Flow
- `PROMPTSENTINEL_API_KEY` unset → open dev mode (no auth)
- `PROMPTSENTINEL_API_KEY` set → API key required via `X-API-Key` header
- Demo mode → anonymous viewer access allowed, mutations blocked

### Demo Mode
- Backend: `PROMPTSENTINEL_DEMO_MODE=1` → `require_not_demo()` dependency blocks mutations
- Frontend: `NEXT_PUBLIC_DEMO_MODE=1` → build-time banner, login gate bypass
- Auto-seeds sample data on startup via `demo_seed.py`

### Frontend Proxy
`next.config.ts` rewrites `/api/*` → backend URL. All client-side fetches use `/api/...` (never direct backend URL).

---

## Deployment

| Service | Platform | Config |
|---------|----------|--------|
| Backend | Render (Docker) | `render.yaml`, uses `$PORT`, auto-seeds in demo mode |
| Frontend | Vercel | Root dir = `app/frontend`, env: `NEXT_PUBLIC_API_BASE_URL`, `NEXT_PUBLIC_DEMO_MODE` |

### Important Notes
- Vercel Hobby plan: commits must have a GitHub-associated author (no unknown `Co-Authored-By`)
- Render free tier: ephemeral filesystem, DB re-seeds on every restart
- `--workers 1` required unless `REDIS_URL` is set

---

## Known Gotchas

1. **`useState(false)` login gate** — `dashboard/page.tsx` inits `hasApiKey` from `NEXT_PUBLIC_DEMO_MODE` at build time to avoid flash of login screen
2. **`NEXT_PUBLIC_*` variables** — baked into JS bundle at build time, not runtime
3. **CSP `connect-src 'self'`** — all API calls must go through Next.js proxy, never direct to backend from browser
4. **SQLite WAL mode** — enables concurrent reads but single writer; adequate for demo/portfolio use

---

## Running Locally

```bash
# Backend
cd app && python -m venv venv && venv\Scripts\pip install -r requirements.txt
cd .. && app\venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Frontend
cd app/frontend && npm install && npm run dev
```

---

## What's Next (Roadmap Priorities)

1. PostgreSQL support (Phase E6)
2. Redis-backed rate limiting for multi-worker
3. Async detection pipeline (`asyncio.gather`)
4. Slack / PagerDuty integrations
5. Custom detector plugin SDK
