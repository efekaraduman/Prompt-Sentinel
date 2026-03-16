# PromptSentinel — Backend

The backend is a FastAPI application with 75+ endpoints covering runtime guard, red-team campaigns, threat intelligence, analytics, billing, auth, and admin.

**Full documentation:** see the [root README](../README.md) and [PROMPTSENTINEL_MASTER_CONTEXT.md](../PROMPTSENTINEL_MASTER_CONTEXT.md).

## Quick start

```bash
python -m venv venv

# Windows
venv\Scripts\pip install -r requirements.txt
venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload

# Linux / macOS
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

API docs (Swagger UI): `http://localhost:8000/docs`
Health check: `http://localhost:8000/health`

## Key modules

| File | Purpose |
|---|---|
| `main.py` | FastAPI app — all routes |
| `guard.py` | Runtime guard pipeline (sync) |
| `guard_pipeline.py` | Detector protocol + orchestration |
| `risk_analyzer.py` | Risk scoring engine (0–100) |
| `campaigns.py` | Campaign lifecycle |
| `runner.py` | Single-attack executor |
| `red_agent.py` | Adaptive red-team prompt generator |
| `analytics.py` | Anomaly detection + aggregations |
| `billing.py` | Stripe integration |
| `auth.py` | Auth helpers, RBAC |
| `db.py` | SQLite connection + inline migrations |
| `schemas.py` | 80+ Pydantic models |
| `models.py` | 20+ SQLModel DB tables |
