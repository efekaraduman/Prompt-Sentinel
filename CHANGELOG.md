# Changelog

All notable changes to PromptSentinel are documented here.

---

## [0.3.0] — 2026-02-28

### Added

- **API key authentication** — optional master-key auth via `PROMPTSENTINEL_API_KEY`; admin endpoints require it; regular endpoints accept any valid user key
- **Per-IP rate limiting** — configurable via `PROMPTSENTINEL_RATE_LIMIT_PER_MIN`; disabled by default
- **User management** — admin endpoints to create users, rotate API keys, and deactivate accounts (`GET/POST /admin/users`, `/admin/users/{id}/deactivate`, `/admin/users/{id}/rotate-key`)
- **Dashboard** — `GET /dashboard/summary` (aggregate stats) and `GET /dashboard/recent` (recent campaigns with metrics)
- **Campaign diff** — `GET /campaigns/diff` comparing avg/max risk and per-category deltas between two campaigns
- **Findings export** — `GET /campaigns/{id}/export?format=json|csv` for bulk download of campaign findings
- **Golden / regression test suite** — `tests/run_golden.py` for deterministic offline testing
- **Web UI** — Next.js 16 App Router frontend with:
  - Dashboard page (stat cards, status bar chart, recent campaigns table)
  - Campaign diff page
  - Confidence heatmap per campaign
  - Category distribution bars per campaign
  - JSON/CSV export buttons
  - Admin users page (create, rotate key, deactivate)
  - Persistent API-key control in header
