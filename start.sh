#!/usr/bin/env bash
# PromptSentinel — Linux/macOS start script (mirrors run.ps1 behaviour)
#
# Usage:
#   ./start.sh
#   PROMPTSENTINEL_API_KEY=secret ./start.sh
#   PROMPTSENTINEL_RATE_LIMIT_PER_MIN=60 ./start.sh
#   PROMPTSENTINEL_DEV_RESET_DB=1 ./start.sh   # wipe DB on first start
#
# NOTE: Single worker is required.
# The rate limiter uses in-memory state; multiple workers would each maintain
# separate counters making per-IP limits ineffective.

set -euo pipefail

exec python -m uvicorn app.main:app \
    --host      "${HOST:-0.0.0.0}" \
    --port      "${PORT:-8000}" \
    --workers   1 \
    --log-level "${LOG_LEVEL:-info}"
