"""Dedicated guard-scan worker — polls queued GuardScan rows and processes them.

Run as:
    python -m app.worker

Environment variables:
    WORKER_POLL_S      Poll interval (seconds) when queue is empty.  Default: 1.0
    WORKER_BATCH_SIZE  Max rows claimed per poll cycle.              Default: 10

Lifecycle
---------
1. Calls ``init_db()`` so the schema is up-to-date on first start.
2. Loops: claim a batch of queued rows (CAS: queued → processing),
   process each one via ``run_scan_sync``, repeat immediately if more
   rows exist, or sleep ``WORKER_POLL_S`` when the queue is empty.
3. Catches SIGINT / SIGTERM — finishes the current batch then exits cleanly.

Multi-worker safety
-------------------
Each claim is a separate ``UPDATE … WHERE status = 'queued'`` that commits
immediately.  SQLite serialises writes so only one worker can flip a given row;
the losing worker sees ``rowcount == 0`` and skips that row.
"""
from __future__ import annotations

import logging
import os
import signal
import time
from typing import List, Optional

from sqlalchemy import text
from sqlmodel import Session, select

from .db import engine, init_db
from .guard_async import run_scan_sync
from .models import GuardScan
from .retention import run_retention_cleanup
from .webhooks import process_pending_deliveries

logger = logging.getLogger(__name__)

_POLL_INTERVAL: float = float(os.environ.get("WORKER_POLL_S", "1"))
_BATCH_SIZE: int      = int(os.environ.get("WORKER_BATCH_SIZE", "10"))
# Run data-retention cleanup every N poll cycles (~60 s at default poll interval).
_CLEANUP_EVERY: int   = 60

_shutdown: bool = False


# ---------------------------------------------------------------------------
# Signal handling
# ---------------------------------------------------------------------------

def _handle_signal(signum: int, _frame: object) -> None:  # noqa: ANN001
    global _shutdown
    logger.info(
        "worker: signal %d received — will stop after current batch", signum
    )
    _shutdown = True


# ---------------------------------------------------------------------------
# Claim helpers
# ---------------------------------------------------------------------------

def _claim_batch(session: Session) -> List[int]:
    """CAS ``queued → processing`` for up to *_BATCH_SIZE* rows.

    Commits after each individual UPDATE so concurrent workers immediately
    see the updated status and skip already-claimed rows.

    Returns a list of claimed scan IDs (may be shorter than the candidate
    list if another worker raced to claim some rows first).
    """
    # Read-only fetch of candidate IDs (no lock held between fetch and UPDATE).
    candidates: List[int] = list(
        session.exec(
            select(GuardScan.id)  # type: ignore[call-overload]
            .where(GuardScan.status == "queued")
            .order_by(GuardScan.created_at)
            .limit(_BATCH_SIZE)
        ).all()
    )

    claimed: List[int] = []
    for scan_id in candidates:
        affected = session.execute(
            text(
                "UPDATE guardscan"
                " SET status = 'processing'"
                " WHERE id = :id AND status = 'queued'"
            ),
            {"id": scan_id},
        ).rowcount
        session.commit()  # commit each claim individually
        if affected:
            claimed.append(scan_id)

    return claimed


# ---------------------------------------------------------------------------
# Per-row processing
# ---------------------------------------------------------------------------

def _process_one(scan_id: int) -> None:
    """Fetch the GuardScan row, run the guard pipeline, write back result.

    ``run_scan_sync`` handles its own DB sessions and updates the row
    to ``completed`` or ``failed``.  This function never raises — any
    unhandled exception is logged so the worker loop can continue.
    """
    # Open a short-lived session just to read the row fields.
    input_text: str            = ""
    output_text: Optional[str] = None
    policy_json: str           = "{}"
    context_text: Optional[str] = None
    plan: str                  = "public"
    user_id: Optional[int]     = None
    org_id: Optional[int]      = None
    model_name: str            = "unknown"

    try:
        with Session(engine) as s:
            scan = s.get(GuardScan, scan_id)
            if scan is None:
                logger.warning("worker: scan_id=%d not found — skipping", scan_id)
                return
            input_text   = scan.input_text
            output_text  = scan.output_text or None
            policy_json  = scan.policy_json or "{}"
            context_text = scan.context_text
            plan         = scan.plan
            user_id      = scan.user_id
            org_id       = scan.org_id
            model_name   = getattr(scan, "model_name", None) or "unknown"
    except Exception:
        logger.exception("worker: error reading scan_id=%d", scan_id)
        return

    # run_scan_sync opens its own sessions for the pipeline and for write-back.
    # retrieved_docs / tool_calls / baseline_output are not persisted on the
    # GuardScan row (they were only available in-process before this refactor).
    run_scan_sync(
        scan_id=scan_id,
        input_text=input_text,
        output_text=output_text,
        policy_json=policy_json,
        context=context_text,
        user_plan=plan,
        user_id=user_id,
        org_id=org_id,
        retrieved_docs=None,
        tool_calls=None,
        baseline_output=None,
    )

    # Update per-model risk profile from the completed scan result.
    try:
        import json as _json
        from .model_risk import update_model_risk as _umr

        with Session(engine) as s:
            completed = s.get(GuardScan, scan_id)
            if completed is not None and completed.status == "completed":
                result_data = _json.loads(completed.result_json or "{}")
                risk_score = int(result_data.get("risk_score", 0))
                blocked = completed.decision == "block"
                _umr(s, model_name, risk_score, blocked)
    except Exception:
        logger.warning("worker: model risk update failed for scan_id=%d", scan_id)


# ---------------------------------------------------------------------------
# Poll cycle
# ---------------------------------------------------------------------------

def poll_once(session: Session) -> int:
    """Claim and process one batch.  Returns the number of rows processed."""
    claimed = _claim_batch(session)
    if not claimed:
        return 0

    logger.info("worker: claimed %d row(s) %s", len(claimed), claimed)
    for scan_id in claimed:
        try:
            _process_one(scan_id)
        except Exception:
            logger.exception("worker: unhandled error on scan_id=%d", scan_id)

    return len(claimed)


def _run_webhook_deliveries() -> int:
    """Process pending webhook deliveries.  Returns count attempted."""
    try:
        with Session(engine) as s:
            n = process_pending_deliveries(s)
        if n:
            logger.info("worker: webhook deliveries processed=%d", n)
        return n
    except Exception:
        logger.warning("worker: webhook delivery error", exc_info=True)
        return 0


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def run_worker() -> None:
    """Block until SIGINT / SIGTERM, polling for queued scans."""
    signal.signal(signal.SIGINT,  _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    logger.info(
        "worker: started  poll_interval=%.1fs  batch_size=%d",
        _POLL_INTERVAL,
        _BATCH_SIZE,
    )

    init_db()  # ensure schema is current

    _cycle: int = 0
    while not _shutdown:
        try:
            with Session(engine) as s:
                n = poll_once(s)
            # E1 — process webhook deliveries every cycle (independent of scan queue)
            _run_webhook_deliveries()
            _cycle += 1
            if _cycle % _CLEANUP_EVERY == 0:
                try:
                    with Session(engine) as s:
                        totals = run_retention_cleanup(s)
                    if any(v for v in totals.values()):
                        logger.info("worker: retention cleanup totals=%s", totals)
                except Exception:
                    logger.warning("worker: retention cleanup error", exc_info=True)
            if n == 0:
                # Queue empty — sleep before next check.
                time.sleep(_POLL_INTERVAL)
            # else: items were processed — poll again immediately to drain.
        except Exception:
            logger.exception("worker: poll error")
            time.sleep(_POLL_INTERVAL)

    logger.info("worker: stopped")


# ---------------------------------------------------------------------------
# CLI entrypoint  (python -m app.worker)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    run_worker()
