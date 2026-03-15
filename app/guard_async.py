"""Async guard scan persistence (Phase E1).

``create_scan_record`` creates a GuardScan row (status=queued) in an
*existing* session before the background thread is spawned.

``run_scan_sync`` is called in a worker thread via asyncio.to_thread.
It opens its own DB session, runs the full guard pipeline via
guard.run_guard_scan, and writes the result back to the GuardScan row.

GuardScanRecord (privacy-safe) is also written by run_guard_scan as a
side-effect — both tables are populated for every async scan.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from sqlmodel import Session

from .db import engine
from .models import GuardScan


_MAX_TEXT = 50_000   # chars stored per field


def create_scan_record(
    session: Session,
    user_id: Optional[int],
    plan: str,
    input_text: str,
    output_text: Optional[str],
    context_text: Optional[str],
    policy_json: str,
    org_id: Optional[int] = None,   # E4
    model_name: str = "unknown",
) -> GuardScan:
    """Insert a GuardScan row with status='queued'. Commits and refreshes."""
    scan = GuardScan(
        user_id=user_id,
        org_id=org_id,
        plan=plan,
        input_text=input_text[:_MAX_TEXT],
        output_text=(output_text or "")[:_MAX_TEXT],
        context_text=context_text[:_MAX_TEXT] if context_text else None,
        policy_json=policy_json,
        status="queued",
        decision="allow",
        severity="low",
        signature_hash="",
        cluster_id="",
        model_name=model_name,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)
    return scan


def run_scan_sync(
    scan_id: int,
    input_text: str,
    output_text: Optional[str],
    policy_json: str,
    context: Optional[str],
    user_plan: Optional[str],
    user_id: Optional[int],
    org_id: Optional[int],
    retrieved_docs: Optional[List[str]],
    tool_calls: Optional[List[Dict[str, Any]]],
    baseline_output: Optional[str],
) -> None:
    """Synchronous worker executed in a thread pool via asyncio.to_thread.

    Opens a fresh DB session, executes the guard pipeline, and persists
    the full GuardScanResponse JSON back to the GuardScan row.
    """
    from .guard import run_guard_scan
    from .schemas import GuardPolicy

    policy: Optional[GuardPolicy] = None
    if policy_json and policy_json != "{}":
        try:
            policy = GuardPolicy.model_validate_json(policy_json)
        except Exception:
            policy = None

    t0 = time.perf_counter()
    result = None
    error_msg: Optional[str] = None

    try:
        with Session(engine) as scan_session:
            result = run_guard_scan(
                input_text, output_text, policy, context,
                user_plan=user_plan,
                session=scan_session,
                async_mode=False,
                user_id=user_id,
                org_id=org_id,
                retrieved_docs=retrieved_docs,
                tool_calls=tool_calls,
                baseline_output=baseline_output,
            )
    except Exception as exc:
        error_msg = str(exc)[:500]

    elapsed = int((time.perf_counter() - t0) * 1000)

    # Write result back to GuardScan row in a separate session so the
    # scan_session above is always cleanly closed first.
    try:
        with Session(engine) as ws:
            scan = ws.get(GuardScan, scan_id)
            if scan is None:
                return
            if result is not None:
                scan.result_json = result.model_dump_json()
                scan.status = "completed"
                scan.elapsed_ms = elapsed
                scan.decision = result.decision
                scan.severity = result.severity
                scan.signature_hash = result.signature_hash or ""
                scan.cluster_id = result.cluster_id or ""
            else:
                scan.status = "failed"
                scan.error_message = error_msg or "Scan produced no result"
                scan.elapsed_ms = elapsed
            ws.add(scan)
            ws.commit()
    except Exception:
        pass  # never propagate — background thread must not crash silently
