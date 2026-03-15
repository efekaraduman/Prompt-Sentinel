"""PHASE 2.16 — SIEM / SOC export utilities.

Converts GuardScanRecord and AuditEvent rows into vendor-neutral
SecurityEventExportItem dicts and optionally renders CEF (Common Event Format)
lines for SIEM ingestion.

CEF format:
  CEF:0|Vendor|Product|Version|EventClassID|Name|Severity|Extension

Severity mapping (CEF 0–10 scale):
  low → 3  |  medium → 6  |  high → 8  |  critical → 10

No ML deps.  No raw payloads stored.  Never raises at module level.
"""
from __future__ import annotations

import json
from typing import Any, List

# ── CEF helpers ───────────────────────────────────────────────────────────────

_CEF_SEV: dict[str, int] = {"low": 3, "medium": 6, "high": 8, "critical": 10}

_CEF_ESCAPE = str.maketrans({"|": r"\|", "=": r"\=", "\\": r"\\"})


def _esc(value: str) -> str:
    """Escape pipe, equals, and backslash for CEF extension values."""
    return str(value).translate(_CEF_ESCAPE)


def to_cef(event: dict[str, Any]) -> str:
    """Render one security event dict as a single CEF 0 line.

    Fields used:
      created_at, event_type, decision, severity,
      categories, signature_hash, cluster_id, elapsed_ms,
      resource_type, resource_id
    """
    sev_num = _CEF_SEV.get(str(event.get("severity", "")).lower(), 3)
    event_class = _esc(event.get("event_type", "guard_scan"))
    name        = _esc(event.get("decision", "allow") or "allow")
    cats        = _esc(",".join(event.get("categories", [])))

    ext_parts = [
        f"rt={_esc(event.get('created_at', ''))}",
        f"cat={cats}",
        f"sig={_esc(event.get('signature_hash', ''))}",
        f"cluster={_esc(event.get('cluster_id', ''))}",
        f"elapsed={int(event.get('elapsed_ms', 0))}",
        f"decision={_esc(event.get('decision', ''))}",
    ]
    if event.get("resource_type"):
        ext_parts.append(f"resType={_esc(event['resource_type'])}")
    if event.get("resource_id"):
        ext_parts.append(f"resId={_esc(event['resource_id'])}")

    ext = " ".join(ext_parts)
    return f"CEF:0|PromptSentinel|PromptSentinel|1.0|{event_class}|{name}|{sev_num}|{ext}"


# ── Row converters ────────────────────────────────────────────────────────────

def guard_history_to_export_items(rows: list) -> List[dict]:
    """Convert GuardScanRecord ORM rows to export-item dicts."""
    items: list[dict] = []
    for r in rows:
        try:
            cats = json.loads(r.categories_json or "[]")
        except Exception:
            cats = []
        items.append({
            "created_at":     r.created_at.isoformat(),
            "event_type":     "guard_scan",
            "decision":       r.decision or "",
            "severity":       r.severity or "",
            "categories":     cats,
            "signature_hash": r.signature_hash or "",
            "cluster_id":     r.sketch_cluster_id or "",
            "elapsed_ms":     int(r.elapsed_ms or 0),
            "resource_type":  None,
            "resource_id":    None,
        })
    return items


def audit_to_export_items(rows: list) -> List[dict]:
    """Convert AuditEvent ORM rows to export-item dicts."""
    items: list[dict] = []
    for r in rows:
        items.append({
            "created_at":     r.created_at.isoformat(),
            "event_type":     r.event_type or "",
            "decision":       "",
            "severity":       "",
            "categories":     [],
            "signature_hash": "",
            "cluster_id":     "",
            "elapsed_ms":     0,
            "resource_type":  r.resource_type or None,
            "resource_id":    r.resource_id or None,
        })
    return items
