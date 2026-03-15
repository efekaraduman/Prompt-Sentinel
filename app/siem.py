"""SIEM Export helpers — CEF formatting (Phase ENTERPRISE).

CEF reference: ArcSight Common Event Format v25
  CEF:Version|Device Vendor|Device Product|Device Version|
      SignatureID|Name|Severity|[Extension]

Extension key=value pairs follow ArcSight field-name conventions where
available; PromptSentinel-specific fields use the cs*/cn* custom slots.

Syslog wrapper: RFC 5424 header prepended when syslog=True, making lines
ready for direct delivery to rsyslog, syslog-ng, or Splunk Universal
Forwarder over UDP/TCP.
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from typing import Optional


# ── constants ─────────────────────────────────────────────────────────────────

_CEF_VERSION = 0
_VENDOR = "PromptSentinel"
_PRODUCT = "PromptSentinel"
_DEV_VERSION = "1.0"

# Syslog facility: security/authorization messages (RFC 5424 §6.2.1, code 4)
_SYSLOG_FACILITY = 4

# CEF integer severity scale: 0 (lowest) – 10 (highest)
_CEF_SEVERITY: dict[str, int] = {
    "low":      2,
    "medium":   5,
    "high":     8,
    "critical": 10,
}

# RFC 5424 syslog severity codes
_SYSLOG_SEVERITY: dict[str, int] = {
    "low":      6,  # informational
    "medium":   5,  # notice
    "high":     4,  # warning
    "critical": 2,  # critical
}

# Severity ordering for min_severity filter
SEVERITY_ORDER: dict[str, int] = {
    "low":      0,
    "medium":   1,
    "high":     2,
    "critical": 3,
}


# ── CEF escaping ──────────────────────────────────────────────────────────────

def _esc_header(value: str) -> str:
    """Escape backslashes and pipe characters in a CEF header field."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _esc_ext(value: str) -> str:
    """Escape backslashes, equals signs and newlines in a CEF extension value."""
    return (
        value
        .replace("\\", "\\\\")
        .replace("=", "\\=")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
    )


# ── record → CEF ──────────────────────────────────────────────────────────────

def record_to_cef(
    record,
    syslog: bool = False,
    hostname: Optional[str] = None,
) -> str:
    """Convert a ``GuardScanRecord`` ORM object to a single CEF log line.

    Parameters
    ----------
    record:
        A ``GuardScanRecord`` instance (or any object with the same fields).
    syslog:
        When *True*, prepend an RFC-5424 syslog priority header so the line
        can be forwarded directly to a syslog receiver or Splunk HEC.
    hostname:
        Override the hostname in the syslog header.  Defaults to the machine's
        FQDN via :func:`socket.gethostname`.

    CEF extension fields used
    -------------------------
    rt          ArcSight receive-time (ms since Unix epoch)
    outcome     Guard decision: allow | warn | block
    act         "block" only when the scan was blocked
    cat         Comma-separated threat categories (up to 5)
    cn1         Risk score (0–100)
    cn1Label    "riskScore"
    cs1         Signature hash (hex)
    cs1Label    "signatureHash"
    cs2         Threat categories (same as cat; label for SIEM field mapping)
    cs2Label    "categories"
    cn2         org_id (when present)
    cn2Label    "orgId"
    msg         First 200 chars of input_snippet (redacted by guard pipeline)
    """
    severity_str = record.severity if record.severity in _CEF_SEVERITY else "low"
    cef_sev = _CEF_SEVERITY[severity_str]

    # Parse categories
    try:
        cats: list[str] = json.loads(record.categories_json or "[]")
    except Exception:
        cats = []
    cat_str = ",".join(str(c) for c in cats[:5])

    # Event name: first category, else decision
    name = cats[0] if cats else record.decision

    # Timestamp — ensure UTC-aware
    ts: datetime = record.created_at
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    rt_ms = int(ts.timestamp() * 1000)

    # Signature ID: first 8 hex chars of signature_hash (device event class ID)
    sig_id = (record.signature_hash or "00000000")[:8]

    # Build extension key=value string
    ext_parts: list[str] = [
        f"rt={rt_ms}",
        f"outcome={_esc_ext(record.decision)}",
        f"cn1={record.risk_score}",
        f"cn1Label=riskScore",
        f"cs1={_esc_ext(record.signature_hash or '')}",
        f"cs1Label=signatureHash",
    ]

    if cat_str:
        ext_parts += [
            f"cat={_esc_ext(cat_str)}",
            f"cs2={_esc_ext(cat_str)}",
            f"cs2Label=categories",
        ]

    if record.blocked:
        ext_parts.append("act=block")

    snippet: str = getattr(record, "input_snippet", "") or ""
    if snippet:
        ext_parts.append(f"msg={_esc_ext(snippet[:200])}")

    org_id = getattr(record, "org_id", None)
    if org_id is not None:
        ext_parts += [f"cn2={org_id}", "cn2Label=orgId"]

    ext = " ".join(ext_parts)

    cef_line = (
        f"CEF:{_CEF_VERSION}"
        f"|{_esc_header(_VENDOR)}"
        f"|{_esc_header(_PRODUCT)}"
        f"|{_esc_header(_DEV_VERSION)}"
        f"|{_esc_header(sig_id)}"
        f"|{_esc_header(name)}"
        f"|{cef_sev}"
        f"|{ext}"
    )

    if not syslog:
        return cef_line

    # RFC 5424 syslog header
    # <priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID SD MSG
    syslog_sev = _SYSLOG_SEVERITY.get(severity_str, 6)
    priority = _SYSLOG_FACILITY * 8 + syslog_sev
    host = hostname or _get_hostname()
    timestamp = ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    return f"<{priority}>1 {timestamp} {host} {_VENDOR} - - - {cef_line}"


def _get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "localhost"


# ── record → dict (JSON feed) ─────────────────────────────────────────────────

def record_to_dict(record) -> dict:
    """Serialise a ``GuardScanRecord`` to a JSON-safe dict for the JSON feed.

    All datetime values are ISO-8601 strings; categories are parsed from JSON.
    """
    try:
        cats: list[str] = json.loads(record.categories_json or "[]")
    except Exception:
        cats = []

    ts: datetime = record.created_at
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    return {
        "id": record.id,
        "timestamp": ts.isoformat(),
        "severity": record.severity,
        "decision": record.decision,
        "risk_score": record.risk_score,
        "blocked": record.blocked,
        "categories": cats,
        "signature_hash": record.signature_hash or "",
        "org_id": getattr(record, "org_id", None),
        "input_snippet": getattr(record, "input_snippet", "") or "",
        "elapsed_ms": record.elapsed_ms,
    }


# ── severity filter ───────────────────────────────────────────────────────────

def filter_min_severity(records: list, min_severity: str) -> list:
    """Return records whose severity level >= *min_severity*.

    Ordering: low < medium < high < critical.
    Unknown severity strings are treated as "low" (pass through).
    """
    floor = SEVERITY_ORDER.get(min_severity, 0)
    return [r for r in records if SEVERITY_ORDER.get(r.severity, 0) >= floor]
