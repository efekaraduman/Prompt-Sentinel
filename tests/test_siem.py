"""Unit tests for app/siem.py — CEF formatter, syslog wrapper, JSON dict."""
from __future__ import annotations

import sys
sys.path.insert(0, ".")

from datetime import datetime, timezone

from app.siem import (
    _esc_ext,
    _esc_header,
    filter_min_severity,
    record_to_cef,
    record_to_dict,
)


class FakeRecord:
    def __init__(self, **kw):
        self.__dict__.update(kw)


R_LOW = FakeRecord(
    id=1,
    created_at=datetime(2026, 3, 5, 12, 0, 0, tzinfo=timezone.utc),
    severity="low",
    decision="allow",
    risk_score=5,
    blocked=False,
    categories_json='["role_confusion"]',
    signature_hash="abcdef1234567890",
    org_id=None,
    input_snippet="ignore previous instructions",
    elapsed_ms=42,
)

R_CRIT = FakeRecord(
    id=2,
    created_at=datetime(2026, 3, 5, 13, 0, 0, tzinfo=timezone.utc),
    severity="critical",
    decision="block",
    risk_score=95,
    blocked=True,
    categories_json='["instruction_override","data_exfiltration"]',
    signature_hash="deadbeef00001111",
    org_id=7,
    input_snippet="val=injected data",
    elapsed_ms=18,
)


# ── escaping helpers ───────────────────────────────────────────────────────────

def test_esc_header_pipe():
    assert _esc_header("foo|bar") == "foo\\|bar"


def test_esc_header_backslash():
    # single backslash in input → double backslash in output
    assert _esc_header("a\\b") == "a\\\\b"


def test_esc_ext_equals():
    assert _esc_ext("a=b") == "a\\=b"


def test_esc_ext_newline():
    # actual newline character → literal \n (two chars)
    assert _esc_ext("a\nb") == "a\\nb"


def test_esc_ext_backslash():
    assert _esc_ext("a\\b") == "a\\\\b"


# ── CEF plain output ──────────────────────────────────────────────────────────

def test_cef_header_prefix():
    cef = record_to_cef(R_LOW)
    assert cef.startswith("CEF:0|PromptSentinel|PromptSentinel|1.0|"), cef


def test_cef_low_severity_value():
    cef = record_to_cef(R_LOW)
    # low → CEF severity 2, appears between the last two | in the header
    assert "|2|" in cef, cef


def test_cef_critical_severity_value():
    cef = record_to_cef(R_CRIT)
    assert "|10|" in cef, cef


def test_cef_risk_score_extension():
    cef = record_to_cef(R_LOW)
    assert "cn1=5" in cef
    assert "cn1Label=riskScore" in cef


def test_cef_outcome_field():
    cef = record_to_cef(R_LOW)
    assert "outcome=allow" in cef


def test_cef_act_block_only_when_blocked():
    cef_low = record_to_cef(R_LOW)
    cef_crit = record_to_cef(R_CRIT)
    assert "act=block" not in cef_low
    assert "act=block" in cef_crit


def test_cef_category_fields():
    cef = record_to_cef(R_LOW)
    assert "cat=role_confusion" in cef
    assert "cs2=role_confusion" in cef
    assert "cs2Label=categories" in cef


def test_cef_multi_category():
    cef = record_to_cef(R_CRIT)
    assert "instruction_override,data_exfiltration" in cef


def test_cef_signature_hash_prefix():
    cef = record_to_cef(R_LOW)
    # sig_id = first 8 chars of signature_hash
    assert "abcdef12" in cef


def test_cef_org_id_extension():
    cef = record_to_cef(R_CRIT)
    assert "cn2=7" in cef
    assert "cn2Label=orgId" in cef


def test_cef_no_org_id_when_none():
    cef = record_to_cef(R_LOW)
    assert "cn2=" not in cef


def test_cef_equals_escaped_in_msg():
    cef = record_to_cef(R_CRIT)
    # "val=injected" in snippet → "val\=injected" in CEF
    assert "val\\=injected" in cef


def test_cef_rt_field_milliseconds():
    cef = record_to_cef(R_LOW)
    # 2026-03-05T12:00:00Z → 1772712000000 ms
    assert "rt=1772712000000" in cef


# ── Syslog wrapper (RFC-5424) ─────────────────────────────────────────────────

def test_syslog_starts_with_priority():
    slog = record_to_cef(R_CRIT, syslog=True)
    assert slog.startswith("<"), slog


def test_syslog_rfc5424_version():
    slog = record_to_cef(R_CRIT, syslog=True)
    # Must contain ">1 " (VERSION=1 after priority)
    assert ">1 " in slog, slog


def test_syslog_contains_cef():
    slog = record_to_cef(R_CRIT, syslog=True)
    assert "CEF:0" in slog


def test_syslog_priority_critical():
    # facility(4)*8 + syslog_sev_critical(2) = 34
    slog = record_to_cef(R_CRIT, syslog=True)
    assert slog.startswith("<34>"), slog


def test_syslog_priority_low():
    # facility(4)*8 + syslog_sev_low(6) = 38
    slog = record_to_cef(R_LOW, syslog=True)
    assert slog.startswith("<38>"), slog


def test_syslog_appname():
    slog = record_to_cef(R_CRIT, syslog=True)
    assert "PromptSentinel" in slog


def test_syslog_timestamp_utc():
    slog = record_to_cef(R_CRIT, syslog=True)
    assert "2026-03-05T13:00:00Z" in slog


def test_syslog_hostname_override():
    slog = record_to_cef(R_CRIT, syslog=True, hostname="my-siem-relay")
    assert "my-siem-relay" in slog


# ── JSON dict ─────────────────────────────────────────────────────────────────

def test_json_dict_fields():
    d = record_to_dict(R_CRIT)
    assert d["id"] == 2
    assert d["risk_score"] == 95
    assert d["blocked"] is True
    assert d["decision"] == "block"
    assert d["severity"] == "critical"
    assert "instruction_override" in d["categories"]
    assert d["org_id"] == 7


def test_json_dict_timestamp_utc():
    d = record_to_dict(R_CRIT)
    # Must be ISO-8601 with UTC offset
    assert d["timestamp"].endswith("+00:00")


def test_json_dict_no_org():
    d = record_to_dict(R_LOW)
    assert d["org_id"] is None


# ── severity filter ───────────────────────────────────────────────────────────

def test_filter_low_passes_all():
    assert len(filter_min_severity([R_LOW, R_CRIT], "low")) == 2


def test_filter_medium_drops_low():
    assert len(filter_min_severity([R_LOW, R_CRIT], "medium")) == 1


def test_filter_high_keeps_only_high_and_above():
    assert len(filter_min_severity([R_LOW, R_CRIT], "high")) == 1


def test_filter_critical_only():
    assert len(filter_min_severity([R_LOW, R_CRIT], "critical")) == 1


def test_filter_empty_list():
    assert filter_min_severity([], "low") == []


# ── runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = {k: v for k, v in globals().items() if k.startswith("test_")}
    passed = failed = 0
    for name, fn in tests.items():
        try:
            fn()
            print(f"  PASS  {name}")
            passed += 1
        except Exception as exc:
            print(f"  FAIL  {name}  --  {exc}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed out of {passed + failed} tests.")
    sys.exit(failed)
