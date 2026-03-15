"""Guard pipeline — detector protocol and result merging (Phase 3.1 / 3.3 / 3.13).

Each detector is a plain callable with the signature::

    detect(input_text, output_text, context, policy,
           retrieved_docs, tool_calls) -> DetectorResult

``run_pipeline`` runs all detectors in order and merges their outputs:

- **categories** — union of all detector category sets
- **reasons**    — concatenated, duplicates removed (insertion-order preserved),
                   prefixed with ``[detector_name]``
- **severity_bump** — accumulated sum, clamped to [0, 100]
- **signals**    — shallow dict merge (later detectors overwrite same key)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Protocol, runtime_checkable

if TYPE_CHECKING:
    from .schemas import GuardPolicy


@dataclass
class DetectorResult:
    """Structured output returned by each detector.

    Registry API field mapping
    --------------------------
    spec name   → dataclass field
    ``score``   → ``severity_bump``  (property alias below)
    ``meta``    → ``signals``        (property alias below)
    """

    categories: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)
    severity_bump: int = 0          # contribution to risk score; accumulated + clamped to 100
    signals: dict = field(default_factory=dict)  # arbitrary per-detector metadata

    # ── Registry-spec aliases ────────────────────────────────────────────────
    @property
    def score(self) -> int:
        """Contribution to the combined risk score (0–100). Alias for severity_bump."""
        return self.severity_bump

    @property
    def meta(self) -> dict:
        """Arbitrary per-detector metadata. Alias for signals."""
        return self.signals


# Callable signature that every detector must satisfy (Phase 3.4: +tool_calls).
Detector = Callable[
    [str, Optional[str], Optional[str], "GuardPolicy",
     Optional[List[str]], Optional[List[Dict[str, Any]]]],
    DetectorResult,
]


@runtime_checkable
class BaseDetector(Protocol):
    """Protocol for named detector objects (Phase 3.13).

    Plain functions also satisfy this protocol when they carry a ``name``
    attribute (set via ``func.name = "..."``) — the pipeline uses
    ``getattr(detector, 'name', detector.__name__)`` so both styles work.
    """

    name: str

    def __call__(
        self,
        input_text: str,
        output_text: Optional[str],
        context: Optional[str],
        policy: "GuardPolicy",
        retrieved_docs: Optional[List[str]],
        tool_calls: Optional[List[Dict[str, Any]]],
    ) -> DetectorResult: ...


# ---------------------------------------------------------------------------
# Detector score weights (ADVANCED — Weighted Detector Engine)
# ---------------------------------------------------------------------------
# Each weight is a multiplier applied to a detector's raw severity_bump before
# accumulation.  Higher weight = greater contribution to the final risk score.
# Unregistered / custom detectors default to 1.0 (no adjustment).
# These same weights are mirrored in guard._CONSENSUS_SIGNALS for consistency.
DETECTOR_WEIGHTS: dict[str, float] = {
    "injection":     1.5,
    "rag":           1.4,
    "pii":           1.3,
    "hallucination": 1.2,
    "tool":          1.15,  # aligns with existing tool_misuse category multiplier
}


def run_pipeline(
    detectors: list[Detector],
    input_text: str,
    output_text: Optional[str],
    context: Optional[str],
    policy: "GuardPolicy",
    retrieved_docs: Optional[List[str]] = None,            # Phase 3.3
    tool_calls: Optional[List[Dict[str, Any]]] = None,     # Phase 3.4
    max_elapsed_ms: Optional[int] = None,                  # Phase 3.6 — hard time budget
    start_time: Optional[float] = None,                    # Phase 3.6 — perf_counter reference
) -> DetectorResult:
    """Run detectors in order and merge their results per the rules above.

    Phase 3.13: each detector reason is prefixed with ``[detector_name]``.
    ADVANCED: each detector's severity_bump is multiplied by its DETECTOR_WEIGHTS
    entry before accumulation (unknown detectors default to 1.0).
    """
    merged_cats: set[str] = set()
    merged_reasons: list[str] = []
    total_bump = 0
    merged_signals: dict = {}
    detectors_run = 0

    for detector in detectors:
        det_name = getattr(detector, "name", getattr(detector, "__name__", "unknown"))
        result = detector(input_text, output_text, context, policy, retrieved_docs, tool_calls)
        detectors_run += 1
        merged_cats |= result.categories
        for reason in result.reasons:
            prefixed = f"[{det_name}] {reason}"
            if prefixed not in merged_reasons:
                merged_reasons.append(prefixed)
        weight = DETECTOR_WEIGHTS.get(det_name, 1.0)
        weighted_bump = round(result.severity_bump * weight)
        total_bump = min(100, total_bump + weighted_bump)
        merged_signals.update(result.signals)

        # Phase 3.6 — budget check after each detector
        if max_elapsed_ms is not None and start_time is not None:
            if (time.perf_counter() - start_time) * 1000 >= max_elapsed_ms:
                break

    merged_signals["detectors_run"] = detectors_run
    merged_signals["detectors_total"] = len(detectors)

    return DetectorResult(
        categories=merged_cats,
        reasons=merged_reasons,
        severity_bump=total_bump,
        signals=merged_signals,
    )
