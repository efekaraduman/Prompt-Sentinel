"""PromptSentinel Python SDK — stdlib only, no extra deps."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Optional


class PromptSentinelError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status


class PromptSentinelClient:
    """Minimal client for the PromptSentinel API.

    Parameters
    ----------
    base_url:
        Base URL of your PromptSentinel instance, e.g. ``"http://localhost:8000"``.
    api_key:
        Optional API key sent as ``X-API-Key``.  Required for authenticated
        endpoints (guard scan, usage, etc.).
    """

    def __init__(self, base_url: str, api_key: Optional[str] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.api_key:
            h["X-API-Key"] = self.api_key
        return h

    def _request(self, method: str, path: str, body: Any = None) -> Any:
        url = self.base_url + path
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read()).get("detail", exc.reason)
            except Exception:
                detail = exc.reason
            raise PromptSentinelError(exc.code, detail) from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def guard_scan(
        self,
        input: str,
        output: Optional[str] = None,
        context: Optional[str] = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Run a guard scan and return the full response dict.

        Extra keyword arguments are forwarded to the request body (e.g.
        ``policy={"block_pii": False}``).
        """
        payload: dict[str, Any] = {"input": input}
        if output is not None:
            payload["output"] = output
        if context is not None:
            payload["context"] = context
        payload.update(kwargs)
        return self._request("POST", "/guard/scan", payload)

    def get_usage_summary(self) -> dict[str, Any]:
        """Return the current billing-period usage summary."""
        return self._request("GET", "/usage/summary")

    def get_trust_score(self, days: int = 30) -> dict[str, Any]:
        """Return the organisation trust score / maturity index.

        Parameters
        ----------
        days:
            Look-back window in days (default 30).
        """
        return self._request("GET", f"/analytics/trust-score?days={days}")
