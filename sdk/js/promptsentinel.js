/**
 * PromptSentinel JS SDK — zero dependencies, works in Node ≥18 and browsers.
 */

export class PromptSentinelError extends Error {
  /** @param {number} status @param {string} message */
  constructor(status, message) {
    super(`HTTP ${status}: ${message}`);
    this.name = "PromptSentinelError";
    this.status = status;
  }
}

export class PromptSentinelClient {
  /**
   * @param {string} baseUrl  Base URL, e.g. "http://localhost:8000"
   * @param {string} [apiKey] X-API-Key for authenticated endpoints
   */
  constructor(baseUrl, apiKey) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.apiKey = apiKey ?? null;
  }

  // ── internal ────────────────────────────────────────────────────────────

  _headers() {
    const h = { "Content-Type": "application/json", Accept: "application/json" };
    if (this.apiKey) h["X-API-Key"] = this.apiKey;
    return h;
  }

  async _request(method, path, body) {
    const res = await fetch(this.baseUrl + path, {
      method,
      headers: this._headers(),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = data?.detail ?? data?.error?.message ?? res.statusText;
      throw new PromptSentinelError(res.status, msg);
    }
    return data;
  }

  // ── public API ───────────────────────────────────────────────────────────

  /**
   * Run a guard scan.
   * @param {string} input           The text to scan (required)
   * @param {string} [output]        LLM output to include in scan
   * @param {string} [context]       Additional context
   * @param {object} [extra]         Extra body fields (e.g. { policy: { block_pii: false } })
   * @returns {Promise<object>}
   */
  async guardScan(input, output, context, extra = {}) {
    const body = { input, ...extra };
    if (output !== undefined) body.output = output;
    if (context !== undefined) body.context = context;
    return this._request("POST", "/guard/scan", body);
  }

  /**
   * Return the current billing-period usage summary.
   * @returns {Promise<object>}
   */
  async getUsageSummary() {
    return this._request("GET", "/usage/summary");
  }

  /**
   * Return the organisation trust score / maturity index.
   * @param {number} [days=30] Look-back window in days
   * @returns {Promise<object>}
   */
  async getTrustScore(days = 30) {
    return this._request("GET", `/analytics/trust-score?days=${days}`);
  }
}
