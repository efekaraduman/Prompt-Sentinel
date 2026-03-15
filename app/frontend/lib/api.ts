import type {
  AdminGlobalAnalyticsResponse,
  AdminUserUsageItem,
  CampaignCreateRequest,
  GuardAnalyticsResponse,
  CampaignCreateResponse,
  CampaignDiff,
  CampaignStatusResponse,
  DashboardSummary,
  MeResponse,
  MeUsageResponse,
  PaginatedFindingsResponse,
  RecentCampaignItem,
  RiskTrendItem,
  TestLLMRequest,
  TestLLMResponse,
  ThreatSignatureItem,
  UserKey,
  UserMe,
  UserSafe,
  UsageStatus,
} from "./types";

export class UpgradeRequiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UpgradeRequiredError";
  }
}

export function isUpgradeError(json: unknown): boolean {
  if (!json || typeof json !== "object") return false;
  const type = (json as { error?: { type?: unknown } }).error?.type;
  return type === "plan_limit" || type === "quota_exceeded";
}

async function parseOrThrow<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let message = `Request failed with status ${response.status}`;
    let data: unknown = null;

    try {
      data = (await response.json()) as unknown;

      if (
        data &&
        typeof data === "object" &&
        "error" in data &&
        data.error &&
        typeof (data as { error: { message?: unknown } }).error === "object"
      ) {
        const maybeMessage = (data as { error: { message?: unknown } }).error.message;
        if (typeof maybeMessage === "string" && maybeMessage.trim().length > 0) {
          message = maybeMessage;
        }
      } else if (
        data &&
        typeof data === "object" &&
        "detail" in data
      ) {
        const det = (data as { detail?: unknown }).detail;
        if (typeof det === "string") {
          message = det;
        } else if (det && typeof det === "object" && "message" in det) {
          // structured detail: {"type": "...", "message": "...", "code": "..."}
          const detMsg = (det as { message?: unknown }).message;
          if (typeof detMsg === "string" && detMsg.trim().length > 0) {
            message = detMsg;
          }
        }
      }
    } catch {
      // ignore JSON parse errors and keep generic message
    }

    if (isUpgradeError(data)) throw new UpgradeRequiredError(message);
    throw new Error(message);
  }

  return (await response.json()) as T;
}

/**
 * Build auth headers for every API call.
 * Priority: explicit apiKey param → localStorage token (Bearer) → localStorage apiKey (X-API-Key).
 */
function buildHeaders(apiKey?: string): Record<string, string> {
  const h: Record<string, string> = { "Accept": "application/json" };
  if (apiKey) {
    h["X-API-Key"] = apiKey;
    return h;
  }
  if (typeof window !== "undefined") {
    const token = localStorage.getItem("token");
    if (token) { h["Authorization"] = `Bearer ${token}`; return h; }
    const key = localStorage.getItem("apiKey");
    if (key) { h["X-API-Key"] = key; }
  }
  return h;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export async function startCheckout(): Promise<{ url: string }> {
  const response = await fetch("/api/billing/checkout", {
    method: "POST",
    headers: buildHeaders(),
  });
  return parseOrThrow<{ url: string }>(response);
}

export async function createPortalSession(apiKey?: string): Promise<{ url: string }> {
  const response = await fetch("/api/billing/portal-session", {
    method: "POST",
    headers: { ...buildHeaders(apiKey), "Content-Type": "application/json" },
    body: "{}",
  });
  return parseOrThrow<{ url: string }>(response);
}

export async function createCheckoutSession(
  apiKey?: string,
): Promise<{ checkout_url: string; session_id: string }> {
  const response = await fetch("/api/billing/checkout-session", {
    method: "POST",
    headers: { ...buildHeaders(apiKey), "Content-Type": "application/json" },
    body: "{}",
  });
  return parseOrThrow<{ checkout_url: string; session_id: string }>(response);
}

/** B3.3 — canonical upgrade entry point used by /pricing */
export async function startProCheckout(apiKey?: string): Promise<{ checkout_url: string }> {
  const res = await fetch("/api/billing/checkout/pro", {
    method: "POST",
    headers: { ...buildHeaders(apiKey), "Content-Type": "application/json" },
    body: JSON.stringify({}),
  });
  return parseOrThrow<{ checkout_url: string }>(res);
}

export async function login(
  email: string,
  password: string,
): Promise<{ token: string }> {
  const response = await fetch("/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  return parseOrThrow<{ token: string }>(response);
}

// ---------------------------------------------------------------------------
// Testing
// ---------------------------------------------------------------------------

export async function runTest(payload: TestLLMRequest): Promise<TestLLMResponse> {
  const response = await fetch("/api/test-llm", {
    method: "POST",
    headers: { ...buildHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  return parseOrThrow<TestLLMResponse>(response);
}

// ---------------------------------------------------------------------------
// Campaigns
// ---------------------------------------------------------------------------

export async function startCampaign(
  payload: CampaignCreateRequest,
): Promise<CampaignCreateResponse> {
  const response = await fetch("/api/campaigns", {
    method: "POST",
    headers: { ...buildHeaders(), "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  return parseOrThrow<CampaignCreateResponse>(response);
}

export async function getCampaign(campaignId: number): Promise<CampaignStatusResponse> {
  const response = await fetch(`/api/campaigns/${campaignId}`, {
    method: "GET",
    headers: buildHeaders(),
  });

  return parseOrThrow<CampaignStatusResponse>(response);
}

interface GetFindingsParams {
  page?: number;
  page_size?: number;
  min_risk?: number;
  sort?: "asc" | "desc";
}

export async function getFindings(
  campaignId: number,
  params: GetFindingsParams = {},
): Promise<PaginatedFindingsResponse> {
  const query = new URLSearchParams();

  if (params.page != null) query.set("page", String(params.page));
  if (params.page_size != null) query.set("page_size", String(params.page_size));
  if (params.min_risk != null) query.set("min_risk", String(params.min_risk));
  if (params.sort) query.set("sort", params.sort);

  const qs = query.toString();
  const url = qs ? `/api/campaigns/${campaignId}/findings?${qs}` : `/api/campaigns/${campaignId}/findings`;

  const response = await fetch(url, {
    method: "GET",
    headers: buildHeaders(),
  });

  return parseOrThrow<PaginatedFindingsResponse>(response);
}

export async function stopCampaign(campaignId: number): Promise<CampaignStatusResponse> {
  const response = await fetch(`/api/campaigns/${campaignId}/stop`, {
    method: "POST",
    headers: buildHeaders(),
  });

  return parseOrThrow<CampaignStatusResponse>(response);
}

export async function getCampaignDiff(
  leftId: number,
  rightId: number,
  apiKey?: string,
): Promise<CampaignDiff> {
  const response = await fetch(
    `/api/campaigns/diff?left_id=${leftId}&right_id=${rightId}`,
    { method: "GET", headers: buildHeaders(apiKey) },
  );

  return parseOrThrow<CampaignDiff>(response);
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

export async function getDashboardSummary(apiKey?: string): Promise<DashboardSummary> {
  const response = await fetch("/api/dashboard/summary", {
    method: "GET",
    headers: buildHeaders(apiKey),
  });

  return parseOrThrow<DashboardSummary>(response);
}

export async function getRecentCampaigns(
  limit = 10,
  apiKey?: string,
): Promise<RecentCampaignItem[]> {
  const response = await fetch(`/api/dashboard/recent?limit=${limit}`, {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<RecentCampaignItem[]>(response);
}

export async function getRiskTrend(
  limit = 10,
  apiKey?: string,
): Promise<RiskTrendItem[]> {
  const response = await fetch(`/api/dashboard/risk-trend?limit=${limit}`, {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<RiskTrendItem[]>(response);
}

export async function getTopThreats(
  limit = 5,
  apiKey?: string,
): Promise<ThreatSignatureItem[]> {
  const response = await fetch(`/api/threats/top?limit=${limit}`, {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<ThreatSignatureItem[]>(response);
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

export async function getMe(apiKey?: string): Promise<MeResponse> {
  const response = await fetch("/api/me", {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<MeResponse>(response);
}

export async function getMeUsage(apiKey?: string): Promise<MeUsageResponse> {
  const response = await fetch("/api/me/usage", {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<MeUsageResponse>(response);
}

export async function getUsageStatus(apiKey?: string): Promise<UsageStatus> {
  const response = await fetch("/api/usage/status", {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<UsageStatus>(response);
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

export async function createAdminUser(
  email: string,
  apiKey?: string,
): Promise<{ email: string; api_key: string }> {
  const response = await fetch("/api/admin/users", {
    method: "POST",
    headers: { ...buildHeaders(apiKey), "Content-Type": "application/json" },
    body: JSON.stringify({ email }),
  });
  return parseOrThrow<{ email: string; api_key: string }>(response);
}

export async function getAdminUsers(apiKey?: string): Promise<UserSafe[]> {
  const response = await fetch("/api/admin/users", {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<UserSafe[]>(response);
}

export async function rotateUserKey(userId: number, apiKey?: string): Promise<UserKey> {
  const response = await fetch(`/api/admin/users/${userId}/rotate-key`, {
    method: "POST",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<UserKey>(response);
}

export async function deactivateUser(userId: number, apiKey?: string): Promise<UserSafe> {
  const response = await fetch(`/api/admin/users/${userId}/deactivate`, {
    method: "POST",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<UserSafe>(response);
}

export async function getGuardAnalytics(apiKey?: string): Promise<GuardAnalyticsResponse> {
  const response = await fetch("/api/analytics/guard", {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<GuardAnalyticsResponse>(response);
}

export async function getAdminAnalytics(apiKey?: string): Promise<AdminGlobalAnalyticsResponse> {
  const response = await fetch("/api/admin/analytics", {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<AdminGlobalAnalyticsResponse>(response);
}

export async function getAdminUsersUsage(
  limit = 50,
  apiKey?: string,
): Promise<AdminUserUsageItem[]> {
  const response = await fetch(`/api/admin/users/usage?limit=${limit}`, {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<AdminUserUsageItem[]>(response);
}

/** Phase 3.14 — SIEM Webhook */
export async function getWebhookConfig(apiKey?: string): Promise<import("./types").WebhookConfig> {
  const response = await fetch("/api/admin/webhook", {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<import("./types").WebhookConfig>(response);
}

export async function setWebhookConfig(
  payload: import("./types").WebhookConfigRequest,
  apiKey?: string,
): Promise<import("./types").WebhookConfig> {
  const response = await fetch("/api/admin/webhook", {
    method: "PUT",
    headers: { ...buildHeaders(apiKey), "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  return parseOrThrow<import("./types").WebhookConfig>(response);
}

/** Phase E2 — daily guard scan trend */
export async function getGuardTrend(
  days: number = 7,
  apiKey?: string,
): Promise<import("./types").ThreatTrendResponse> {
  const response = await fetch(`/api/analytics/guard/trend?days=${days}`, {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<import("./types").ThreatTrendResponse>(response);
}

/** Phase 3.16 */
export async function getUsageSummary(apiKey?: string): Promise<import("./types").UsageSummary> {
  const response = await fetch("/api/usage/summary", {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<import("./types").UsageSummary>(response);
}

/** PHASE 2.19 — guard scan history */
export async function getGuardHistory(
  limit = 20,
  apiKey?: string,
): Promise<import("./types").GuardHistoryItem[]> {
  const response = await fetch(`/api/guard/history?limit=${limit}`, {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<import("./types").GuardHistoryItem[]>(response);
}

/** PHASE 2.19 — replay a past scan */
export async function replayGuardScan(
  scanId: number,
  apiKey?: string,
): Promise<import("./types").GuardReplayResponse> {
  const response = await fetch(`/api/guard/replay/${scanId}`, {
    method: "POST",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<import("./types").GuardReplayResponse>(response);
}

/** PHASE 2.21 — org-scoped webhook aliases (same endpoints, named per spec) */
export const getOrgWebhook = getWebhookConfig;
export const setOrgWebhook = setWebhookConfig;

/** PHASE 2.22 — guard performance analytics */
export async function getPerformanceAnalytics(
  days = 7,
  apiKey?: string,
): Promise<import("./types").PerformanceAnalyticsResponse> {
  const response = await fetch(`/api/analytics/performance?days=${days}`, {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<import("./types").PerformanceAnalyticsResponse>(response);
}

/** PHASE 2.37 — trust score / maturity index */
export async function getTrustScore(
  days = 30,
  apiKey?: string,
): Promise<import("./types").TrustScoreResponse> {
  const response = await fetch(`/api/analytics/trust-score?days=${days}`, {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<import("./types").TrustScoreResponse>(response);
}

/** PHASE 2.29 — security scorecard */
export async function getScorecard(
  days = 30,
  apiKey?: string,
): Promise<import("./types").SecurityScorecardResponse> {
  const response = await fetch(`/api/analytics/scorecard?days=${days}`, {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<import("./types").SecurityScorecardResponse>(response);
}

/** PHASE 2.17 — anomaly alerts */
export async function getAnomalies(
  days = 30,
  apiKey?: string,
): Promise<import("./types").AnomalyAlertResponse> {
  const response = await fetch(`/api/analytics/anomalies?days=${days}`, {
    method: "GET",
    headers: buildHeaders(apiKey),
  });
  return parseOrThrow<import("./types").AnomalyAlertResponse>(response);
}
