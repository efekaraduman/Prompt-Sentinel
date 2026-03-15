export interface CheckoutSessionResponse {
  checkout_url: string;
  session_id: string;
}

export interface TestLLMRequest {
  system_prompt: string;
  model: string;
}

export interface TestResult {
  id: number;
  attack_prompt: string;
  llm_response: string;
  leakage_detected: boolean;
  override_detected: boolean;
  risk_score: number;
}

export interface TestLLMResponse {
  risk_score: number;
  summary: string;
  tests: TestResult[];
}

export type CampaignStatus = "queued" | "running" | "completed" | "failed" | "stopped";

export interface CampaignCreateRequest {
  system_prompt: string;
  model: string;
  iterations: number;
  categories?: string[] | null;
}

export interface CampaignCreateResponse {
  campaign_id: number;
  status: CampaignStatus;
}

export interface CampaignStatusResponse {
  campaign_id: number;
  status: CampaignStatus;
  iterations_total: number;
  iterations_done: number;
  progress: number;
  metrics: Record<string, unknown>;
  error_message?: string | null;
}

export interface FindingResponse {
  id: number;
  created_at: string;
  iteration: number;
  category: string;
  attack_prompt: string;
  llm_response: string;
  leakage_detected: boolean;
  override_detected: boolean;
  risk_score: number;
  confidence_score?: number | null;
  notes?: string | null;
}

export interface PaginatedFindingsResponse {
  items: FindingResponse[];
  page: number;
  page_size: number;
  total: number;
}

export interface DashboardSummary {
  total_campaigns: number;
  total_users: number;
  avg_risk_global: number;
  running: number;
  completed: number;
  failed: number;
}

export interface UserSafe {
  id: number;
  email: string;
  created_at: string;
  is_active: boolean;
}

export interface UserKey {
  id: number;
  email: string;
  api_key: string;
}

export interface RecentCampaignItem {
  id: number;
  created_at: string;
  status: string;
  iterations_total: number;
  iterations_done: number;
  progress: number;
  max_risk: number;
  avg_risk: number;
}

export interface CampaignDiff {
  left_id: number;
  right_id: number;
  avg_risk_delta?: number | null;
  max_risk_delta?: number | null;
  category_deltas?: Record<string, number> | null;
}

export interface RiskTrendItem {
  campaign_id: number;
  created_at: string;
  avg_risk: number;
  max_risk: number;
}

export interface ThreatSignatureItem {
  signature_hash: string;
  count: number;
  top_category: string | null;
  first_seen_at: string;
  last_seen_at: string;
  example_snippet: string | null;
}

export interface UserMe {
  id: number;
  email: string;
  plan: string;
  is_active: boolean;
}

/** Shape returned by GET /me (B7.1 — works for public + authenticated callers). */
export interface MeResponse {
  email: string | null;
  plan: string;
  max_iterations: number;
  allow_export: boolean;
  rate_limit_per_min: number | null;
  campaigns_total: number;
  guard_scans_total: number;
}

export interface MeUsageResponse {
  period_ym: string;
  plan: "free" | "pro" | string;
  guard_scans_used: number;
  guard_scans_limit: number;
  guard_scans_remaining: number;
  campaign_iterations_used: number;
  campaign_iterations_limit: number;
  campaign_iterations_remaining: number;
}

export interface AdminGlobalAnalyticsResponse {
  total_users: number;
  active_users: number;
  pro_users: number;
  total_campaigns: number;
  campaigns_completed: number;
  campaigns_failed: number;
  guard_total_scans: number;
  guard_blocks: number;
  guard_warns: number;
  guard_allows: number;
  avg_guard_latency_ms: number;
}

export interface GuardAnalyticsResponse {
  total_scans: number;
  allows: number;
  warns: number;
  blocks: number;
  avg_latency_ms: number;
  top_category_counts: Record<string, number>;
}

export interface AdminUserUsageItem {
  id: number;
  email: string;
  is_active: boolean;
  plan: string;
  period_ym: string;
  guard_scans_used: number;
  guard_scans_limit: number;
  guard_scans_remaining: number;
  campaign_iterations_used: number;
  campaign_iterations_limit: number;
  campaign_iterations_remaining: number;
}

/** Shape returned by GET /usage/status (Phase 2.2). */
export interface UsageStatus {
  period: string;
  plan: string;
  guard_scans: number;
  campaigns_started: number;
  limits: { guard_scans: number | null; campaigns_started: number | null };
  remaining: { guard_scans: number | null; campaigns_started: number | null };
  pct_used: { guard_scans: number | null; campaigns_started: number | null };
}

/** Phase 3.14 — SIEM Webhook */
export interface WebhookConfig {
  url: string;
  is_active: boolean;
  created_at: string;
  last_error: string | null;
  last_sent_at: string | null;
}

export interface WebhookConfigRequest {
  url: string;
  secret: string;
  is_active: boolean;
}

/** Phase E2 — daily guard trend */
export interface DailyCountPoint {
  day: string;    // YYYY-MM-DD
  total: number;
  blocked: number;
}

export interface ThreatTrendResponse {
  days: number;
  points: DailyCountPoint[];
}

/** Phase 3.16 — flat usage summary */
export interface UsageSummary {
  plan: string;
  period_start: string;   // YYYY-MM-DD
  period_end: string;     // YYYY-MM-DD
  guard_used: number;
  guard_limit: number;    // -1 = unlimited
  guard_remaining: number;  // -1 = unlimited
  campaigns_used: number;
  campaigns_limit: number;
  campaigns_remaining: number;
  percent_used: number;   // 0..1; 0 for pro
}

/** PHASE 2.17 — anomaly alert from GET /analytics/anomalies */
export interface AnomalyAlertItem {
  metric: string;
  day: string;           // YYYY-MM-DD
  value: number;
  baseline_mean: number;
  baseline_std: number;
  z_score: number;
  severity: "low" | "medium" | "high" | "critical";
}

export interface AnomalyAlertResponse {
  alerts: AnomalyAlertItem[];
  days: number;
}

/** PHASE 2.19 — individual scan row from GET /guard/history */
export interface GuardHistoryItem {
  id: number;
  created_at: string;
  decision: string;
  severity: string;
  blocked: boolean;
  signature_hash: string;
  elapsed_ms: number;
}

/** PHASE 2.21 — org-scoped webhook config (alias; same shape as WebhookConfig) */
export type OrgWebhookConfig = WebhookConfig;

/** PHASE 2.22 — guard latency and stage-timing analytics */
export interface PerformanceAnalyticsResponse {
  window_days: number;
  total_scans: number;
  avg_elapsed_ms: number;
  p95_elapsed_ms: number;
  slow_scan_count: number;
  avg_stage_timings: Record<string, number>;
}

/** PHASE 2.19 — response from POST /guard/replay/{scan_id} */
export interface GuardReplayResponse {
  scan_id: number;
  match: boolean;                  // backward-compat alias
  replay_match: boolean;
  original_severity: string;
  replay_severity: string;
  original_signature_hash: string;
  replay_signature_hash: string;
}

/** PHASE 2.37 — customer-facing trust / maturity index */
export interface TrustScoreResponse {
  org_id: number | null;
  trust_score: number;                                                  // 0–100
  maturity_level: "starter" | "developing" | "advanced" | "hardened";
  protection_coverage: number;   // 0–100
  control_maturity: number;      // 0–100
  threat_pressure: number;       // 0–100
  response_readiness: number;    // 0–100
  notes: string[];
}

/** PHASE 2.29 — security scorecard for an org */
export interface SecurityScorecardResponse {
  org_id: number;
  exposure_score: number;           // 0–100
  control_maturity_score: number;   // 0–100
  threat_pressure_score: number;    // 0–100
  overall_grade: string;            // A / B / C / D / F
  contributing_factors: string[];
}

