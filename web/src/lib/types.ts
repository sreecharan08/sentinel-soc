// Response shapes of the Django REST contract. See ../../../API.md.

export type Label = "malicious" | "suspicious" | "benign" | "unknown";
export type ProviderPath = "rule_engine" | "agentic" | "active_list" | "fallback";
export type Role = "analyst" | "viewer";

export interface User {
  username: string;
  role: Role;
}

export interface Page<T> {
  count: number;
  next: string | null;
  previous: string | null;
  results: T[];
}

export interface ProviderFields {
  provider: string | null;
  provider_detail: string | null;
  provider_path: ProviderPath | null;
  tool_calls: number;
}

export interface SubmissionRow extends ProviderFields {
  id: string;
  package_name: string;
  app_label: string;
  version_name: string;
  device: { id: string; name: string };
  status: string;
  status_label: string;
  label: Label | null;
  confidence: number | null;
  fallback_from: string | null;
  overridden: boolean;
  remediation_hold: boolean;
  created_at: string;
  updated_at: string;
  in_progress: boolean;
}

export interface Signal {
  id: string;
  code: string;
  name: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  category: string;
  source: string;
  detail: string;
  attck?: string[];
}

export interface Technique {
  id: string;
  name: string;
  tactic?: string;
  confidence: number;
  evidence_ids: string[];
}

export interface TraceStep {
  type: "tool_call" | "conclude" | "malformed_json" | "invalid_tool_call" | "turn_limit_reached";
  tool?: string;
  args?: Record<string, unknown>;
  reason?: string;
  result?: unknown;
  verdict?: string;
  confidence?: number;
  attck?: string[];
  rationale?: string;
  detail?: string;
  requested?: string;
}

export interface Verdict {
  id: number;
  label: Label;
  score: number;
  confidence: number;
  explanation: string;
  techniques: Technique[];
  needs_more_verification: boolean;
  verification_requests: { kind: string; reason: string; focus?: string[] }[];
  recommended_action: "none" | "monitor" | "uninstall";
  provider: {
    name: string;
    version: string;
    fallback_from: string | null;
    detail: string | null;
    path: ProviderPath | null;
  };
  agentic_trace: TraceStep[];
  generated_at: string | null;
}

export interface RemediationRow {
  id: string;
  submission_id: string;
  package_name: string;
  app_label: string;
  device: { id: string; name: string };
  origin: string;
  state: string;
  created_at: string;
  expires_at: string;
  resolved_at: string | null;
  created_by: string | null;
  outcome_detail: string;
  checks: { id: string; passed: boolean; detail?: string }[];
}

export interface RuleOut {
  id: string;
  name: string;
  kind: "yara" | "sigma";
  status: "draft" | "approved" | "retired";
  level: string;
  version: number;
  source_sha256: string;
  needs_review: boolean;
  fp_test: { status?: string };
  created_at: string;
  approved_at: string | null;
  hits: number;
  attck: { id: string; name: string; tactic: string }[];
  package_name: string | null;
}

export interface SubmissionDetail {
  submission: SubmissionRow & {
    sha256: string;
    size_bytes: number;
    requested_permissions: string[];
    installer_package: string | null;
    first_install_time: string | null;
    error_code: string;
    error_detail: string;
  };
  evidence: { signals: Signal[]; partial?: boolean; partial_reasons?: string[] } | null;
  verdict: Verdict | null;
  verdict_history: {
    id: number;
    label: Label;
    confidence: number;
    is_current: boolean;
    provider: string;
    provider_detail: string;
    provider_path: ProviderPath;
    tool_calls: number;
    created_at: string;
  }[];
  effective_label: Label | null;
  analyst_actions: {
    kind: string;
    from: string | null;
    to: string | null;
    note: string;
    user: string | null;
    created_at: string;
  }[];
  remediations: { id: string; state: string; origin: string; created_at: string; outcome_detail: string }[];
  rules: { id: string; name: string; kind: string; status: string }[];
}

export interface PipelineEvent {
  v: number;
  event_id: number;
  type: string;
  ts: string;
  submission_id: string | null;
  stage: string;
  step: string;
  level: "debug" | "info" | "warn" | "error";
  message: string;
  data: Record<string, unknown>;
}

export interface Stats {
  devices_online: number;
  devices_total: number;
  submissions_today: number;
  submissions_yesterday: number;
  submissions_total: number;
  by_label: Record<Label, number>;
  in_progress: number;
  avg_time_to_verdict_s: number | null;
  ttv_p95_s: number | null;
  pending_remediations: number;
  ttv_series: { at: string; seconds: number }[];
  malicious_24h: number;
  generated_at: string;
}

export interface DeviceRow {
  id: string;
  name: string;
  android_version: string;
  app_version: string;
  last_seen: string | null;
  online: boolean;
  protection_on: boolean;
  revoked: boolean;
  scans: number;
  paired_at: string;
}

export interface NetworkData {
  generated_at: string;
  kpis: {
    events_last_minute: number;
    warn_error_24h: number;
    ioc_endpoints: number;
    flagged_endpoints: number;
    rule_matches_24h: number;
  };
  events_per_minute: number[];
  alerts: {
    ts: string;
    level: "crit" | "high" | "med" | "low";
    rule: string | null;
    message: string;
    source: string;
    submission_id: string | null;
  }[];
  agents: { name: string; role: string; online: boolean; detail: string }[];
  talkers: { value: string; kind: string; flagged: boolean; samples: number; pct: number }[];
  iocs: { value: string; kind: string; flagged: boolean; samples: number }[];
  attck: { tactic: string; count: number }[];
}

export interface GraphApp extends ProviderFields {
  id: string;
  device_id: string;
  package_name: string;
  app_label: string;
  label: Label;
  confidence: number | null;
}

export interface GraphData {
  devices: { id: string; name: string; online: boolean }[];
  apps: GraphApp[];
  signals: { id: string; app_id: string; name: string; severity: string }[];
  /** Endpoints that are flagged or referenced by 2+ apps; each links to every app that references it. */
  iocs: { id: string; value: string; kind: "host" | "ip"; flagged: boolean; app_ids: string[] }[];
  shared_iocs: number;
  active_threats: number;
}

export interface PipelineData {
  stages: {
    key: string;
    name: string;
    status: "active" | "idle" | "degraded" | "disabled";
    description: string;
    metric: string;
  }[];
  health: { ok: boolean; db: boolean; redis: boolean | null; workers: number };
  reasoner_backend: string;
  llm_model: string | null;
  submissions_by_status: Record<string, number>;
}

export interface QueueCandidate extends ProviderFields {
  submission_id: string;
  package_name: string;
  app_label: string;
  device: { id: string; name: string };
  label: Label;
  confidence: number;
  explanation: string;
  recommended_action: string;
  created_at: string;
}

export interface QueueData {
  open: RemediationRow[];
  candidates: QueueCandidate[];
  auto_remediation_enabled: boolean;
}

export interface SettingsData {
  settings: {
    auto_remediation_enabled: boolean;
    auto_remediation_min_confidence: number;
    remediation_rate_limit_per_device_hour: number;
    protected_packages: string[];
    reasoner_backend: string;
    dynamic_enabled: boolean;
    show_demo_console: boolean;
  };
  reputation_counts: { bad_hashes: number; good_hashes: number; bad_signers: number };
  env: { dynamic_available: boolean; reasoner_options: string[]; analysis_version: number };
}
