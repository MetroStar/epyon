// API response types matching FastAPI backend

export interface Stats {
  total_applications: number;
  total_scans: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface CiSource {
  source: string;
  repo: string;
  branch: string;
  commit: string;
  workflow: string;
  event: string;
  run_id: number | null;
}

export interface Scan {
  scan_id: string;
  target: string;
  user: string;
  timestamp: string;
  scan_type: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
  tools_analyzed: string[];
  has_dashboard: boolean;
  dashboard_url: string | null;
  location: string;
  target_directory?: string;
  file_statistics?: Record<string, unknown>;
  ci_source?: CiSource;
  findings?: Findings;
}

export interface Application {
  name: string;
  scan_count: number;
  last_scanned: string;
  scan_type: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  status: string;
  latest_scan_id: string;
}

export interface Finding {
  tool: string;
  id: string;
  severity: string;
  package: string;
  version: string;
  fixed_version: string;
  title: string;
  description: string;
  target: string;
  references: string[];
}

export interface FindingsSummary {
  total_critical: number;
  total_high: number;
  total_medium: number;
  total_low: number;
  tools_analyzed: string[];
}

export interface Findings {
  summary: FindingsSummary;
  critical_findings: Finding[];
  high_findings: Finding[];
  medium_findings: Finding[];
  low_findings: Finding[];
}

export interface Job {
  job_id: string;
  target: string;
  scan_type: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'error' | 'cancelled';
  started_at: string;
  completed_at: string | null;
  exit_code: number | null;
  output: string[];
  error: string | null;
}

export interface ScanHistory {
  generated_at: string;
  total_scans: number;
  targets: string[];
  users: string[];
}

export interface GitHubConfig {
  token_set: boolean;
  token_hint: string;
  repos: string[];
  last_sync: string | null;
}

export interface SyncState {
  status: 'idle' | 'running' | 'done' | 'error';
  started_at: string | null;
  result: { synced: string[]; skipped: string[]; failed: unknown[] } | null;
  error: string | null;
}

export interface ApprovedImages {
  content: string;
}

export interface MetricsTrendPoint {
  scan_id: string;
  target: string;
  timestamp: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface MetricsToolEntry {
  tool: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

export interface MetricsCveEntry {
  cve_id: string;
  count: number;
  severity: string;
  title: string;
  apps: string[];
}

export interface MetricsScanFrequency {
  total: number;
  dates: string[];
}

export interface Metrics {
  trend: MetricsTrendPoint[];
  by_tool: MetricsToolEntry[];
  fix_rate: { with_fix: number; without_fix: number };
  top_cves: MetricsCveEntry[];
  scan_frequency: Record<string, MetricsScanFrequency>;
}
