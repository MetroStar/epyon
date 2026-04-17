import {
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query';
import type {
  Application,
  ApprovedImages,
  GitHubConfig,
  Job,
  Metrics,
  Scan,
  ScanHistory,
  Stats,
  SyncState,
} from './types';
import api from './client';

// ── Stats ─────────────────────────────────────────────────────
export const useStats = () =>
  useQuery<Stats>({
    queryKey: ['stats'],
    queryFn: () => api.get<Stats>('/stats').then((r) => r.data),
  });

// ── Applications ──────────────────────────────────────────────
export const useApplications = () =>
  useQuery<Application[]>({
    queryKey: ['applications'],
    queryFn: () => api.get<Application[]>('/applications').then((r) => r.data),
  });

export const useAppScans = (name: string) =>
  useQuery<Scan[]>({
    queryKey: ['applications', name, 'scans'],
    queryFn: () =>
      api.get<Scan[]>(`/applications/${encodeURIComponent(name)}/scans`).then((r) => r.data),
    enabled: !!name,
  });

export const useHideApplication = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      api.delete(`/applications/${encodeURIComponent(name)}`).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['applications'] });
      qc.invalidateQueries({ queryKey: ['applications-hidden'] });
    },
  });
};

export const useRestoreApplication = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) =>
      api.post(`/applications/${encodeURIComponent(name)}/restore`).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['applications'] });
      qc.invalidateQueries({ queryKey: ['applications-hidden'] });
    },
  });
};

export const useHiddenApplications = () =>
  useQuery<string[]>({
    queryKey: ['applications-hidden'],
    queryFn: () => api.get<string[]>('/applications-hidden').then((r) => r.data),
  });

// ── Scans ─────────────────────────────────────────────────────
export const useScan = (id: string) =>
  useQuery<Scan>({
    queryKey: ['scans', id],
    queryFn: () =>
      api.get<Scan>(`/scans/${encodeURIComponent(id)}`).then((r) => r.data),
    enabled: !!id,
  });

// ── Jobs ──────────────────────────────────────────────────────
export const useJobs = () =>
  useQuery<Job[]>({
    queryKey: ['jobs'],
    queryFn: () => api.get<Job[]>('/jobs').then((r) => r.data),
  });

export const useJob = (id: string | null, polling = false) =>
  useQuery<Job>({
    queryKey: ['jobs', id],
    queryFn: () =>
      api.get<Job>(`/jobs/${id}`).then((r) => r.data),
    enabled: !!id,
    refetchInterval: polling ? 2000 : false,
  });

export const useTriggerScan = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: { target: string; scan_type: string }) =>
      api.post<{ job_id: string; status: string }>('/scans', payload).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['jobs'] });
    },
  });
};

export const useCancelJob = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (jobId: string) =>
      api.post(`/jobs/${jobId}/cancel`).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['jobs'] });
    },
  });
};

// ── Scan history ──────────────────────────────────────────────
export const useScanHistory = () =>
  useQuery<ScanHistory>({
    queryKey: ['scan-history'],
    queryFn: () => api.get<ScanHistory>('/scan-history').then((r) => r.data),
  });

// ── GitHub ────────────────────────────────────────────────────
export const useGitHubConfig = () =>
  useQuery<GitHubConfig>({
    queryKey: ['github', 'config'],
    queryFn: () => api.get<GitHubConfig>('/github/config').then((r) => r.data),
  });

export const useSaveGitHubConfig = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: { token?: string; repos: string[] }) =>
      api.post('/github/config', payload).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['github'] });
    },
  });
};

export const useGitHubSyncStatus = (polling = false) =>
  useQuery<SyncState>({
    queryKey: ['github', 'sync'],
    queryFn: () => api.get<SyncState>('/github/sync').then((r) => r.data),
    refetchInterval: polling ? 2000 : false,
  });

export const useTriggerGitHubSync = () => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post('/github/sync').then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['github', 'sync'] });
    },
  });
};

// ── Settings ──────────────────────────────────────────────────
export const useApprovedImages = () =>
  useQuery<ApprovedImages>({
    queryKey: ['approved-images'],
    queryFn: () => api.get<ApprovedImages>('/settings/approved-images').then((r) => r.data),
  });

// ── Metrics ───────────────────────────────────────────────────
export const useMetrics = () =>
  useQuery<Metrics>({
    queryKey: ['metrics'],
    queryFn: () => api.get<Metrics>('/metrics').then((r) => r.data),
    staleTime: 5 * 60 * 1000,
  });
