// ---------------------------------------------------------------------------
// API client — typed fetch wrapper for backend communication
// ---------------------------------------------------------------------------

const API_BASE = '/api/v1';

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ message: response.statusText }));
    throw new Error(error.message || `API error: ${response.status}`);
  }

  if (response.status === 204) return undefined as T;
  return response.json();
}

// Targets
export const targetsApi = {
  list: (page = 1) => request<any>(`/targets?page=${page}`),
  get: (id: string) => request<any>(`/targets/${id}`),
  create: (data: any) => request<any>('/targets', { method: 'POST', body: JSON.stringify(data) }),
};

// Credentials
export const credentialsApi = {
  list: () => request<any>('/credentials'),
  create: (data: any) => request<any>('/credentials', { method: 'POST', body: JSON.stringify(data) }),
  delete: (id: string) => request<void>(`/credentials/${id}`, { method: 'DELETE' }),
};

// Scans
export const scansApi = {
  list: (page = 1) => request<any>(`/scans?page=${page}`),
  get: (id: string) => request<any>(`/scans/${id}`),
  create: (data: any) => request<any>('/scans', { method: 'POST', body: JSON.stringify(data) }),
  status: (id: string) => request<any>(`/scans/${id}/status`),
  cancel: (id: string) => request<any>(`/scans/${id}/cancel`, { method: 'POST' }),
};

// Findings
export const findingsApi = {
  list: (params: Record<string, any>) => {
    const qs = new URLSearchParams(params).toString();
    return request<any>(`/findings?${qs}`);
  },
  get: (id: string) => request<any>(`/findings/${id}`),
  correlated: (scanId: string) => request<any>(`/findings/correlated/${scanId}`),
};

// Remediation
export const remediationApi = {
  proposals: (scanId: string) => request<any>(`/remediation/proposals/${scanId}`),
  approve: (data: any) => request<any>('/remediation/approve', { method: 'POST', body: JSON.stringify(data) }),
  apply: (data: any) => request<any>('/remediation/apply', { method: 'POST', body: JSON.stringify(data) }),
  patch: (scanId: string) => request<any>(`/remediation/patch/${scanId}`),
};

// Reports
export const reportsApi = {
  generate: (data: any) => request<any>('/reports/generate', { method: 'POST', body: JSON.stringify(data) }),
  list: (scanId: string) => request<any>(`/reports/${scanId}`),
};
