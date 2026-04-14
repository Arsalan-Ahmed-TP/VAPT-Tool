// ---------------------------------------------------------------------------
// API request/response contracts
// ---------------------------------------------------------------------------

import {
  ApprovalScope,
  AutofixMode,
  Environment,
  ReportFormat,
  ScannerCategory,
  ScanProfile,
  Severity,
  SourceType,
} from './enums.js';
import type {
  AuditEvent,
  CodePatch,
  CorrelatedFindingGroup,
  CredentialProfile,
  NormalizedFinding,
  RemediationApproval,
  RemediationProposal,
  ReportArtifact,
  ScannerJob,
  ScanRequest,
  ScanSummary,
  ScanTarget,
  ValidationComparison,
  ValidationRun,
} from './models.js';

// ---------------------------------------------------------------------------
// Generic
// ---------------------------------------------------------------------------

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface ApiError {
  error: string;
  message: string;
  details?: Record<string, unknown>;
  request_id?: string;
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

export interface CreateTargetRequest {
  name: string;
  source_type: SourceType;
  location: string;
  ref?: string;
  environment: Environment;
  credential_id?: string;
  exclusions?: string[];
  authorization_confirmed: boolean;
  metadata?: Record<string, unknown>;
}

export type TargetResponse = ScanTarget;

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

export interface CreateCredentialRequest {
  name: string;
  type: import('./enums.js').CredentialType;
  /** Raw value — will be encrypted before storage */
  value: string;
  config?: Record<string, string>;
}

/** Never returns the encrypted value */
export type CredentialResponse = Omit<CredentialProfile, 'encrypted_value'>;

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export interface CreateScanRequest {
  target_id: string;
  profile?: ScanProfile;
  autofix_mode?: AutofixMode;
  allow_secret_verification?: boolean;
  report_formats?: ReportFormat[];
  enabled_scanners?: ScannerCategory[];
}

export interface ScanResponse extends ScanRequest {
  target: ScanTarget;
  jobs: ScannerJob[];
  summary: ScanSummary | null;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: import('./enums.js').ScanStatus;
  progress: ScanProgressDetail;
  jobs: JobProgressDetail[];
}

export interface ScanProgressDetail {
  phase: string;
  percent: number;
  message: string;
}

export interface JobProgressDetail {
  job_id: string;
  scanner: string;
  category: ScannerCategory;
  status: import('./enums.js').JobStatus;
  percent: number;
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

export interface FindingsQuery {
  scan_id: string;
  severity?: Severity[];
  category?: ScannerCategory[];
  autofixable?: boolean;
  search?: string;
  sort_by?: 'priority_score' | 'severity' | 'discovered_at';
  sort_order?: 'asc' | 'desc';
  page?: number;
  page_size?: number;
}

export type FindingResponse = NormalizedFinding;
export type FindingsListResponse = PaginatedResponse<NormalizedFinding>;
export type CorrelatedGroupsResponse = PaginatedResponse<CorrelatedFindingGroup>;

// ---------------------------------------------------------------------------
// Remediation
// ---------------------------------------------------------------------------

export interface ApproveRemediationRequest {
  scan_id: string;
  scope: ApprovalScope;
  proposal_ids?: string[];
  approved_severities?: Severity[];
  approved_categories?: ScannerCategory[];
  notes?: string;
}

export interface ApplyRemediationRequest {
  approval_id: string;
  /** Create a branch instead of patching in-place */
  create_branch?: boolean;
  branch_name?: string;
  dry_run?: boolean;
}

export interface RemediationResponse {
  proposals: RemediationProposal[];
  approval?: RemediationApproval;
  patches: CodePatch[];
}

export interface PatchExportResponse {
  /** Combined unified diff */
  unified_diff: string;
  file_count: number;
  files: string[];
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export interface CreateValidationRequest {
  original_scan_id: string;
  /** Optionally restrict to specific scanner categories */
  scanner_categories?: ScannerCategory[];
}

export interface ValidationResponse extends ValidationRun {
  comparison: ValidationComparison | null;
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

export interface GenerateReportRequest {
  scan_id: string;
  formats: ReportFormat[];
  report_types: Array<'executive' | 'technical' | 'remediation_plan' | 'findings' | 'validation' | 'compliance'>;
}

export type ReportListResponse = ReportArtifact[];

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export interface AuditQuery {
  target_id?: string;
  scan_id?: string;
  action?: import('./enums.js').AuditAction;
  from?: string;
  to?: string;
  page?: number;
  page_size?: number;
}

export type AuditListResponse = PaginatedResponse<AuditEvent>;
