// ---------------------------------------------------------------------------
// Core data models — every entity in the platform
// ---------------------------------------------------------------------------

import {
  ApiStyle,
  ApprovalScope,
  AssetType,
  AuditAction,
  AutofixMode,
  Confidence,
  CredentialType,
  Environment,
  JobStatus,
  RemediationStatus,
  ReportFormat,
  ScannerCategory,
  ScanProfile,
  ScanStatus,
  Severity,
  SourceType,
  ValidationStatus,
} from './enums.js';

// ---------------------------------------------------------------------------
// Common
// ---------------------------------------------------------------------------

export interface Timestamps {
  created_at: string; // ISO-8601
  updated_at: string;
}

// ---------------------------------------------------------------------------
// ScanTarget — what the user wants scanned
// ---------------------------------------------------------------------------

export interface ScanTarget extends Timestamps {
  id: string;
  name: string;
  source_type: SourceType;
  /** Git URL, uploaded archive path, live URL, image ref, etc. */
  location: string;
  /** Branch or tag for git repos */
  ref?: string;
  environment: Environment;
  /** Credential profile ID to use when accessing the target */
  credential_id?: string;
  /** Paths or URL patterns to exclude from scanning */
  exclusions: string[];
  /** User attestation that they own / are authorized to scan this target */
  authorization_confirmed: boolean;
  metadata: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// CredentialProfile — encrypted at rest, masked in logs
// ---------------------------------------------------------------------------

export interface CredentialProfile extends Timestamps {
  id: string;
  name: string;
  type: CredentialType;
  /** Encrypted blob — never exposed raw in UI/logs/reports */
  encrypted_value: string;
  /** Optional metadata like header name for custom headers */
  config: Record<string, string>;
  /** When this credential was last used */
  last_used_at?: string;
}

// ---------------------------------------------------------------------------
// ScanRequest — one invocation of the scanning pipeline
// ---------------------------------------------------------------------------

export interface ScanRequest extends Timestamps {
  id: string;
  target_id: string;
  status: ScanStatus;
  profile: ScanProfile;
  autofix_mode: AutofixMode;
  /** Whether live secret verification is allowed */
  allow_secret_verification: boolean;
  /** Requested output formats */
  report_formats: ReportFormat[];
  /** Which scanner categories to enable (empty = all applicable) */
  enabled_scanners: ScannerCategory[];
  /** Fingerprint results populated during discovery phase */
  fingerprint?: TargetFingerprint;
  /** IDs of scanner jobs created for this request */
  job_ids: string[];
  /** Summary stats populated after completion */
  summary?: ScanSummary;
  started_at?: string;
  completed_at?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// TargetFingerprint — auto-detected characteristics
// ---------------------------------------------------------------------------

export interface TargetFingerprint {
  languages: string[];
  frameworks: string[];
  package_managers: string[];
  dependency_manifests: string[];
  has_dockerfile: boolean;
  has_kubernetes: boolean;
  has_terraform: boolean;
  has_iac: boolean;
  api_styles: ApiStyle[];
  detected_endpoints: string[];
  auth_patterns: string[];
  frontend_detected: boolean;
  backend_detected: boolean;
  monorepo: boolean;
}

// ---------------------------------------------------------------------------
// ScannerJob — one scanner execution within a scan
// ---------------------------------------------------------------------------

export interface ScannerJob extends Timestamps {
  id: string;
  scan_id: string;
  scanner_name: string;
  category: ScannerCategory;
  status: JobStatus;
  /** Container/process ID for isolation tracking */
  execution_ref?: string;
  started_at?: string;
  completed_at?: string;
  /** Duration in milliseconds */
  duration_ms?: number;
  /** Path to raw output artifact */
  raw_artifact_path?: string;
  /** Count of findings produced after normalization */
  finding_count: number;
  exit_code?: number;
  error?: string;
  retries: number;
  max_retries: number;
}

// ---------------------------------------------------------------------------
// RawScanArtifact — raw scanner output, stored for auditability
// ---------------------------------------------------------------------------

export interface RawScanArtifact extends Timestamps {
  id: string;
  job_id: string;
  scanner_name: string;
  /** S3 key or local path */
  storage_path: string;
  content_type: string;
  size_bytes: number;
  checksum_sha256: string;
}

// ---------------------------------------------------------------------------
// NormalizedFinding — the canonical finding schema
// ---------------------------------------------------------------------------

export interface NormalizedFinding extends Timestamps {
  finding_id: string;
  scan_id: string;
  job_id: string;
  title: string;
  summary: string;
  category: ScannerCategory;
  scanner: string;
  scanner_rule_id: string;
  severity: Severity;
  confidence: Confidence;
  exploitability: 'easy' | 'moderate' | 'difficult' | 'theoretical';
  cvss?: number;
  cwe?: string;
  owasp_mapping?: string;
  asset_type: AssetType;
  asset_name: string;
  file_path?: string;
  line_start?: number;
  line_end?: number;
  endpoint?: string;
  method?: string;
  parameter?: string;
  environment: Environment;
  /** Raw evidence (may contain sensitive data — internal only) */
  evidence?: string;
  /** Redacted evidence safe for reports and UI */
  redacted_evidence?: string;
  remediation: string;
  fix_strategy?: string;
  autofixable: boolean;
  validation_status: ValidationStatus;
  /** ID of the finding this duplicates, if any */
  duplicate_of?: string;
  /** IDs of correlated findings from other scanners */
  correlation_refs: string[];
  discovered_at: string;
  rescanned_at?: string;
  /** Computed priority score (higher = fix first) */
  priority_score: number;
}

// ---------------------------------------------------------------------------
// CorrelatedFindingGroup — cross-scanner correlation
// ---------------------------------------------------------------------------

export interface CorrelatedFindingGroup extends Timestamps {
  id: string;
  scan_id: string;
  title: string;
  description: string;
  finding_ids: string[];
  combined_severity: Severity;
  combined_priority_score: number;
  correlation_type: string;
  /** Human-readable explanation of why these findings are correlated */
  rationale: string;
}

// ---------------------------------------------------------------------------
// Remediation entities
// ---------------------------------------------------------------------------

export interface RemediationProposal extends Timestamps {
  id: string;
  scan_id: string;
  finding_id: string;
  status: RemediationStatus;
  title: string;
  description: string;
  /** The actual diff / patch content */
  diff: string;
  file_path: string;
  /** Is this safe to auto-apply? */
  safe_to_auto_apply: boolean;
  /** Why it may not be safe */
  risk_notes?: string;
  /** Suggested tests to add */
  suggested_tests?: string[];
  /** Manual steps if auto-fix is not possible */
  manual_steps?: string[];
}

export interface RemediationApproval extends Timestamps {
  id: string;
  scan_id: string;
  scope: ApprovalScope;
  /** Which specific proposal IDs are approved (for ByFinding scope) */
  proposal_ids?: string[];
  /** Which severities are approved (for BySeverity scope) */
  approved_severities?: Severity[];
  /** Which categories are approved (for ByCategory scope) */
  approved_categories?: ScannerCategory[];
  approved_by: string;
  approved_at: string;
  notes?: string;
}

export interface CodePatch extends Timestamps {
  id: string;
  scan_id: string;
  proposal_id: string;
  approval_id: string;
  file_path: string;
  original_content_hash: string;
  patch_content: string;
  applied: boolean;
  applied_at?: string;
  rolled_back: boolean;
  rolled_back_at?: string;
  branch_name?: string;
}

// ---------------------------------------------------------------------------
// ValidationRun — re-scan after remediation
// ---------------------------------------------------------------------------

export interface ValidationRun extends Timestamps {
  id: string;
  original_scan_id: string;
  validation_scan_id: string;
  status: ScanStatus;
  comparison?: ValidationComparison;
  started_at?: string;
  completed_at?: string;
}

export interface ValidationComparison {
  total_before: number;
  total_after: number;
  fixed: number;
  partially_mitigated: number;
  unchanged: number;
  false_positive: number;
  regressed: number;
  requires_manual_validation: number;
  new_findings: number;
  findings_detail: ValidationFindingDetail[];
}

export interface ValidationFindingDetail {
  finding_id: string;
  title: string;
  severity: Severity;
  status: ValidationStatus;
  before_evidence?: string;
  after_evidence?: string;
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

export interface ReportArtifact extends Timestamps {
  id: string;
  scan_id: string;
  format: ReportFormat;
  report_type: 'executive' | 'technical' | 'remediation_plan' | 'findings' | 'validation' | 'compliance';
  storage_path: string;
  size_bytes: number;
  generated_at: string;
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

export interface AuditEvent {
  id: string;
  action: AuditAction;
  actor: string;
  target_type: string;
  target_id: string;
  details: Record<string, unknown>;
  ip_address?: string;
  timestamp: string;
}

// ---------------------------------------------------------------------------
// Integration config
// ---------------------------------------------------------------------------

export interface IntegrationConfig extends Timestamps {
  id: string;
  name: string;
  type: 'jira' | 'slack' | 'webhook' | 'github' | 'gitlab' | 'azure_devops';
  enabled: boolean;
  config: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Scan summary for dashboard
// ---------------------------------------------------------------------------

export interface ScanSummary {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  autofixable: number;
  scanners_run: number;
  scanners_succeeded: number;
  scanners_failed: number;
  duration_ms: number;
  correlated_groups: number;
}
