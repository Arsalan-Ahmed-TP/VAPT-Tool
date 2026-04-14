// ---------------------------------------------------------------------------
// Core enumerations used across the entire platform
// ---------------------------------------------------------------------------

/** How the user is providing the scan target */
export enum SourceType {
  GitRepository = 'git_repository',
  UploadedArchive = 'uploaded_archive',
  LiveUrl = 'live_url',
  DockerImage = 'docker_image',
  KubernetesManifest = 'kubernetes_manifest',
  TerraformDirectory = 'terraform_directory',
}

/** Environment classification — affects risk scoring and safety guardrails */
export enum Environment {
  Development = 'development',
  QA = 'qa',
  Staging = 'staging',
  Production = 'production',
}

/** How aggressive scanners should be */
export enum ScanProfile {
  Safe = 'safe',
  Balanced = 'balanced',
  Aggressive = 'aggressive',
}

/** What the platform is allowed to do with remediation */
export enum AutofixMode {
  Off = 'off',
  RecommendOnly = 'recommend_only',
  ApprovalRequired = 'approval_required',
}

/** Scanner categories */
export enum ScannerCategory {
  DAST = 'dast',
  SAST = 'sast',
  ApiSecurity = 'api_security',
  SecretScanning = 'secret_scanning',
  DependencyScanning = 'dependency_scanning',
  InfraScanning = 'infra_scanning',
  ContainerScanning = 'container_scanning',
}

/** Lifecycle state of a scan request */
export enum ScanStatus {
  Pending = 'pending',
  Validating = 'validating',
  Fingerprinting = 'fingerprinting',
  Planning = 'planning',
  Running = 'running',
  Normalizing = 'normalizing',
  Correlating = 'correlating',
  Reporting = 'reporting',
  Completed = 'completed',
  Failed = 'failed',
  Cancelled = 'cancelled',
}

/** Lifecycle state of an individual scanner job */
export enum JobStatus {
  Queued = 'queued',
  Running = 'running',
  Parsing = 'parsing',
  Completed = 'completed',
  Failed = 'failed',
  TimedOut = 'timed_out',
  Skipped = 'skipped',
}

/** Severity aligned with CVSS qualitative ratings */
export enum Severity {
  Critical = 'critical',
  High = 'high',
  Medium = 'medium',
  Low = 'low',
  Informational = 'informational',
}

/** Confidence the scanner has in its finding */
export enum Confidence {
  Confirmed = 'confirmed',
  High = 'high',
  Medium = 'medium',
  Low = 'low',
  Tentative = 'tentative',
}

/** What kind of asset the finding relates to */
export enum AssetType {
  SourceCode = 'source_code',
  Endpoint = 'endpoint',
  Dependency = 'dependency',
  Secret = 'secret',
  Container = 'container',
  InfraConfig = 'infra_config',
  ApiRoute = 'api_route',
}

/** Validation status after revalidation */
export enum ValidationStatus {
  Fixed = 'fixed',
  PartiallyMitigated = 'partially_mitigated',
  Unchanged = 'unchanged',
  FalsePositive = 'false_positive',
  Regressed = 'regressed',
  RequiresManualValidation = 'requires_manual_validation',
  NotRetested = 'not_retested',
}

/** Remediation approval scope */
export enum ApprovalScope {
  AllSafe = 'all_safe',
  BySeverity = 'by_severity',
  ByCategory = 'by_category',
  ByFinding = 'by_finding',
  RecommendOnly = 'recommend_only',
  ExportPatchOnly = 'export_patch_only',
  CreateBranchOnly = 'create_branch_only',
}

/** State of a remediation proposal */
export enum RemediationStatus {
  Proposed = 'proposed',
  Approved = 'approved',
  Rejected = 'rejected',
  Applied = 'applied',
  RolledBack = 'rolled_back',
  Verified = 'verified',
  VerificationFailed = 'verification_failed',
}

/** Audit event types for full traceability */
export enum AuditAction {
  ScanCreated = 'scan_created',
  ScanStarted = 'scan_started',
  ScanCompleted = 'scan_completed',
  ScanFailed = 'scan_failed',
  FindingCreated = 'finding_created',
  RemediationProposed = 'remediation_proposed',
  RemediationApproved = 'remediation_approved',
  RemediationRejected = 'remediation_rejected',
  RemediationApplied = 'remediation_applied',
  RemediationRolledBack = 'remediation_rolled_back',
  ValidationStarted = 'validation_started',
  ValidationCompleted = 'validation_completed',
  ReportGenerated = 'report_generated',
  CredentialCreated = 'credential_created',
  CredentialAccessed = 'credential_accessed',
  SettingsUpdated = 'settings_updated',
}

/** Report output formats */
export enum ReportFormat {
  HTML = 'html',
  JSON = 'json',
  Markdown = 'markdown',
  CSV = 'csv',
  SARIF = 'sarif',
}

/** Credential types the platform can store */
export enum CredentialType {
  GitPAT = 'git_pat',
  GitSSH = 'git_ssh',
  BearerToken = 'bearer_token',
  CookieSession = 'cookie_session',
  ApiKey = 'api_key',
  BasicAuth = 'basic_auth',
  CustomHeader = 'custom_header',
  OAuth2 = 'oauth2',
}

/** API style detection */
export enum ApiStyle {
  REST = 'rest',
  GraphQL = 'graphql',
  SOAP = 'soap',
  gRPC = 'grpc',
  Mixed = 'mixed',
  Unknown = 'unknown',
}
