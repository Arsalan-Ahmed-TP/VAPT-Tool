// ---------------------------------------------------------------------------
// Database schema — Drizzle ORM definitions for PostgreSQL
// ---------------------------------------------------------------------------

import { pgTable, text, timestamp, integer, boolean, jsonb, real, pgEnum, uuid, index } from 'drizzle-orm/pg-core';

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

export const sourceTypeEnum = pgEnum('source_type', [
  'git_repository', 'uploaded_archive', 'live_url', 'docker_image', 'kubernetes_manifest', 'terraform_directory',
]);

export const environmentEnum = pgEnum('environment', ['development', 'qa', 'staging', 'production']);

export const scanProfileEnum = pgEnum('scan_profile', ['safe', 'balanced', 'aggressive']);

export const autofixModeEnum = pgEnum('autofix_mode', ['off', 'recommend_only', 'approval_required']);

export const scanStatusEnum = pgEnum('scan_status', [
  'pending', 'validating', 'fingerprinting', 'planning', 'running',
  'normalizing', 'correlating', 'reporting', 'completed', 'failed', 'cancelled',
]);

export const jobStatusEnum = pgEnum('job_status', [
  'queued', 'running', 'parsing', 'completed', 'failed', 'timed_out', 'skipped',
]);

export const severityEnum = pgEnum('severity', ['critical', 'high', 'medium', 'low', 'informational']);

export const confidenceEnum = pgEnum('confidence', ['confirmed', 'high', 'medium', 'low', 'tentative']);

export const scannerCategoryEnum = pgEnum('scanner_category', [
  'dast', 'sast', 'api_security', 'secret_scanning', 'dependency_scanning', 'infra_scanning', 'container_scanning',
]);

export const validationStatusEnum = pgEnum('validation_status', [
  'fixed', 'partially_mitigated', 'unchanged', 'false_positive', 'regressed', 'requires_manual_validation', 'not_retested',
]);

export const remediationStatusEnum = pgEnum('remediation_status', [
  'proposed', 'approved', 'rejected', 'applied', 'rolled_back', 'verified', 'verification_failed',
]);

export const credentialTypeEnum = pgEnum('credential_type', [
  'git_pat', 'git_ssh', 'bearer_token', 'cookie_session', 'api_key', 'basic_auth', 'custom_header', 'oauth2',
]);

export const reportFormatEnum = pgEnum('report_format', ['html', 'json', 'markdown', 'csv', 'sarif']);

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

export const scanTargets = pgTable('scan_targets', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  source_type: sourceTypeEnum('source_type').notNull(),
  location: text('location').notNull(),
  ref: text('ref'),
  environment: environmentEnum('environment').notNull().default('development'),
  credential_id: uuid('credential_id'),
  exclusions: jsonb('exclusions').$type<string[]>().default([]),
  authorization_confirmed: boolean('authorization_confirmed').notNull().default(false),
  metadata: jsonb('metadata').$type<Record<string, unknown>>().default({}),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
});

export const credentialProfiles = pgTable('credential_profiles', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: text('name').notNull(),
  type: credentialTypeEnum('type').notNull(),
  encrypted_value: text('encrypted_value').notNull(),
  config: jsonb('config').$type<Record<string, string>>().default({}),
  last_used_at: timestamp('last_used_at'),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
});

export const scanRequests = pgTable('scan_requests', {
  id: uuid('id').primaryKey().defaultRandom(),
  target_id: uuid('target_id').notNull().references(() => scanTargets.id),
  status: scanStatusEnum('status').notNull().default('pending'),
  profile: scanProfileEnum('profile').notNull().default('safe'),
  autofix_mode: autofixModeEnum('autofix_mode').notNull().default('off'),
  allow_secret_verification: boolean('allow_secret_verification').notNull().default(false),
  report_formats: jsonb('report_formats').$type<string[]>().default(['json', 'html']),
  enabled_scanners: jsonb('enabled_scanners').$type<string[]>().default([]),
  fingerprint: jsonb('fingerprint'),
  job_ids: jsonb('job_ids').$type<string[]>().default([]),
  summary: jsonb('summary'),
  started_at: timestamp('started_at'),
  completed_at: timestamp('completed_at'),
  error: text('error'),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
}, (table) => [
  index('idx_scan_requests_target').on(table.target_id),
  index('idx_scan_requests_status').on(table.status),
]);

export const scannerJobs = pgTable('scanner_jobs', {
  id: uuid('id').primaryKey().defaultRandom(),
  scan_id: uuid('scan_id').notNull().references(() => scanRequests.id),
  scanner_name: text('scanner_name').notNull(),
  category: scannerCategoryEnum('category').notNull(),
  status: jobStatusEnum('status').notNull().default('queued'),
  execution_ref: text('execution_ref'),
  started_at: timestamp('started_at'),
  completed_at: timestamp('completed_at'),
  duration_ms: integer('duration_ms'),
  raw_artifact_path: text('raw_artifact_path'),
  finding_count: integer('finding_count').notNull().default(0),
  exit_code: integer('exit_code'),
  error: text('error'),
  retries: integer('retries').notNull().default(0),
  max_retries: integer('max_retries').notNull().default(2),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
}, (table) => [
  index('idx_scanner_jobs_scan').on(table.scan_id),
  index('idx_scanner_jobs_status').on(table.status),
]);

export const normalizedFindings = pgTable('normalized_findings', {
  finding_id: uuid('finding_id').primaryKey().defaultRandom(),
  scan_id: uuid('scan_id').notNull().references(() => scanRequests.id),
  job_id: uuid('job_id').notNull().references(() => scannerJobs.id),
  title: text('title').notNull(),
  summary: text('summary').notNull(),
  category: scannerCategoryEnum('category').notNull(),
  scanner: text('scanner').notNull(),
  scanner_rule_id: text('scanner_rule_id').notNull(),
  severity: severityEnum('severity').notNull(),
  confidence: confidenceEnum('confidence').notNull(),
  exploitability: text('exploitability').notNull().default('moderate'),
  cvss: real('cvss'),
  cwe: text('cwe'),
  owasp_mapping: text('owasp_mapping'),
  asset_type: text('asset_type').notNull(),
  asset_name: text('asset_name').notNull(),
  file_path: text('file_path'),
  line_start: integer('line_start'),
  line_end: integer('line_end'),
  endpoint: text('endpoint'),
  method: text('method'),
  parameter: text('parameter'),
  environment: environmentEnum('environment').notNull().default('development'),
  evidence: text('evidence'),
  redacted_evidence: text('redacted_evidence'),
  remediation: text('remediation').notNull(),
  fix_strategy: text('fix_strategy'),
  autofixable: boolean('autofixable').notNull().default(false),
  validation_status: validationStatusEnum('validation_status').notNull().default('not_retested'),
  duplicate_of: uuid('duplicate_of'),
  correlation_refs: jsonb('correlation_refs').$type<string[]>().default([]),
  discovered_at: timestamp('discovered_at').defaultNow().notNull(),
  rescanned_at: timestamp('rescanned_at'),
  priority_score: real('priority_score').notNull().default(0),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
}, (table) => [
  index('idx_findings_scan').on(table.scan_id),
  index('idx_findings_severity').on(table.severity),
  index('idx_findings_category').on(table.category),
  index('idx_findings_priority').on(table.priority_score),
]);

export const correlatedGroups = pgTable('correlated_groups', {
  id: uuid('id').primaryKey().defaultRandom(),
  scan_id: uuid('scan_id').notNull().references(() => scanRequests.id),
  title: text('title').notNull(),
  description: text('description').notNull(),
  finding_ids: jsonb('finding_ids').$type<string[]>().default([]),
  combined_severity: severityEnum('combined_severity').notNull(),
  combined_priority_score: real('combined_priority_score').notNull().default(0),
  correlation_type: text('correlation_type').notNull(),
  rationale: text('rationale').notNull(),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
});

export const remediationProposals = pgTable('remediation_proposals', {
  id: uuid('id').primaryKey().defaultRandom(),
  scan_id: uuid('scan_id').notNull().references(() => scanRequests.id),
  finding_id: uuid('finding_id').notNull().references(() => normalizedFindings.finding_id),
  status: remediationStatusEnum('status').notNull().default('proposed'),
  title: text('title').notNull(),
  description: text('description').notNull(),
  diff: text('diff').notNull(),
  file_path: text('file_path').notNull(),
  safe_to_auto_apply: boolean('safe_to_auto_apply').notNull().default(false),
  risk_notes: text('risk_notes'),
  suggested_tests: jsonb('suggested_tests').$type<string[]>(),
  manual_steps: jsonb('manual_steps').$type<string[]>(),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
});

export const remediationApprovals = pgTable('remediation_approvals', {
  id: uuid('id').primaryKey().defaultRandom(),
  scan_id: uuid('scan_id').notNull().references(() => scanRequests.id),
  scope: text('scope').notNull(),
  proposal_ids: jsonb('proposal_ids').$type<string[]>(),
  approved_severities: jsonb('approved_severities').$type<string[]>(),
  approved_categories: jsonb('approved_categories').$type<string[]>(),
  approved_by: text('approved_by').notNull(),
  approved_at: timestamp('approved_at').defaultNow().notNull(),
  notes: text('notes'),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
});

export const codePatches = pgTable('code_patches', {
  id: uuid('id').primaryKey().defaultRandom(),
  scan_id: uuid('scan_id').notNull().references(() => scanRequests.id),
  proposal_id: uuid('proposal_id').notNull().references(() => remediationProposals.id),
  approval_id: uuid('approval_id').notNull().references(() => remediationApprovals.id),
  file_path: text('file_path').notNull(),
  original_content_hash: text('original_content_hash').notNull(),
  patch_content: text('patch_content').notNull(),
  applied: boolean('applied').notNull().default(false),
  applied_at: timestamp('applied_at'),
  rolled_back: boolean('rolled_back').notNull().default(false),
  rolled_back_at: timestamp('rolled_back_at'),
  branch_name: text('branch_name'),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
});

export const validationRuns = pgTable('validation_runs', {
  id: uuid('id').primaryKey().defaultRandom(),
  original_scan_id: uuid('original_scan_id').notNull().references(() => scanRequests.id),
  validation_scan_id: uuid('validation_scan_id').references(() => scanRequests.id),
  status: scanStatusEnum('status').notNull().default('pending'),
  comparison: jsonb('comparison'),
  started_at: timestamp('started_at'),
  completed_at: timestamp('completed_at'),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
});

export const reportArtifacts = pgTable('report_artifacts', {
  id: uuid('id').primaryKey().defaultRandom(),
  scan_id: uuid('scan_id').notNull().references(() => scanRequests.id),
  format: reportFormatEnum('format').notNull(),
  report_type: text('report_type').notNull(),
  storage_path: text('storage_path').notNull(),
  size_bytes: integer('size_bytes').notNull().default(0),
  generated_at: timestamp('generated_at').defaultNow().notNull(),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
});

export const auditEvents = pgTable('audit_events', {
  id: uuid('id').primaryKey().defaultRandom(),
  action: text('action').notNull(),
  actor: text('actor').notNull(),
  target_type: text('target_type').notNull(),
  target_id: text('target_id').notNull(),
  details: jsonb('details').$type<Record<string, unknown>>().default({}),
  ip_address: text('ip_address'),
  timestamp: timestamp('timestamp').defaultNow().notNull(),
}, (table) => [
  index('idx_audit_action').on(table.action),
  index('idx_audit_target').on(table.target_type, table.target_id),
  index('idx_audit_timestamp').on(table.timestamp),
]);
