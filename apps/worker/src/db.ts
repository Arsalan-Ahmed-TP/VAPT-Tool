// ---------------------------------------------------------------------------
// Worker database connection (reuse same schema as API)
// ---------------------------------------------------------------------------

import { drizzle } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import { config } from './config.js';

// Import schema from API — in production these would share via the package
// For now we import the same schema definition patterns
import {
  pgTable, text, timestamp, integer, boolean, jsonb, real, pgEnum, uuid, index,
} from 'drizzle-orm/pg-core';

// Re-declare enums and tables to avoid cross-app import
// In a real setup, schema would live in a shared package
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
export const environmentEnum = pgEnum('environment', ['development', 'qa', 'staging', 'production']);
export const sourceTypeEnum = pgEnum('source_type', [
  'git_repository', 'uploaded_archive', 'live_url', 'docker_image', 'kubernetes_manifest', 'terraform_directory',
]);
export const credentialTypeEnum = pgEnum('credential_type', [
  'git_pat', 'git_ssh', 'bearer_token', 'cookie_session', 'api_key', 'basic_auth', 'custom_header', 'oauth2',
]);
export const reportFormatEnum = pgEnum('report_format', ['html', 'json', 'markdown', 'csv', 'sarif']);
export const remediationStatusEnum = pgEnum('remediation_status', [
  'proposed', 'approved', 'rejected', 'applied', 'rolled_back', 'verified', 'verification_failed',
]);

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
  target_id: uuid('target_id').notNull(),
  status: scanStatusEnum('status').notNull().default('pending'),
  profile: text('profile').notNull().default('safe'),
  autofix_mode: text('autofix_mode').notNull().default('off'),
  allow_secret_verification: boolean('allow_secret_verification').notNull().default(false),
  report_formats: jsonb('report_formats').$type<string[]>().default([]),
  enabled_scanners: jsonb('enabled_scanners').$type<string[]>().default([]),
  fingerprint: jsonb('fingerprint'),
  job_ids: jsonb('job_ids').$type<string[]>().default([]),
  summary: jsonb('summary'),
  started_at: timestamp('started_at'),
  completed_at: timestamp('completed_at'),
  error: text('error'),
  created_at: timestamp('created_at').defaultNow().notNull(),
  updated_at: timestamp('updated_at').defaultNow().notNull(),
});

export const scannerJobs = pgTable('scanner_jobs', {
  id: uuid('id').primaryKey().defaultRandom(),
  scan_id: uuid('scan_id').notNull(),
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
});

export const normalizedFindings = pgTable('normalized_findings', {
  finding_id: uuid('finding_id').primaryKey().defaultRandom(),
  scan_id: uuid('scan_id').notNull(),
  job_id: uuid('job_id').notNull(),
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
});

export const correlatedGroups = pgTable('correlated_groups', {
  id: uuid('id').primaryKey().defaultRandom(),
  scan_id: uuid('scan_id').notNull(),
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

const pool = new pg.Pool({
  connectionString: config.db.connectionString,
  max: 10,
});

export const db = drizzle(pool, {
  schema: {
    scanTargets, credentialProfiles, scanRequests, scannerJobs,
    normalizedFindings, correlatedGroups,
  },
});
