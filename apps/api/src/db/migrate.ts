// ---------------------------------------------------------------------------
// Database migration script — creates tables via raw SQL
// This avoids a drizzle-kit dependency for the MVP; in production
// you'd use drizzle-kit push or generate migration files.
// ---------------------------------------------------------------------------

import pg from 'pg';
import { config } from '../config.js';

const MIGRATION_SQL = `
-- Enums
DO $$ BEGIN
  CREATE TYPE source_type AS ENUM ('git_repository', 'uploaded_archive', 'live_url', 'docker_image', 'kubernetes_manifest', 'terraform_directory');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE environment AS ENUM ('development', 'qa', 'staging', 'production');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE scan_profile AS ENUM ('safe', 'balanced', 'aggressive');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE autofix_mode AS ENUM ('off', 'recommend_only', 'approval_required');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE scan_status AS ENUM ('pending', 'validating', 'fingerprinting', 'planning', 'running', 'normalizing', 'correlating', 'reporting', 'completed', 'failed', 'cancelled');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE job_status AS ENUM ('queued', 'running', 'parsing', 'completed', 'failed', 'timed_out', 'skipped');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE severity AS ENUM ('critical', 'high', 'medium', 'low', 'informational');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE confidence AS ENUM ('confirmed', 'high', 'medium', 'low', 'tentative');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE scanner_category AS ENUM ('dast', 'sast', 'api_security', 'secret_scanning', 'dependency_scanning', 'infra_scanning', 'container_scanning');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE validation_status AS ENUM ('fixed', 'partially_mitigated', 'unchanged', 'false_positive', 'regressed', 'requires_manual_validation', 'not_retested');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE remediation_status AS ENUM ('proposed', 'approved', 'rejected', 'applied', 'rolled_back', 'verified', 'verification_failed');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE credential_type AS ENUM ('git_pat', 'git_ssh', 'bearer_token', 'cookie_session', 'api_key', 'basic_auth', 'custom_header', 'oauth2');
EXCEPTION WHEN duplicate_object THEN null; END $$;

DO $$ BEGIN
  CREATE TYPE report_format AS ENUM ('html', 'json', 'markdown', 'csv', 'sarif');
EXCEPTION WHEN duplicate_object THEN null; END $$;

-- Tables
CREATE TABLE IF NOT EXISTS scan_targets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  source_type source_type NOT NULL,
  location TEXT NOT NULL,
  ref TEXT,
  environment environment NOT NULL DEFAULT 'development',
  credential_id UUID,
  exclusions JSONB DEFAULT '[]'::jsonb,
  authorization_confirmed BOOLEAN NOT NULL DEFAULT false,
  metadata JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS credential_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  type credential_type NOT NULL,
  encrypted_value TEXT NOT NULL,
  config JSONB DEFAULT '{}'::jsonb,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scan_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID NOT NULL REFERENCES scan_targets(id),
  status scan_status NOT NULL DEFAULT 'pending',
  profile scan_profile NOT NULL DEFAULT 'safe',
  autofix_mode autofix_mode NOT NULL DEFAULT 'off',
  allow_secret_verification BOOLEAN NOT NULL DEFAULT false,
  report_formats JSONB DEFAULT '["json","html"]'::jsonb,
  enabled_scanners JSONB DEFAULT '[]'::jsonb,
  fingerprint JSONB,
  job_ids JSONB DEFAULT '[]'::jsonb,
  summary JSONB,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_requests_target ON scan_requests(target_id);
CREATE INDEX IF NOT EXISTS idx_scan_requests_status ON scan_requests(status);

CREATE TABLE IF NOT EXISTS scanner_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scan_requests(id),
  scanner_name TEXT NOT NULL,
  category scanner_category NOT NULL,
  status job_status NOT NULL DEFAULT 'queued',
  execution_ref TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  duration_ms INTEGER,
  raw_artifact_path TEXT,
  finding_count INTEGER NOT NULL DEFAULT 0,
  exit_code INTEGER,
  error TEXT,
  retries INTEGER NOT NULL DEFAULT 0,
  max_retries INTEGER NOT NULL DEFAULT 2,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scanner_jobs_scan ON scanner_jobs(scan_id);
CREATE INDEX IF NOT EXISTS idx_scanner_jobs_status ON scanner_jobs(status);

CREATE TABLE IF NOT EXISTS normalized_findings (
  finding_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scan_requests(id),
  job_id UUID NOT NULL REFERENCES scanner_jobs(id),
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  category scanner_category NOT NULL,
  scanner TEXT NOT NULL,
  scanner_rule_id TEXT NOT NULL,
  severity severity NOT NULL,
  confidence confidence NOT NULL,
  exploitability TEXT NOT NULL DEFAULT 'moderate',
  cvss REAL,
  cwe TEXT,
  owasp_mapping TEXT,
  asset_type TEXT NOT NULL,
  asset_name TEXT NOT NULL,
  file_path TEXT,
  line_start INTEGER,
  line_end INTEGER,
  endpoint TEXT,
  method TEXT,
  parameter TEXT,
  environment environment NOT NULL DEFAULT 'development',
  evidence TEXT,
  redacted_evidence TEXT,
  remediation TEXT NOT NULL,
  fix_strategy TEXT,
  autofixable BOOLEAN NOT NULL DEFAULT false,
  validation_status validation_status NOT NULL DEFAULT 'not_retested',
  duplicate_of UUID,
  correlation_refs JSONB DEFAULT '[]'::jsonb,
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  rescanned_at TIMESTAMPTZ,
  priority_score REAL NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON normalized_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON normalized_findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_category ON normalized_findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_priority ON normalized_findings(priority_score);

CREATE TABLE IF NOT EXISTS correlated_groups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scan_requests(id),
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  finding_ids JSONB DEFAULT '[]'::jsonb,
  combined_severity severity NOT NULL,
  combined_priority_score REAL NOT NULL DEFAULT 0,
  correlation_type TEXT NOT NULL,
  rationale TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS remediation_proposals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scan_requests(id),
  finding_id UUID NOT NULL REFERENCES normalized_findings(finding_id),
  status remediation_status NOT NULL DEFAULT 'proposed',
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  diff TEXT NOT NULL,
  file_path TEXT NOT NULL,
  safe_to_auto_apply BOOLEAN NOT NULL DEFAULT false,
  risk_notes TEXT,
  suggested_tests JSONB,
  manual_steps JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS remediation_approvals (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scan_requests(id),
  scope TEXT NOT NULL,
  proposal_ids JSONB,
  approved_severities JSONB,
  approved_categories JSONB,
  approved_by TEXT NOT NULL,
  approved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS code_patches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scan_requests(id),
  proposal_id UUID NOT NULL REFERENCES remediation_proposals(id),
  approval_id UUID NOT NULL REFERENCES remediation_approvals(id),
  file_path TEXT NOT NULL,
  original_content_hash TEXT NOT NULL,
  patch_content TEXT NOT NULL,
  applied BOOLEAN NOT NULL DEFAULT false,
  applied_at TIMESTAMPTZ,
  rolled_back BOOLEAN NOT NULL DEFAULT false,
  rolled_back_at TIMESTAMPTZ,
  branch_name TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS validation_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  original_scan_id UUID NOT NULL REFERENCES scan_requests(id),
  validation_scan_id UUID REFERENCES scan_requests(id),
  status scan_status NOT NULL DEFAULT 'pending',
  comparison JSONB,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS report_artifacts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES scan_requests(id),
  format report_format NOT NULL,
  report_type TEXT NOT NULL,
  storage_path TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT NOT NULL,
  details JSONB DEFAULT '{}'::jsonb,
  ip_address TEXT,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_target ON audit_events(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
`;

async function migrate() {
  const client = new pg.Client({ connectionString: config.db.connectionString });
  try {
    await client.connect();
    console.log('Running migrations...');
    await client.query(MIGRATION_SQL);
    console.log('Migrations completed successfully');
  } catch (err) {
    console.error('Migration failed:', err);
    process.exit(1);
  } finally {
    await client.end();
  }
}

migrate();
