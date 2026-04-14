// ---------------------------------------------------------------------------
// Secret scanning adapter — Gitleaks
// ---------------------------------------------------------------------------

import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  type ScannerCapability,
  type ScannerInput,
  type ScannerRawResult,
  type NormalizedFinding,
  type TargetFingerprint,
  ScannerCategory,
  ScanProfile,
  Severity,
  Confidence,
  AssetType,
  ValidationStatus,
} from '@securescope/shared-types';
import { BaseScannerAdapter } from '../base-adapter.js';

interface GitleaksFinding {
  Description: string;
  StartLine: number;
  EndLine: number;
  StartColumn: number;
  EndColumn: number;
  Match: string;
  Secret: string;
  File: string;
  Commit: string;
  Entropy: number;
  Author: string;
  Email: string;
  Date: string;
  Message: string;
  Tags: string[];
  RuleID: string;
  Fingerprint: string;
}

export class GitleaksAdapter extends BaseScannerAdapter {
  getCapability(): ScannerCapability {
    return {
      name: 'gitleaks',
      displayName: 'Gitleaks Secret Scanner',
      category: ScannerCategory.SecretScanning,
      supported_source_types: ['git_repository', 'uploaded_archive'],
      relevant_languages: [],
      minimum_profile: ScanProfile.Safe,
      requires_network: false,
      requires_source: true,
      default_timeout_ms: 180_000, // 3 minutes
      supports_container_isolation: true,
      version: '8.x',
    };
  }

  shouldRun(_fingerprint: TargetFingerprint, _profile: ScanProfile): boolean {
    // Always run on source code — secrets can be anywhere
    return true;
  }

  protected buildCommand(input: ScannerInput) {
    const outputPath = join(input.artifact_output_dir, 'gitleaks-results.json');

    const args = [
      'detect',
      '--source', input.source_path || '.',
      '--report-format', 'json',
      '--report-path', outputPath,
      '--no-banner',
    ];

    // Scan git history by default; skip if not a git repo
    if (input.profile === ScanProfile.Safe) {
      args.push('--no-git'); // Only scan working tree in safe mode
    }

    return { command: 'gitleaks', args };
  }

  // Gitleaks: exit 0 = no leaks, exit 1 = leaks found
  protected isSuccessExitCode(code: number): boolean {
    return code === 0 || code === 1;
  }

  async parseResults(rawResult: ScannerRawResult, input: ScannerInput): Promise<NormalizedFinding[]> {
    const findings: NormalizedFinding[] = [];
    const jsonPath = join(input.artifact_output_dir, 'gitleaks-results.json');
    let raw: GitleaksFinding[];

    try {
      const content = await readFile(jsonPath, 'utf-8');
      raw = JSON.parse(content) as GitleaksFinding[];
    } catch {
      return findings;
    }

    const now = new Date().toISOString();

    for (const leak of raw) {
      // CRITICAL: Never expose the actual secret value
      const redactedMatch = this.redactSecret(leak.Match);
      const redactedSecret = this.redactSecret(leak.Secret);

      findings.push({
        finding_id: this.generateFindingId(),
        scan_id: input.job.scan_id,
        job_id: input.job.id,
        title: `Exposed Secret: ${leak.RuleID}`,
        summary: `${leak.Description} found in ${leak.File}:${leak.StartLine}`,
        category: ScannerCategory.SecretScanning,
        scanner: 'gitleaks',
        scanner_rule_id: leak.RuleID,
        severity: Severity.High, // Exposed secrets are always high severity
        confidence: leak.Entropy > 4.5 ? Confidence.High : Confidence.Medium,
        exploitability: 'easy', // Exposed secrets are trivially exploitable
        cwe: 'CWE-798', // Use of Hard-coded Credentials
        owasp_mapping: 'A07:2021 - Identification and Authentication Failures',
        asset_type: AssetType.Secret,
        asset_name: leak.File,
        file_path: leak.File,
        line_start: leak.StartLine,
        line_end: leak.EndLine,
        environment: 'development' as any,
        // Never store the raw secret
        evidence: `Rule: ${leak.RuleID}, File: ${leak.File}:${leak.StartLine}, Commit: ${leak.Commit?.slice(0, 8) || 'working-tree'}`,
        redacted_evidence: `Match: ${redactedMatch}`,
        remediation: this.buildRemediation(leak),
        fix_strategy: 'secret_rotation',
        autofixable: false, // Secrets need rotation, not just removal
        validation_status: ValidationStatus.NotRetested,
        correlation_refs: [],
        discovered_at: now,
        priority_score: 90, // Secrets are always high priority
        created_at: now,
        updated_at: now,
      });
    }

    return findings;
  }

  /**
   * Redact a secret value, showing only type hint and length.
   * NEVER expose full secret values.
   */
  private redactSecret(value: string): string {
    if (!value) return '[empty]';
    const len = value.length;
    if (len <= 8) return '[REDACTED]';
    // Show first 2 and last 2 chars only
    return `${value.slice(0, 2)}${'*'.repeat(Math.min(len - 4, 20))}${value.slice(-2)} (${len} chars)`;
  }

  private buildRemediation(leak: GitleaksFinding): string {
    const steps = [
      `1. Immediately rotate/revoke the ${leak.RuleID} credential`,
      `2. Remove the secret from ${leak.File}:${leak.StartLine}`,
      `3. Use environment variables or a secrets manager instead`,
      `4. Add ${leak.File} pattern to .gitignore if it's a config file`,
      `5. If this secret was committed to git history, consider the credential compromised and rotate it`,
      `6. Audit access logs for unauthorized use of this credential`,
    ];
    return steps.join('\n');
  }
}
