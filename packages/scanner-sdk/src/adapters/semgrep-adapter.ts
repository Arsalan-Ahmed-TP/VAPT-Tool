// ---------------------------------------------------------------------------
// SAST adapter — Semgrep
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

interface SemgrepResult {
  results: SemgrepFinding[];
  errors: unknown[];
}

interface SemgrepFinding {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity: string;
    metadata?: {
      cwe?: string[];
      owasp?: string[];
      confidence?: string;
      impact?: string;
      likelihood?: string;
      references?: string[];
    };
    lines?: string;
    fix?: string;
  };
}

export class SemgrepAdapter extends BaseScannerAdapter {
  getCapability(): ScannerCapability {
    return {
      name: 'semgrep',
      displayName: 'Semgrep SAST',
      category: ScannerCategory.SAST,
      supported_source_types: ['git_repository', 'uploaded_archive'],
      relevant_languages: [], // Semgrep supports many languages
      minimum_profile: ScanProfile.Safe,
      requires_network: false,
      requires_source: true,
      default_timeout_ms: 300_000, // 5 minutes
      supports_container_isolation: true,
      version: '1.x',
    };
  }

  shouldRun(fingerprint: TargetFingerprint, _profile: ScanProfile): boolean {
    // Run if we have source code (always applicable for SAST)
    return fingerprint.languages.length > 0;
  }

  protected buildCommand(input: ScannerInput) {
    const outputPath = join(input.artifact_output_dir, 'semgrep-results.json');
    const args = [
      'scan',
      '--json',
      '--output', outputPath,
      '--config', 'auto', // Use Semgrep registry rules
      '--timeout', String(Math.floor(input.timeout_ms / 1000)),
    ];

    // Add exclusions
    for (const exclusion of input.exclusions) {
      args.push('--exclude', exclusion);
    }

    // Add source path
    if (input.source_path) {
      args.push(input.source_path);
    }

    return { command: 'semgrep', args };
  }

  // Semgrep returns exit code 1 when findings are present, 0 when clean
  protected isSuccessExitCode(code: number): boolean {
    return code === 0 || code === 1;
  }

  async parseResults(rawResult: ScannerRawResult, input: ScannerInput): Promise<NormalizedFinding[]> {
    const findings: NormalizedFinding[] = [];

    // Find the JSON results file
    const jsonPath = join(input.artifact_output_dir, 'semgrep-results.json');
    let raw: SemgrepResult;

    try {
      const content = await readFile(jsonPath, 'utf-8');
      raw = JSON.parse(content) as SemgrepResult;
    } catch {
      // If we can't parse results, try stdout
      try {
        const stdoutPath = rawResult.artifact_paths.find((p) => p.endsWith('stdout.txt'));
        if (!stdoutPath) return findings;
        const content = await readFile(stdoutPath, 'utf-8');
        raw = JSON.parse(content) as SemgrepResult;
      } catch {
        return findings;
      }
    }

    const now = new Date().toISOString();

    for (const result of raw.results) {
      const severity = this.mapSeverity(result.extra.severity);
      const confidence = this.mapConfidence(result.extra.metadata?.confidence);

      findings.push({
        finding_id: this.generateFindingId(),
        scan_id: input.job.scan_id,
        job_id: input.job.id,
        title: result.check_id.split('.').pop() || result.check_id,
        summary: result.extra.message,
        category: ScannerCategory.SAST,
        scanner: 'semgrep',
        scanner_rule_id: result.check_id,
        severity,
        confidence,
        exploitability: this.inferExploitability(severity, confidence),
        cwe: result.extra.metadata?.cwe?.[0],
        owasp_mapping: result.extra.metadata?.owasp?.[0],
        asset_type: AssetType.SourceCode,
        asset_name: result.path,
        file_path: result.path,
        line_start: result.start.line,
        line_end: result.end.line,
        environment: input.job.scan_id ? input.fingerprint.languages[0] || 'unknown' : 'unknown' as any,
        evidence: result.extra.lines,
        redacted_evidence: result.extra.lines?.slice(0, 500),
        remediation: result.extra.fix
          ? `Apply suggested fix: ${result.extra.fix}`
          : `Review and fix the ${result.check_id} issue at ${result.path}:${result.start.line}`,
        fix_strategy: result.extra.fix ? 'auto_patch' : 'manual_review',
        autofixable: !!result.extra.fix,
        validation_status: ValidationStatus.NotRetested,
        correlation_refs: [],
        discovered_at: now,
        priority_score: this.computePriority(severity, confidence),
        created_at: now,
        updated_at: now,
      });
    }

    return findings;
  }

  private mapSeverity(s: string): Severity {
    switch (s?.toUpperCase()) {
      case 'ERROR': return Severity.High;
      case 'WARNING': return Severity.Medium;
      case 'INFO': return Severity.Low;
      default: return Severity.Medium;
    }
  }

  private mapConfidence(c?: string): Confidence {
    switch (c?.toUpperCase()) {
      case 'HIGH': return Confidence.High;
      case 'MEDIUM': return Confidence.Medium;
      case 'LOW': return Confidence.Low;
      default: return Confidence.Medium;
    }
  }

  private inferExploitability(
    severity: Severity,
    confidence: Confidence,
  ): NormalizedFinding['exploitability'] {
    if (severity === Severity.Critical && confidence === Confidence.High) return 'easy';
    if (severity === Severity.High) return 'moderate';
    if (severity === Severity.Medium) return 'moderate';
    return 'difficult';
  }

  private computePriority(severity: Severity, confidence: Confidence): number {
    const severityScore: Record<Severity, number> = {
      [Severity.Critical]: 100,
      [Severity.High]: 80,
      [Severity.Medium]: 50,
      [Severity.Low]: 20,
      [Severity.Informational]: 5,
    };
    const confidenceMultiplier: Record<Confidence, number> = {
      [Confidence.Confirmed]: 1.0,
      [Confidence.High]: 0.9,
      [Confidence.Medium]: 0.7,
      [Confidence.Low]: 0.4,
      [Confidence.Tentative]: 0.2,
    };
    return Math.round(severityScore[severity] * confidenceMultiplier[confidence]);
  }
}
