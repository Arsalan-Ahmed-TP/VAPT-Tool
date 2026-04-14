// ---------------------------------------------------------------------------
// DAST adapter — OWASP ZAP
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

interface ZapAlert {
  pluginid: string;
  alertRef: string;
  alert: string;
  name: string;
  riskcode: string;
  confidence: string;
  riskdesc: string;
  desc: string;
  solution: string;
  reference: string;
  cweid: string;
  wascid: string;
  instances: ZapInstance[];
}

interface ZapInstance {
  uri: string;
  method: string;
  param: string;
  attack: string;
  evidence: string;
}

interface ZapReport {
  '@version': string;
  site: Array<{
    '@name': string;
    alerts: ZapAlert[];
  }>;
}

export class ZapAdapter extends BaseScannerAdapter {
  getCapability(): ScannerCapability {
    return {
      name: 'zap',
      displayName: 'OWASP ZAP DAST',
      category: ScannerCategory.DAST,
      supported_source_types: ['live_url'],
      relevant_languages: [],
      minimum_profile: ScanProfile.Safe,
      requires_network: true,
      requires_source: false,
      default_timeout_ms: 600_000, // 10 minutes
      supports_container_isolation: true,
      version: '2.x',
    };
  }

  shouldRun(fingerprint: TargetFingerprint, _profile: ScanProfile): boolean {
    // Run if we have a live target URL
    return fingerprint.detected_endpoints.length > 0 || fingerprint.api_styles.length > 0;
  }

  protected buildCommand(input: ScannerInput) {
    const outputPath = join(input.artifact_output_dir, 'zap-results.json');
    const targetUrl = input.target_url || '';

    const args = [
      `-cmd`,
      `-quickurl`, targetUrl,
      `-quickout`, outputPath,
      `-quickprogress`,
    ];

    // Add auth headers if provided
    if (input.credentials?.headers) {
      for (const [key, value] of Object.entries(input.credentials.headers)) {
        args.push('-config', `replacer.full_list(0).match_type=REQ_HEADER`);
        args.push('-config', `replacer.full_list(0).match_string=${key}`);
        args.push('-config', `replacer.full_list(0).replacement=${value}`);
      }
    }

    if (input.credentials?.bearer_token) {
      args.push('-config', `replacer.full_list(0).match_type=REQ_HEADER`);
      args.push('-config', `replacer.full_list(0).match_string=Authorization`);
      args.push('-config', `replacer.full_list(0).replacement=Bearer ${input.credentials.bearer_token}`);
    }

    return { command: 'zap.sh', args };
  }

  protected isSuccessExitCode(code: number): boolean {
    // ZAP: 0 = clean, 1 = warnings found, 2 = errors found
    return code === 0 || code === 1 || code === 2;
  }

  async parseResults(_rawResult: ScannerRawResult, input: ScannerInput): Promise<NormalizedFinding[]> {
    const findings: NormalizedFinding[] = [];
    const jsonPath = join(input.artifact_output_dir, 'zap-results.json');
    let raw: ZapReport;

    try {
      const content = await readFile(jsonPath, 'utf-8');
      raw = JSON.parse(content) as ZapReport;
    } catch {
      return findings;
    }

    const now = new Date().toISOString();

    for (const site of raw.site || []) {
      for (const alert of site.alerts || []) {
        const severity = this.mapRiskCode(alert.riskcode);

        for (const instance of alert.instances || []) {
          // Redact sensitive data from evidence
          const redactedEvidence = this.redactEvidence(instance.evidence);

          findings.push({
            finding_id: this.generateFindingId(),
            scan_id: input.job.scan_id,
            job_id: input.job.id,
            title: alert.name || alert.alert,
            summary: this.stripHtml(alert.desc),
            category: ScannerCategory.DAST,
            scanner: 'zap',
            scanner_rule_id: alert.pluginid,
            severity,
            confidence: this.mapConfidence(alert.confidence),
            exploitability: severity === Severity.Critical ? 'easy' : 'moderate',
            cwe: alert.cweid ? `CWE-${alert.cweid}` : undefined,
            asset_type: AssetType.Endpoint,
            asset_name: instance.uri,
            endpoint: instance.uri,
            method: instance.method,
            parameter: instance.param || undefined,
            environment: 'development' as any,
            evidence: instance.evidence,
            redacted_evidence: redactedEvidence,
            remediation: this.stripHtml(alert.solution),
            autofixable: false, // DAST findings generally need manual fix
            validation_status: ValidationStatus.NotRetested,
            correlation_refs: [],
            discovered_at: now,
            priority_score: this.computePriority(severity),
            created_at: now,
            updated_at: now,
          });
        }
      }
    }

    return findings;
  }

  private mapRiskCode(code: string): Severity {
    switch (code) {
      case '3': return Severity.High;
      case '2': return Severity.Medium;
      case '1': return Severity.Low;
      case '0': return Severity.Informational;
      default: return Severity.Medium;
    }
  }

  private mapConfidence(c: string): Confidence {
    switch (c) {
      case '3': return Confidence.High;
      case '2': return Confidence.Medium;
      case '1': return Confidence.Low;
      default: return Confidence.Medium;
    }
  }

  private stripHtml(html: string): string {
    return html?.replace(/<[^>]*>/g, '').trim() || '';
  }

  private redactEvidence(evidence: string): string {
    if (!evidence) return '';
    // Redact potential tokens/keys in evidence
    return evidence
      .replace(/([A-Za-z0-9+/=]{40,})/g, '[REDACTED]')
      .replace(/(password|token|secret|key|authorization)\s*[:=]\s*\S+/gi, '$1=[REDACTED]')
      .slice(0, 500);
  }

  private computePriority(severity: Severity): number {
    const scores: Record<Severity, number> = {
      [Severity.Critical]: 95,
      [Severity.High]: 80,
      [Severity.Medium]: 50,
      [Severity.Low]: 20,
      [Severity.Informational]: 5,
    };
    return scores[severity];
  }
}
