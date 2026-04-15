// ---------------------------------------------------------------------------
// Infrastructure/Container scanning adapter — Trivy
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

interface TrivyResult {
  Results?: TrivyTarget[];
}

interface TrivyTarget {
  Target: string;
  Class: string;
  Type: string;
  Vulnerabilities?: TrivyVuln[];
  Misconfigurations?: TrivyMisconfig[];
}

interface TrivyVuln {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Title: string;
  Description: string;
  Severity: string;
  References: string[];
  CVSS?: Record<string, { V3Score?: number }>;
  CweIDs?: string[];
}

interface TrivyMisconfig {
  Type: string;
  ID: string;
  AVDID: string;
  Title: string;
  Description: string;
  Message: string;
  Resolution: string;
  Severity: string;
  References: string[];
  CauseMetadata: {
    Provider?: string;
    Service?: string;
    StartLine?: number;
    EndLine?: number;
    Code?: { Lines: Array<{ Number: number; Content: string }> };
  };
}

export class TrivyAdapter extends BaseScannerAdapter {
  getCapability(): ScannerCapability {
    return {
      name: 'trivy',
      displayName: 'Trivy Container & IaC Scanner',
      category: ScannerCategory.InfraScanning,
      supported_source_types: ['git_repository', 'uploaded_archive', 'docker_image', 'kubernetes_manifest', 'terraform_directory'],
      relevant_languages: [],
      minimum_profile: ScanProfile.Safe,
      requires_network: true,
      requires_source: true,
      default_timeout_ms: 300_000,
      supports_container_isolation: true,
      version: '0.x',
    };
  }

  shouldRun(fingerprint: TargetFingerprint, _profile: ScanProfile): boolean {
    return (
      fingerprint.has_dockerfile ||
      fingerprint.has_kubernetes ||
      fingerprint.has_terraform ||
      fingerprint.has_iac
    );
  }

  protected buildCommand(input: ScannerInput) {
    const outputPath = join(input.artifact_output_dir, 'trivy-results.json');
    const args = [
      'fs',
      '--format', 'json',
      '--output', outputPath,
      '--scanners', 'vuln,misconfig,secret',
      '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
      input.source_path || '.',
    ];

    return { command: 'trivy', args };
  }

  protected isSuccessExitCode(code: number): boolean {
    return code === 0;
  }

  async parseResults(_rawResult: ScannerRawResult, input: ScannerInput): Promise<NormalizedFinding[]> {
    const findings: NormalizedFinding[] = [];
    const jsonPath = join(input.artifact_output_dir, 'trivy-results.json');
    let raw: TrivyResult;

    try {
      const content = await readFile(jsonPath, 'utf-8');
      raw = JSON.parse(content) as TrivyResult;
    } catch {
      return findings;
    }

    const now = new Date().toISOString();

    for (const target of raw.Results || []) {
      // Parse vulnerabilities
      for (const vuln of target.Vulnerabilities || []) {
        const severity = this.mapSeverity(vuln.Severity);
        const cvss = this.extractCvss(vuln);

        findings.push({
          finding_id: this.generateFindingId(),
          scan_id: input.job.scan_id,
          job_id: input.job.id,
          title: `${vuln.VulnerabilityID}: ${vuln.PkgName}`,
          summary: vuln.Title || vuln.Description?.slice(0, 300) || `Vulnerability in ${vuln.PkgName}`,
          category: ScannerCategory.ContainerScanning,
          scanner: 'trivy',
          scanner_rule_id: vuln.VulnerabilityID,
          severity,
          confidence: Confidence.High,
          exploitability: severity === Severity.Critical ? 'easy' : 'moderate',
          cvss,
          cwe: vuln.CweIDs?.[0],
          asset_type: AssetType.Container,
          asset_name: `${target.Target}:${vuln.PkgName}@${vuln.InstalledVersion}`,
          file_path: target.Target,
          environment: 'development' as any,
          evidence: `Package: ${vuln.PkgName}@${vuln.InstalledVersion}`,
          redacted_evidence: `Package: ${vuln.PkgName}@${vuln.InstalledVersion}`,
          remediation: vuln.FixedVersion
            ? `Upgrade ${vuln.PkgName} to ${vuln.FixedVersion}`
            : `No fix available. Consider alternative package or mitigation.`,
          fix_strategy: vuln.FixedVersion ? 'dependency_update' : 'manual_review',
          autofixable: !!vuln.FixedVersion,
          validation_status: ValidationStatus.NotRetested,
          correlation_refs: [],
          discovered_at: now,
          priority_score: this.computePriority(severity),
          created_at: now,
          updated_at: now,
        });
      }

      // Parse misconfigurations
      for (const mc of target.Misconfigurations || []) {
        const severity = this.mapSeverity(mc.Severity);

        findings.push({
          finding_id: this.generateFindingId(),
          scan_id: input.job.scan_id,
          job_id: input.job.id,
          title: `${mc.ID}: ${mc.Title}`,
          summary: mc.Description || mc.Message,
          category: ScannerCategory.InfraScanning,
          scanner: 'trivy',
          scanner_rule_id: mc.ID,
          severity,
          confidence: Confidence.High,
          exploitability: 'moderate',
          asset_type: AssetType.InfraConfig,
          asset_name: target.Target,
          file_path: target.Target,
          line_start: mc.CauseMetadata?.StartLine,
          line_end: mc.CauseMetadata?.EndLine,
          environment: 'development' as any,
          evidence: mc.Message,
          redacted_evidence: mc.Message?.slice(0, 500),
          remediation: mc.Resolution || `Fix misconfiguration ${mc.ID} in ${target.Target}`,
          fix_strategy: 'config_change',
          autofixable: false,
          validation_status: ValidationStatus.NotRetested,
          correlation_refs: [],
          discovered_at: now,
          priority_score: this.computePriority(severity),
          created_at: now,
          updated_at: now,
        });
      }
    }

    return findings;
  }

  private mapSeverity(s: string): Severity {
    switch (s?.toUpperCase()) {
      case 'CRITICAL': return Severity.Critical;
      case 'HIGH': return Severity.High;
      case 'MEDIUM': return Severity.Medium;
      case 'LOW': return Severity.Low;
      default: return Severity.Informational;
    }
  }

  private extractCvss(vuln: TrivyVuln): number | undefined {
    if (!vuln.CVSS) return undefined;
    for (const source of Object.values(vuln.CVSS)) {
      if (source.V3Score) return source.V3Score;
    }
    return undefined;
  }

  private computePriority(severity: Severity): number {
    const scores: Record<Severity, number> = {
      [Severity.Critical]: 90,
      [Severity.High]: 75,
      [Severity.Medium]: 50,
      [Severity.Low]: 20,
      [Severity.Informational]: 5,
    };
    return scores[severity];
  }
}
