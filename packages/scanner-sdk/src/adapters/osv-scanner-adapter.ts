// ---------------------------------------------------------------------------
// Dependency scanning adapter — OSV-Scanner
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

interface OsvResult {
  results: OsvPackageResult[];
}

interface OsvPackageResult {
  source: { path: string; type: string };
  packages: OsvPackageVuln[];
}

interface OsvPackageVuln {
  package: { name: string; version: string; ecosystem: string };
  vulnerabilities: OsvVulnerability[];
  groups: Array<{ ids: string[]; aliases: string[] }>;
}

interface OsvVulnerability {
  id: string;
  summary: string;
  detail: string;
  aliases: string[];
  severity: Array<{ type: string; score: string }>;
  affected: Array<{
    package: { name: string; ecosystem: string };
    ranges: Array<{
      type: string;
      events: Array<{ introduced?: string; fixed?: string }>;
    }>;
  }>;
  references: Array<{ type: string; url: string }>;
  database_specific?: { severity?: string };
}

export class OsvScannerAdapter extends BaseScannerAdapter {
  getCapability(): ScannerCapability {
    return {
      name: 'osv-scanner',
      displayName: 'OSV-Scanner Dependency Check',
      category: ScannerCategory.DependencyScanning,
      supported_source_types: ['git_repository', 'uploaded_archive'],
      relevant_languages: [],
      minimum_profile: ScanProfile.Safe,
      requires_network: true, // Needs to query OSV database
      requires_source: true,
      default_timeout_ms: 120_000, // 2 minutes
      supports_container_isolation: true,
      version: '1.x',
    };
  }

  shouldRun(fingerprint: TargetFingerprint, _profile: ScanProfile): boolean {
    return fingerprint.dependency_manifests.length > 0 || fingerprint.package_managers.length > 0;
  }

  protected buildCommand(input: ScannerInput) {
    const outputPath = join(input.artifact_output_dir, 'osv-results.json');
    const args = [
      'scan',
      '--format', 'json',
      '--output', outputPath,
      '-r', // Recursive
      input.source_path || '.',
    ];

    return { command: 'osv-scanner', args };
  }

  // OSV-Scanner: exit 0 = no vulns, exit 1 = vulns found
  protected isSuccessExitCode(code: number): boolean {
    return code === 0 || code === 1;
  }

  async parseResults(_rawResult: ScannerRawResult, input: ScannerInput): Promise<NormalizedFinding[]> {
    const findings: NormalizedFinding[] = [];
    const jsonPath = join(input.artifact_output_dir, 'osv-results.json');
    let raw: OsvResult;

    try {
      const content = await readFile(jsonPath, 'utf-8');
      raw = JSON.parse(content) as OsvResult;
    } catch {
      return findings;
    }

    const now = new Date().toISOString();

    for (const result of raw.results || []) {
      for (const pkg of result.packages || []) {
        for (const vuln of pkg.vulnerabilities || []) {
          const severity = this.extractSeverity(vuln);
          const fixVersion = this.extractFixVersion(vuln, pkg.package.name);
          const cvss = this.extractCvss(vuln);

          findings.push({
            finding_id: this.generateFindingId(),
            scan_id: input.job.scan_id,
            job_id: input.job.id,
            title: `${vuln.id}: ${pkg.package.name}@${pkg.package.version}`,
            summary: vuln.summary || vuln.detail?.slice(0, 300) || `Vulnerability ${vuln.id} in ${pkg.package.name}`,
            category: ScannerCategory.DependencyScanning,
            scanner: 'osv-scanner',
            scanner_rule_id: vuln.id,
            severity,
            confidence: Confidence.High, // Database-backed findings are high confidence
            exploitability: severity === Severity.Critical ? 'easy' : 'moderate',
            cvss,
            cwe: undefined, // OSV doesn't always provide CWE
            owasp_mapping: 'A06:2021 - Vulnerable and Outdated Components',
            asset_type: AssetType.Dependency,
            asset_name: `${pkg.package.name}@${pkg.package.version}`,
            file_path: result.source.path,
            environment: 'development' as any,
            evidence: `Package: ${pkg.package.name}@${pkg.package.version}, Vuln: ${vuln.id}`,
            redacted_evidence: `Package: ${pkg.package.name}@${pkg.package.version}, Vuln: ${vuln.id}`,
            remediation: this.buildRemediation(pkg.package.name, pkg.package.version, fixVersion, vuln),
            fix_strategy: fixVersion ? 'dependency_update' : 'manual_review',
            autofixable: !!fixVersion,
            validation_status: ValidationStatus.NotRetested,
            correlation_refs: [],
            discovered_at: now,
            priority_score: this.computePriority(severity, !!fixVersion),
            created_at: now,
            updated_at: now,
          });
        }
      }
    }

    return findings;
  }

  private extractSeverity(vuln: OsvVulnerability): Severity {
    // Try CVSS score first
    const cvss = this.extractCvss(vuln);
    if (cvss !== undefined) {
      if (cvss >= 9.0) return Severity.Critical;
      if (cvss >= 7.0) return Severity.High;
      if (cvss >= 4.0) return Severity.Medium;
      if (cvss >= 0.1) return Severity.Low;
      return Severity.Informational;
    }

    // Fallback to database severity
    const dbSeverity = vuln.database_specific?.severity?.toUpperCase();
    switch (dbSeverity) {
      case 'CRITICAL': return Severity.Critical;
      case 'HIGH': return Severity.High;
      case 'MODERATE':
      case 'MEDIUM': return Severity.Medium;
      case 'LOW': return Severity.Low;
      default: return Severity.Medium;
    }
  }

  private extractCvss(vuln: OsvVulnerability): number | undefined {
    const cvssEntry = vuln.severity?.find((s) => s.type === 'CVSS_V3');
    if (cvssEntry) {
      const score = parseFloat(cvssEntry.score);
      return isNaN(score) ? undefined : score;
    }
    return undefined;
  }

  private extractFixVersion(vuln: OsvVulnerability, pkgName: string): string | undefined {
    for (const affected of vuln.affected || []) {
      if (affected.package?.name === pkgName) {
        for (const range of affected.ranges || []) {
          for (const event of range.events || []) {
            if (event.fixed) return event.fixed;
          }
        }
      }
    }
    return undefined;
  }

  private buildRemediation(
    name: string,
    currentVersion: string,
    fixVersion: string | undefined,
    vuln: OsvVulnerability,
  ): string {
    const lines: string[] = [];

    if (fixVersion) {
      lines.push(`Upgrade ${name} from ${currentVersion} to ${fixVersion} or later`);
      lines.push(`Run: npm update ${name} or manually set version to ^${fixVersion}`);
    } else {
      lines.push(`No known fix version available for ${vuln.id}`);
      lines.push(`Consider finding an alternative package or applying a workaround`);
    }

    const refs = vuln.references?.filter((r) => r.type === 'ADVISORY').slice(0, 3);
    if (refs?.length) {
      lines.push('References:');
      for (const ref of refs) {
        lines.push(`  - ${ref.url}`);
      }
    }

    return lines.join('\n');
  }

  private computePriority(severity: Severity, hasFixVersion: boolean): number {
    const scores: Record<Severity, number> = {
      [Severity.Critical]: 95,
      [Severity.High]: 75,
      [Severity.Medium]: 50,
      [Severity.Low]: 20,
      [Severity.Informational]: 5,
    };
    // Boost priority if a fix is available (easier to act on)
    return scores[severity] + (hasFixVersion ? 5 : 0);
  }
}
