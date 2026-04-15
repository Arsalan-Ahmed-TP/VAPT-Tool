// ---------------------------------------------------------------------------
// Correlation engine — finds compound risks across scanner findings
// ---------------------------------------------------------------------------

import { randomUUID } from 'node:crypto';
import type { NormalizedFinding } from '@securescope/shared-types';
import { Severity, ScannerCategory } from '@securescope/shared-types';

export interface CorrelationResult {
  id: string;
  title: string;
  description: string;
  finding_ids: string[];
  combined_severity: Severity;
  combined_priority_score: number;
  correlation_type: string;
  rationale: string;
}

/**
 * Run all correlation rules against findings from a scan.
 * Each rule looks for a specific pattern of compound risk.
 */
export function correlateFindings(findings: NormalizedFinding[]): CorrelationResult[] {
  const results: CorrelationResult[] = [];

  results.push(...correlateVulnDepWithEndpoint(findings));
  results.push(...correlateSecretWithExposure(findings));
  results.push(...correlateSastWithDast(findings));
  results.push(...correlateInfraWithContainer(findings));

  return results;
}

/**
 * Rule 1: Vulnerable dependency used by a reachable endpoint.
 * A known CVE in a dependency is more severe when that dependency
 * serves live traffic.
 */
function correlateVulnDepWithEndpoint(findings: NormalizedFinding[]): CorrelationResult[] {
  const results: CorrelationResult[] = [];
  const depFindings = findings.filter((f) => f.category === ScannerCategory.DependencyScanning);
  const endpointFindings = findings.filter((f) =>
    f.category === ScannerCategory.DAST || f.category === ScannerCategory.ApiSecurity,
  );

  if (depFindings.length > 0 && endpointFindings.length > 0) {
    // Group: any critical/high dep vuln + any endpoint finding = compound risk
    const criticalDeps = depFindings.filter((f) =>
      f.severity === Severity.Critical || f.severity === Severity.High,
    );

    if (criticalDeps.length > 0 && endpointFindings.length > 0) {
      results.push({
        id: randomUUID(),
        title: 'Vulnerable Dependency Serving Live Traffic',
        description: `${criticalDeps.length} high/critical dependency vulnerabilities detected alongside ${endpointFindings.length} live endpoint findings`,
        finding_ids: [
          ...criticalDeps.map((f) => f.finding_id),
          ...endpointFindings.slice(0, 5).map((f) => f.finding_id),
        ],
        combined_severity: Severity.Critical,
        combined_priority_score: 98,
        correlation_type: 'vuln_dep_reachable_endpoint',
        rationale: 'Vulnerable dependencies that serve live traffic have increased exploitability because attackers can directly trigger the vulnerable code path through the exposed endpoints.',
      });
    }
  }

  return results;
}

/**
 * Rule 2: Hardcoded secret + verified or high-confidence exposure.
 */
function correlateSecretWithExposure(findings: NormalizedFinding[]): CorrelationResult[] {
  const results: CorrelationResult[] = [];
  const secretFindings = findings.filter((f) => f.category === ScannerCategory.SecretScanning);
  const dastFindings = findings.filter((f) => f.category === ScannerCategory.DAST);

  // If secrets are found and there are information disclosure findings in DAST
  const infoDisclosure = dastFindings.filter((f) =>
    f.title.toLowerCase().includes('information disclosure') ||
    f.title.toLowerCase().includes('error') ||
    f.title.toLowerCase().includes('header'),
  );

  if (secretFindings.length > 0 && infoDisclosure.length > 0) {
    results.push({
      id: randomUUID(),
      title: 'Exposed Secrets with Information Disclosure',
      description: `${secretFindings.length} secrets found in source code alongside ${infoDisclosure.length} information disclosure issues in the running application`,
      finding_ids: [
        ...secretFindings.map((f) => f.finding_id),
        ...infoDisclosure.slice(0, 3).map((f) => f.finding_id),
      ],
      combined_severity: Severity.Critical,
      combined_priority_score: 99,
      correlation_type: 'secret_with_exposure',
      rationale: 'Hardcoded secrets combined with information disclosure endpoints create a critical risk: secrets may be exposed through error messages, headers, or debug output.',
    });
  }

  return results;
}

/**
 * Rule 3: SAST finding confirmed by DAST (same vulnerability class).
 */
function correlateSastWithDast(findings: NormalizedFinding[]): CorrelationResult[] {
  const results: CorrelationResult[] = [];
  const sastFindings = findings.filter((f) => f.category === ScannerCategory.SAST);
  const dastFindings = findings.filter((f) => f.category === ScannerCategory.DAST);

  // Match by CWE
  const sastByCwe = new Map<string, NormalizedFinding[]>();
  for (const f of sastFindings) {
    if (f.cwe) {
      const arr = sastByCwe.get(f.cwe) || [];
      arr.push(f);
      sastByCwe.set(f.cwe, arr);
    }
  }

  for (const dast of dastFindings) {
    if (dast.cwe && sastByCwe.has(dast.cwe)) {
      const matchingSast = sastByCwe.get(dast.cwe)!;
      results.push({
        id: randomUUID(),
        title: `SAST+DAST Confirmed: ${dast.cwe}`,
        description: `${dast.cwe} detected in both source code analysis and runtime testing, confirming exploitability`,
        finding_ids: [dast.finding_id, ...matchingSast.map((f) => f.finding_id)],
        combined_severity: Severity.Critical,
        combined_priority_score: 97,
        correlation_type: 'sast_dast_confirmation',
        rationale: `When both SAST and DAST detect the same vulnerability class (${dast.cwe}), it confirms that the code-level issue is exploitable at runtime. This is a confirmed vulnerability.`,
      });
    }
  }

  return results;
}

/**
 * Rule 4: Infrastructure misconfiguration + container vulnerability.
 */
function correlateInfraWithContainer(findings: NormalizedFinding[]): CorrelationResult[] {
  const results: CorrelationResult[] = [];
  const infraFindings = findings.filter((f) => f.category === ScannerCategory.InfraScanning);
  const containerFindings = findings.filter((f) => f.category === ScannerCategory.ContainerScanning);

  if (infraFindings.length > 0 && containerFindings.length > 0) {
    const highInfra = infraFindings.filter((f) =>
      f.severity === Severity.High || f.severity === Severity.Critical,
    );
    const highContainer = containerFindings.filter((f) =>
      f.severity === Severity.High || f.severity === Severity.Critical,
    );

    if (highInfra.length > 0 && highContainer.length > 0) {
      results.push({
        id: randomUUID(),
        title: 'Vulnerable Container in Misconfigured Infrastructure',
        description: `${highContainer.length} high/critical container vulnerabilities running in infrastructure with ${highInfra.length} misconfigurations`,
        finding_ids: [
          ...highInfra.slice(0, 5).map((f) => f.finding_id),
          ...highContainer.slice(0, 5).map((f) => f.finding_id),
        ],
        combined_severity: Severity.Critical,
        combined_priority_score: 95,
        correlation_type: 'infra_container_compound',
        rationale: 'Vulnerable containers deployed in misconfigured infrastructure amplify risk: infrastructure gaps (privileged containers, weak RBAC, public exposure) make container vulnerabilities easier to exploit.',
      });
    }
  }

  return results;
}
