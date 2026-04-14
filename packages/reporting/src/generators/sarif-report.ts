// ---------------------------------------------------------------------------
// SARIF 2.1.0 report generator — for IDE and CI/CD integration
// ---------------------------------------------------------------------------

import { Severity } from '@securescope/shared-types';
import type { ReportInput } from '../report-engine.js';

function severityToSarifLevel(severity: string): string {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'informational':
      return 'note';
    default:
      return 'none';
  }
}

export function generateSarifReport(input: ReportInput): string {
  // Group findings by scanner to create separate runs
  const scannerGroups = new Map<string, typeof input.findings>();

  for (const f of input.findings) {
    const group = scannerGroups.get(f.scanner) || [];
    group.push(f);
    scannerGroups.set(f.scanner, group);
  }

  const runs = Array.from(scannerGroups.entries()).map(([scannerName, findings]) => {
    // Collect unique rules
    const rulesMap = new Map<string, { id: string; name: string; shortDescription: string }>();
    for (const f of findings) {
      if (!rulesMap.has(f.scanner_rule_id)) {
        rulesMap.set(f.scanner_rule_id, {
          id: f.scanner_rule_id,
          name: f.title,
          shortDescription: f.summary.slice(0, 200),
        });
      }
    }

    return {
      tool: {
        driver: {
          name: `SecureScope/${scannerName}`,
          version: '0.1.0',
          informationUri: 'https://github.com/securescope',
          rules: Array.from(rulesMap.values()).map((rule) => ({
            id: rule.id,
            name: rule.name,
            shortDescription: { text: rule.shortDescription },
          })),
        },
      },
      results: findings.map((f) => ({
        ruleId: f.scanner_rule_id,
        level: severityToSarifLevel(f.severity),
        message: {
          text: f.summary,
        },
        locations: f.file_path ? [{
          physicalLocation: {
            artifactLocation: {
              uri: f.file_path,
            },
            region: f.line_start ? {
              startLine: f.line_start,
              endLine: f.line_end || f.line_start,
            } : undefined,
          },
        }] : f.endpoint ? [{
          logicalLocations: [{
            fullyQualifiedName: `${f.method || 'GET'} ${f.endpoint}`,
          }],
        }] : [],
        properties: {
          severity: f.severity,
          confidence: f.confidence,
          priority_score: f.priority_score,
          category: f.category,
          autofixable: f.autofixable,
          ...(f.cwe ? { cwe: f.cwe } : {}),
          ...(f.cvss ? { cvss: f.cvss } : {}),
        },
        fixes: f.remediation ? [{
          description: { text: f.remediation },
        }] : undefined,
      })),
    };
  });

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs,
  };

  return JSON.stringify(sarif, null, 2);
}
