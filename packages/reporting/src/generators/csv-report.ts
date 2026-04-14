// ---------------------------------------------------------------------------
// CSV report generator
// ---------------------------------------------------------------------------

import type { ReportInput } from '../report-engine.js';

function escapeCsv(value: string | number | boolean | undefined | null): string {
  if (value === null || value === undefined) return '';
  const str = String(value);
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export function generateCsvReport(input: ReportInput): string {
  const headers = [
    'Finding ID', 'Severity', 'Priority Score', 'Title', 'Summary',
    'Category', 'Scanner', 'Rule ID', 'Confidence', 'Exploitability',
    'CVSS', 'CWE', 'OWASP', 'Asset Type', 'Asset Name',
    'File Path', 'Line Start', 'Line End', 'Endpoint', 'Method',
    'Parameter', 'Auto-fixable', 'Validation Status', 'Remediation',
  ];

  const rows = input.findings.map((f) => [
    f.finding_id,
    f.severity,
    f.priority_score,
    f.title,
    f.summary,
    f.category,
    f.scanner,
    f.scanner_rule_id,
    f.confidence,
    f.exploitability,
    f.cvss ?? '',
    f.cwe ?? '',
    f.owasp_mapping ?? '',
    f.asset_type,
    f.asset_name,
    f.file_path ?? '',
    f.line_start ?? '',
    f.line_end ?? '',
    f.endpoint ?? '',
    f.method ?? '',
    f.parameter ?? '',
    f.autofixable,
    f.validation_status,
    f.remediation,
  ].map(escapeCsv));

  return [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
}
