// ---------------------------------------------------------------------------
// JSON report generator
// ---------------------------------------------------------------------------

import type { ReportInput } from '../report-engine.js';

export function generateJsonReport(input: ReportInput): string {
  return JSON.stringify({
    report: {
      type: input.reportType,
      scan_id: input.scanId,
      target: input.targetName,
      generated_at: new Date().toISOString(),
      scan_date: input.scanDate,
    },
    summary: input.summary,
    findings: input.findings.map((f) => ({
      ...f,
      // Strip raw evidence from exported reports
      evidence: undefined,
      redacted_evidence: f.redacted_evidence,
    })),
    correlated_groups: input.correlatedGroups,
    validation: input.validation || null,
  }, null, 2);
}
