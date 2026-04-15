// ---------------------------------------------------------------------------
// HTML report generator — self-contained single-file report
// ---------------------------------------------------------------------------

import type { ReportInput } from '../report-engine.js';

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return '#dc2626';
    case 'high': return '#ea580c';
    case 'medium': return '#ca8a04';
    case 'low': return '#2563eb';
    default: return '#6b7280';
  }
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

export function generateHtmlReport(input: ReportInput): string {
  const { summary, findings, correlatedGroups, scanId, targetName, scanDate, reportType, validation } = input;

  const findingRows = findings.map((f) => `
    <tr>
      <td><span class="severity-badge" style="background:${severityColor(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span></td>
      <td>${escapeHtml(f.title)}</td>
      <td>${escapeHtml(f.category)}</td>
      <td>${escapeHtml(f.scanner)}</td>
      <td>${escapeHtml(f.file_path || f.endpoint || '-')}</td>
      <td>${f.line_start || '-'}</td>
      <td>${f.autofixable ? 'Yes' : 'No'}</td>
      <td>${f.priority_score}</td>
    </tr>
  `).join('');

  const correlationSection = correlatedGroups.length > 0 ? `
    <h2>Correlated Risk Groups</h2>
    ${correlatedGroups.map((g) => `
      <div class="correlation-card">
        <h3><span class="severity-badge" style="background:${severityColor(g.combined_severity)}">${g.combined_severity.toUpperCase()}</span> ${escapeHtml(g.title)}</h3>
        <p>${escapeHtml(g.description)}</p>
        <p><strong>Rationale:</strong> ${escapeHtml(g.rationale)}</p>
        <p><em>${g.finding_ids.length} findings correlated</em></p>
      </div>
    `).join('')}
  ` : '';

  const validationSection = validation ? `
    <h2>Validation Results</h2>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-value">${validation.fixed}</div><div class="stat-label">Fixed</div></div>
      <div class="stat-card"><div class="stat-value">${validation.unchanged}</div><div class="stat-label">Unchanged</div></div>
      <div class="stat-card"><div class="stat-value">${validation.regressed}</div><div class="stat-label">Regressed</div></div>
      <div class="stat-card"><div class="stat-value">${validation.new_findings}</div><div class="stat-label">New</div></div>
    </div>
  ` : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureScope Report - ${escapeHtml(targetName)}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1f2937; background: #f9fafb; }
    .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
    h1 { font-size: 1.875rem; margin-bottom: 0.5rem; }
    h2 { font-size: 1.5rem; margin: 2rem 0 1rem; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem; }
    .meta { color: #6b7280; margin-bottom: 2rem; }
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
    .stat-card { background: white; border-radius: 0.5rem; padding: 1.5rem; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .stat-value { font-size: 2rem; font-weight: 700; }
    .stat-label { font-size: 0.875rem; color: #6b7280; text-transform: uppercase; }
    .stat-critical { color: #dc2626; }
    .stat-high { color: #ea580c; }
    .stat-medium { color: #ca8a04; }
    .stat-low { color: #2563eb; }
    .stat-info { color: #6b7280; }
    table { width: 100%; border-collapse: collapse; background: white; border-radius: 0.5rem; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid #e5e7eb; font-size: 0.875rem; }
    th { background: #f3f4f6; font-weight: 600; }
    tr:hover { background: #f9fafb; }
    .severity-badge { display: inline-block; padding: 0.125rem 0.5rem; border-radius: 9999px; color: white; font-size: 0.75rem; font-weight: 600; }
    .correlation-card { background: white; border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 4px solid #dc2626; }
    .footer { margin-top: 3rem; text-align: center; color: #9ca3af; font-size: 0.75rem; }
  </style>
</head>
<body>
  <div class="container">
    <h1>SecureScope Security Report</h1>
    <div class="meta">
      <strong>Target:</strong> ${escapeHtml(targetName)} &bull;
      <strong>Scan ID:</strong> ${escapeHtml(scanId.slice(0, 8))} &bull;
      <strong>Type:</strong> ${escapeHtml(reportType)} &bull;
      <strong>Date:</strong> ${escapeHtml(scanDate)} &bull;
      <strong>Generated:</strong> ${new Date().toISOString()}
    </div>

    <h2>Summary</h2>
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-value">${summary.total_findings}</div><div class="stat-label">Total Findings</div></div>
      <div class="stat-card"><div class="stat-value stat-critical">${summary.critical}</div><div class="stat-label">Critical</div></div>
      <div class="stat-card"><div class="stat-value stat-high">${summary.high}</div><div class="stat-label">High</div></div>
      <div class="stat-card"><div class="stat-value stat-medium">${summary.medium}</div><div class="stat-label">Medium</div></div>
      <div class="stat-card"><div class="stat-value stat-low">${summary.low}</div><div class="stat-label">Low</div></div>
      <div class="stat-card"><div class="stat-value stat-info">${summary.informational}</div><div class="stat-label">Info</div></div>
      <div class="stat-card"><div class="stat-value">${summary.autofixable}</div><div class="stat-label">Auto-fixable</div></div>
    </div>

    ${correlationSection}
    ${validationSection}

    <h2>Findings (${findings.length})</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th><th>Title</th><th>Category</th><th>Scanner</th><th>Location</th><th>Line</th><th>Fixable</th><th>Priority</th>
        </tr>
      </thead>
      <tbody>${findingRows}</tbody>
    </table>

    <div class="footer">
      <p>Generated by SecureScope &mdash; Vulnerability Discovery &amp; Remediation Platform</p>
      <p>This report may contain sensitive security information. Handle according to your organization's data classification policy.</p>
    </div>
  </div>
</body>
</html>`;
}
