// ---------------------------------------------------------------------------
// Report engine — orchestrates multi-format report generation
// ---------------------------------------------------------------------------

import { ReportFormat } from '@securescope/shared-types';
import type { NormalizedFinding, ScanSummary, CorrelatedFindingGroup, ValidationComparison } from '@securescope/shared-types';
import { generateJsonReport } from './generators/json-report.js';
import { generateHtmlReport } from './generators/html-report.js';
import { generateMarkdownReport } from './generators/markdown-report.js';
import { generateCsvReport } from './generators/csv-report.js';
import { generateSarifReport } from './generators/sarif-report.js';

export interface ReportInput {
  scanId: string;
  targetName: string;
  scanDate: string;
  summary: ScanSummary;
  findings: NormalizedFinding[];
  correlatedGroups: CorrelatedFindingGroup[];
  validation?: ValidationComparison;
  reportType: 'executive' | 'technical' | 'remediation_plan' | 'findings' | 'validation' | 'compliance';
}

export interface GeneratedReport {
  format: ReportFormat;
  content: string;
  filename: string;
  contentType: string;
}

export class ReportEngine {
  async generate(input: ReportInput, formats: ReportFormat[]): Promise<GeneratedReport[]> {
    const reports: GeneratedReport[] = [];

    for (const format of formats) {
      const report = await this.generateSingle(input, format);
      reports.push(report);
    }

    return reports;
  }

  private async generateSingle(input: ReportInput, format: ReportFormat): Promise<GeneratedReport> {
    const baseName = `securescope-${input.reportType}-${input.scanId.slice(0, 8)}`;

    switch (format) {
      case ReportFormat.JSON:
        return {
          format,
          content: generateJsonReport(input),
          filename: `${baseName}.json`,
          contentType: 'application/json',
        };
      case ReportFormat.HTML:
        return {
          format,
          content: generateHtmlReport(input),
          filename: `${baseName}.html`,
          contentType: 'text/html',
        };
      case ReportFormat.Markdown:
        return {
          format,
          content: generateMarkdownReport(input),
          filename: `${baseName}.md`,
          contentType: 'text/markdown',
        };
      case ReportFormat.CSV:
        return {
          format,
          content: generateCsvReport(input),
          filename: `${baseName}.csv`,
          contentType: 'text/csv',
        };
      case ReportFormat.SARIF:
        return {
          format,
          content: generateSarifReport(input),
          filename: `${baseName}.sarif.json`,
          contentType: 'application/json',
        };
      default:
        throw new Error(`Unsupported report format: ${format}`);
    }
  }
}
