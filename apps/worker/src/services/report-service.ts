// ---------------------------------------------------------------------------
// Report service — generates reports after scan completion
// ---------------------------------------------------------------------------

import { eq } from 'drizzle-orm';
import { writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { ReportEngine } from '@securescope/reporting';
import type { ReportInput } from '@securescope/reporting';
import { ReportFormat } from '@securescope/shared-types';
import type { NormalizedFinding, CorrelatedFindingGroup, ScanSummary } from '@securescope/shared-types';
import { db, scanRequests, scanTargets, normalizedFindings, correlatedGroups } from '../db.js';
import { config } from '../config.js';

const engine = new ReportEngine();

export async function generateScanReports(
  scanId: string,
  formats: ReportFormat[] = [ReportFormat.JSON, ReportFormat.HTML, ReportFormat.Markdown],
): Promise<string[]> {
  // Load scan + target
  const [scan] = await db.select().from(scanRequests).where(eq(scanRequests.id, scanId));
  if (!scan) throw new Error(`Scan ${scanId} not found`);

  const [target] = await db.select().from(scanTargets).where(eq(scanTargets.id, scan.target_id));
  if (!target) throw new Error(`Target ${scan.target_id} not found`);

  // Load findings and correlated groups
  const findings = await db.select().from(normalizedFindings).where(eq(normalizedFindings.scan_id, scanId));
  const groups = await db.select().from(correlatedGroups).where(eq(correlatedGroups.scan_id, scanId));

  const input: ReportInput = {
    scanId,
    targetName: target.name,
    scanDate: (scan.completed_at ?? scan.created_at).toISOString(),
    summary: (scan.summary as ScanSummary) ?? {
      total_findings: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
      autofixable: 0,
      scanners_run: 0,
      scanners_succeeded: 0,
      scanners_failed: 0,
      duration_ms: 0,
      correlated_groups: 0,
    },
    findings: findings as unknown as NormalizedFinding[],
    correlatedGroups: groups as unknown as CorrelatedFindingGroup[],
    reportType: 'technical',
  };

  const reports = await engine.generate(input, formats);

  const outDir = join(config.scanners.artifactDir, scanId, 'reports');
  await mkdir(outDir, { recursive: true });

  const paths: string[] = [];
  for (const report of reports) {
    const filePath = join(outDir, report.filename);
    await writeFile(filePath, report.content, 'utf-8');
    paths.push(filePath);
  }

  return paths;
}
