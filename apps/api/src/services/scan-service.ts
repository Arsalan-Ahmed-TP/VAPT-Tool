// ---------------------------------------------------------------------------
// Scan orchestration service — creates scans and dispatches to workers
// ---------------------------------------------------------------------------

import { eq, desc, and, inArray, sql } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { scanPipelineQueue } from '../queue/index.js';
import { recordAuditEvent } from '../middleware/audit.js';
import { AuditAction, ScanStatus, Environment } from '@securescope/shared-types';
import type { CreateScanRequest } from '@securescope/shared-types';
import { logger } from '../logger.js';

export async function createScan(data: CreateScanRequest, actor: string) {
  // Validate target exists
  const [target] = await db.select().from(schema.scanTargets).where(eq(schema.scanTargets.id, data.target_id));
  if (!target) throw new Error('Target not found');

  // Warn about production environment
  if (target.environment === Environment.Production) {
    logger.warn('Scan requested against production environment', {
      target_id: target.id,
      actor,
    });
  }

  const [scan] = await db.insert(schema.scanRequests).values({
    target_id: data.target_id,
    status: 'pending',
    profile: data.profile || 'safe',
    autofix_mode: data.autofix_mode || 'off',
    allow_secret_verification: data.allow_secret_verification || false,
    report_formats: data.report_formats || ['json', 'html'],
    enabled_scanners: data.enabled_scanners || [],
  }).returning();

  await recordAuditEvent({
    action: AuditAction.ScanCreated,
    actor,
    target_type: 'scan',
    target_id: scan.id,
    details: {
      target_id: data.target_id,
      profile: data.profile,
      autofix_mode: data.autofix_mode,
    },
  });

  // Enqueue the scan pipeline
  await scanPipelineQueue.add('run-scan', {
    scan_id: scan.id,
    target_id: data.target_id,
  }, {
    jobId: `scan-${scan.id}`,
  });

  logger.info('Scan created and enqueued', { scan_id: scan.id });

  return { ...scan, target };
}

export async function getScan(id: string) {
  const [scan] = await db.select().from(schema.scanRequests).where(eq(schema.scanRequests.id, id));
  if (!scan) return null;

  const [target] = await db.select().from(schema.scanTargets).where(eq(schema.scanTargets.id, scan.target_id));
  const jobs = await db.select().from(schema.scannerJobs).where(eq(schema.scannerJobs.scan_id, id));

  return { ...scan, target, jobs };
}

export async function listScans(page = 1, pageSize = 20) {
  const offset = (page - 1) * pageSize;
  const scans = await db.select()
    .from(schema.scanRequests)
    .orderBy(desc(schema.scanRequests.created_at))
    .limit(pageSize)
    .offset(offset);
  return scans;
}

export async function getScanStatus(id: string) {
  const [scan] = await db.select().from(schema.scanRequests).where(eq(schema.scanRequests.id, id));
  if (!scan) return null;

  const jobs = await db.select().from(schema.scannerJobs).where(eq(schema.scannerJobs.scan_id, id));

  const completedJobs = jobs.filter((j) => j.status === 'completed').length;
  const totalJobs = jobs.length;
  const percent = totalJobs > 0 ? Math.round((completedJobs / totalJobs) * 100) : 0;

  return {
    scan_id: id,
    status: scan.status,
    progress: {
      phase: scan.status,
      percent,
      message: `${completedJobs}/${totalJobs} scanner jobs completed`,
    },
    jobs: jobs.map((j) => ({
      job_id: j.id,
      scanner: j.scanner_name,
      category: j.category,
      status: j.status,
      percent: j.status === 'completed' ? 100 : j.status === 'running' ? 50 : 0,
    })),
  };
}

export async function cancelScan(id: string, actor: string) {
  await db.update(schema.scanRequests)
    .set({ status: 'cancelled', updated_at: new Date() })
    .where(eq(schema.scanRequests.id, id));

  await recordAuditEvent({
    action: AuditAction.ScanFailed,
    actor,
    target_type: 'scan',
    target_id: id,
    details: { reason: 'cancelled_by_user' },
  });
}
