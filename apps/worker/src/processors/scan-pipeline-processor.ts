// ---------------------------------------------------------------------------
// Scan pipeline processor — orchestrates the full scan lifecycle
// ---------------------------------------------------------------------------

import { Worker, type Job } from 'bullmq';
import { eq } from 'drizzle-orm';
import { randomUUID } from 'node:crypto';
import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import simpleGit from 'simple-git';
import IORedis from 'ioredis';
import { config } from '../config.js';
import { db, scanRequests, scannerJobs, scanTargets, normalizedFindings, correlatedGroups } from '../db.js';
import { fingerprintTarget } from '../services/fingerprint-service.js';
import { correlateFindings, type CorrelationResult } from '../services/correlation-service.js';
import {
  scannerRegistry,
  SemgrepAdapter,
  ZapAdapter,
  GitleaksAdapter,
  OsvScannerAdapter,
  TrivyAdapter,
} from '@securescope/scanner-sdk';
import type { ScannerAdapter, ScannerInput, NormalizedFinding, TargetFingerprint, ScanProfile } from '@securescope/shared-types';
import { ScannerCategory, JobStatus, Severity, ScanStatus } from '@securescope/shared-types';

import winston from 'winston';

const logger = winston.createLogger({
  level: config.logging.level,
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'scan-pipeline-worker' },
  transports: [new winston.transports.Console()],
});

// ---------------------------------------------------------------------------
// Register all scanner adapters
// ---------------------------------------------------------------------------

function registerScanners() {
  const adapters = [
    new SemgrepAdapter(),
    new ZapAdapter(),
    new GitleaksAdapter(),
    new OsvScannerAdapter(),
    new TrivyAdapter(),
  ];

  for (const adapter of adapters) {
    try {
      scannerRegistry.register(adapter.getCapability(), () => adapter);
    } catch {
      // Already registered
    }
  }
}

registerScanners();

// ---------------------------------------------------------------------------
// Pipeline phases
// ---------------------------------------------------------------------------

interface PipelineContext {
  scanId: string;
  targetId: string;
  sourcePath?: string;
  targetUrl?: string;
  fingerprint?: TargetFingerprint;
  profile: ScanProfile;
  enabledScanners: ScannerCategory[];
  exclusions: string[];
  allowSecretVerification: boolean;
  allFindings: NormalizedFinding[];
}

async function updateScanStatus(scanId: string, status: string) {
  await db.update(scanRequests)
    .set({ status: status as any, updated_at: new Date() })
    .where(eq(scanRequests.id, scanId));
}

async function phaseValidate(ctx: PipelineContext): Promise<void> {
  await updateScanStatus(ctx.scanId, 'validating');
  logger.info('Phase: Validating', { scan_id: ctx.scanId });

  const [target] = await db.select().from(scanTargets).where(eq(scanTargets.id, ctx.targetId));
  if (!target) throw new Error(`Target ${ctx.targetId} not found`);
  if (!target.authorization_confirmed) {
    throw new Error('Target authorization not confirmed — scan blocked');
  }

  ctx.exclusions = (target.exclusions as string[]) || [];
  ctx.targetUrl = target.source_type === 'live_url' ? target.location : undefined;
}

async function phaseFingerprint(ctx: PipelineContext): Promise<void> {
  await updateScanStatus(ctx.scanId, 'fingerprinting');
  logger.info('Phase: Fingerprinting', { scan_id: ctx.scanId });

  const [target] = await db.select().from(scanTargets).where(eq(scanTargets.id, ctx.targetId));

  // Clone source if it's a git repository
  if (target.source_type === 'git_repository') {
    const workDir = join(config.scanners.workDir, ctx.scanId);
    await mkdir(workDir, { recursive: true });
    const git = simpleGit();
    try {
      await git.clone(target.location, workDir, ['--depth', '50']);
      if (target.ref) {
        await simpleGit(workDir).checkout(target.ref);
      }
      ctx.sourcePath = workDir;
    } catch (err) {
      logger.error('Git clone failed', { error: (err as Error).message, scan_id: ctx.scanId });
      throw new Error(`Failed to clone repository: ${(err as Error).message}`);
    }
  }

  // Fingerprint source if available
  if (ctx.sourcePath) {
    ctx.fingerprint = await fingerprintTarget(ctx.sourcePath);
    await db.update(scanRequests)
      .set({ fingerprint: ctx.fingerprint as any, updated_at: new Date() })
      .where(eq(scanRequests.id, ctx.scanId));

    logger.info('Fingerprint complete', {
      scan_id: ctx.scanId,
      languages: ctx.fingerprint.languages,
      frameworks: ctx.fingerprint.frameworks,
    });
  } else {
    // Minimal fingerprint for URL-only scans
    ctx.fingerprint = {
      languages: [],
      frameworks: [],
      package_managers: [],
      dependency_manifests: [],
      has_dockerfile: false,
      has_kubernetes: false,
      has_terraform: false,
      has_iac: false,
      api_styles: [],
      detected_endpoints: ctx.targetUrl ? [ctx.targetUrl] : [],
      auth_patterns: [],
      frontend_detected: false,
      backend_detected: false,
      monorepo: false,
    };
  }
}

async function phasePlan(ctx: PipelineContext): Promise<ScannerAdapter[]> {
  await updateScanStatus(ctx.scanId, 'planning');
  logger.info('Phase: Planning', { scan_id: ctx.scanId });

  const selectedScanners = scannerRegistry.selectScanners(
    ctx.fingerprint!,
    ctx.profile,
    ctx.enabledScanners.length > 0 ? ctx.enabledScanners : undefined,
  );

  logger.info('Selected scanners', {
    scan_id: ctx.scanId,
    scanners: selectedScanners.map((s) => s.getCapability().name),
  });

  // Create scanner job records
  const jobIds: string[] = [];
  for (const scanner of selectedScanners) {
    const cap = scanner.getCapability();
    const [job] = await db.insert(scannerJobs).values({
      id: randomUUID(),
      scan_id: ctx.scanId,
      scanner_name: cap.name,
      category: cap.category,
      status: 'queued',
      max_retries: config.scanners.maxRetries,
    }).returning();
    jobIds.push(job.id);
  }

  await db.update(scanRequests)
    .set({ job_ids: jobIds, updated_at: new Date() })
    .where(eq(scanRequests.id, ctx.scanId));

  return selectedScanners;
}

async function phaseExecute(ctx: PipelineContext, scanners: ScannerAdapter[]): Promise<void> {
  await updateScanStatus(ctx.scanId, 'running');
  logger.info('Phase: Running scanners', { scan_id: ctx.scanId, count: scanners.length });

  await db.update(scanRequests)
    .set({ started_at: new Date(), updated_at: new Date() })
    .where(eq(scanRequests.id, ctx.scanId));

  // Run scanners — in production these would be parallelized per category
  for (const scanner of scanners) {
    const cap = scanner.getCapability();
    const [job] = await db.select().from(scannerJobs)
      .where(eq(scannerJobs.scanner_name, cap.name));

    if (!job) continue;

    const artifactDir = join(config.scanners.artifactDir, ctx.scanId, cap.name);
    await mkdir(artifactDir, { recursive: true });

    const input: ScannerInput = {
      job: job as any,
      source_path: ctx.sourcePath,
      target_url: ctx.targetUrl,
      fingerprint: ctx.fingerprint!,
      profile: ctx.profile,
      exclusions: ctx.exclusions,
      artifact_output_dir: artifactDir,
      timeout_ms: cap.default_timeout_ms,
      allow_secret_verification: ctx.allowSecretVerification,
    };

    // Update job status
    await db.update(scannerJobs)
      .set({ status: 'running', started_at: new Date(), updated_at: new Date() })
      .where(eq(scannerJobs.id, job.id));

    try {
      logger.info(`Running scanner: ${cap.name}`, { scan_id: ctx.scanId, job_id: job.id });

      const rawResult = await scanner.execute(input);

      await db.update(scannerJobs)
        .set({
          status: 'parsing',
          duration_ms: rawResult.duration_ms,
          exit_code: rawResult.exit_code,
          raw_artifact_path: artifactDir,
          updated_at: new Date(),
        })
        .where(eq(scannerJobs.id, job.id));

      // Parse results
      const findings = await scanner.parseResults(rawResult, input);

      // Store findings
      for (const finding of findings) {
        await db.insert(normalizedFindings).values(finding as any);
      }

      ctx.allFindings.push(...findings);

      await db.update(scannerJobs)
        .set({
          status: 'completed',
          finding_count: findings.length,
          completed_at: new Date(),
          updated_at: new Date(),
        })
        .where(eq(scannerJobs.id, job.id));

      logger.info(`Scanner complete: ${cap.name}`, {
        scan_id: ctx.scanId,
        findings: findings.length,
      });
    } catch (err) {
      logger.error(`Scanner failed: ${cap.name}`, {
        scan_id: ctx.scanId,
        error: (err as Error).message,
      });

      await db.update(scannerJobs)
        .set({
          status: 'failed',
          error: (err as Error).message,
          completed_at: new Date(),
          updated_at: new Date(),
        })
        .where(eq(scannerJobs.id, job.id));
    }
  }
}

async function phaseCorrelate(ctx: PipelineContext): Promise<void> {
  await updateScanStatus(ctx.scanId, 'correlating');
  logger.info('Phase: Correlating findings', { scan_id: ctx.scanId });

  if (ctx.allFindings.length === 0) return;

  const correlations = correlateFindings(ctx.allFindings);

  for (const corr of correlations) {
    await db.insert(correlatedGroups).values({
      id: corr.id,
      scan_id: ctx.scanId,
      title: corr.title,
      description: corr.description,
      finding_ids: corr.finding_ids,
      combined_severity: corr.combined_severity,
      combined_priority_score: corr.combined_priority_score,
      correlation_type: corr.correlation_type,
      rationale: corr.rationale,
    });

    // Update finding correlation refs
    for (const findingId of corr.finding_ids) {
      const [finding] = await db.select().from(normalizedFindings)
        .where(eq(normalizedFindings.finding_id, findingId));
      if (finding) {
        const refs = [...(finding.correlation_refs as string[] || []), corr.id];
        await db.update(normalizedFindings)
          .set({ correlation_refs: refs, updated_at: new Date() })
          .where(eq(normalizedFindings.finding_id, findingId));
      }
    }
  }

  logger.info('Correlation complete', {
    scan_id: ctx.scanId,
    groups: correlations.length,
  });
}

async function phaseFinalize(ctx: PipelineContext): Promise<void> {
  await updateScanStatus(ctx.scanId, 'reporting');

  const severityCounts = {
    critical: 0, high: 0, medium: 0, low: 0, informational: 0,
  };
  for (const f of ctx.allFindings) {
    const key = f.severity as keyof typeof severityCounts;
    if (key in severityCounts) severityCounts[key]++;
  }

  const summary = {
    total_findings: ctx.allFindings.length,
    ...severityCounts,
    autofixable: ctx.allFindings.filter((f) => f.autofixable).length,
    scanners_run: 0,
    scanners_succeeded: 0,
    scanners_failed: 0,
    duration_ms: 0,
    correlated_groups: 0,
  };

  await db.update(scanRequests)
    .set({
      status: 'completed',
      summary: summary as any,
      completed_at: new Date(),
      updated_at: new Date(),
    })
    .where(eq(scanRequests.id, ctx.scanId));

  logger.info('Scan complete', { scan_id: ctx.scanId, summary });
}

// ---------------------------------------------------------------------------
// Worker entry point
// ---------------------------------------------------------------------------

export function createScanPipelineWorker() {
  const connection = new IORedis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password,
    maxRetriesPerRequest: null,
    enableReadyCheck: false,
  });

  const worker = new Worker(
    'scan-pipeline',
    async (job: Job) => {
      const { scan_id, target_id } = job.data;

      logger.info('Starting scan pipeline', { scan_id, target_id });

      // Load scan config
      const [scan] = await db.select().from(scanRequests).where(eq(scanRequests.id, scan_id));
      if (!scan) throw new Error(`Scan ${scan_id} not found`);

      const ctx: PipelineContext = {
        scanId: scan_id,
        targetId: target_id,
        profile: scan.profile as ScanProfile,
        enabledScanners: (scan.enabled_scanners as ScannerCategory[]) || [],
        exclusions: [],
        allowSecretVerification: scan.allow_secret_verification,
        allFindings: [],
      };

      try {
        await phaseValidate(ctx);
        await phaseFingerprint(ctx);
        const scanners = await phasePlan(ctx);
        await phaseExecute(ctx, scanners);
        await phaseCorrelate(ctx);
        await phaseFinalize(ctx);
      } catch (err) {
        logger.error('Scan pipeline failed', {
          scan_id,
          error: (err as Error).message,
          stack: (err as Error).stack,
        });

        await db.update(scanRequests)
          .set({
            status: 'failed',
            error: (err as Error).message,
            completed_at: new Date(),
            updated_at: new Date(),
          })
          .where(eq(scanRequests.id, scan_id));

        throw err;
      } finally {
        // Clean up working directory
        if (ctx.sourcePath) {
          try {
            await rm(ctx.sourcePath, { recursive: true, force: true });
          } catch { /* best effort */ }
        }
      }
    },
    {
      connection,
      concurrency: config.scanners.concurrency,
    },
  );

  worker.on('completed', (job) => {
    logger.info('Scan pipeline job completed', { job_id: job.id });
  });

  worker.on('failed', (job, err) => {
    logger.error('Scan pipeline job failed', { job_id: job?.id, error: err.message });
  });

  return worker;
}
