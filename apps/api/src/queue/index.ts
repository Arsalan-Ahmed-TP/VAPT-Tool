// ---------------------------------------------------------------------------
// BullMQ queue definitions for scan orchestration
// ---------------------------------------------------------------------------

import { Queue } from 'bullmq';
import IORedis from 'ioredis';
import { config } from '../config.js';
import { logger } from '../logger.js';

export const redisConnection = new IORedis({
  host: config.redis.host,
  port: config.redis.port,
  password: config.redis.password,
  maxRetriesPerRequest: null, // Required by BullMQ
  enableReadyCheck: false,
});

redisConnection.on('error', (err) => {
  logger.error('Redis connection error', { error: err.message });
});

// Queue for orchestrating entire scan pipelines
export const scanPipelineQueue = new Queue('scan-pipeline', {
  connection: redisConnection,
  defaultJobOptions: {
    removeOnComplete: { count: 100 },
    removeOnFail: { count: 50 },
    attempts: 1, // Pipeline-level retries handled by orchestrator
  },
});

// Queue for individual scanner job execution
export const scannerJobQueue = new Queue('scanner-jobs', {
  connection: redisConnection,
  defaultJobOptions: {
    removeOnComplete: { count: 500 },
    removeOnFail: { count: 200 },
    attempts: 3,
    backoff: {
      type: 'exponential',
      delay: 5000,
    },
  },
});

// Queue for report generation
export const reportQueue = new Queue('report-generation', {
  connection: redisConnection,
  defaultJobOptions: {
    removeOnComplete: { count: 100 },
    removeOnFail: { count: 50 },
    attempts: 2,
  },
});

// Queue for remediation application
export const remediationQueue = new Queue('remediation', {
  connection: redisConnection,
  defaultJobOptions: {
    removeOnComplete: { count: 100 },
    removeOnFail: { count: 50 },
    attempts: 1, // Remediation should not auto-retry
  },
});

export async function checkRedisConnection(): Promise<boolean> {
  try {
    await redisConnection.ping();
    return true;
  } catch {
    return false;
  }
}
