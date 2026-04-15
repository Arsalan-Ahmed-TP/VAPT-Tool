// ---------------------------------------------------------------------------
// SecureScope Worker — processes scan pipelines and background jobs
// ---------------------------------------------------------------------------

import 'dotenv/config';
import winston from 'winston';
import { config } from './config.js';
import { createScanPipelineWorker } from './processors/scan-pipeline-processor.js';

const logger = winston.createLogger({
  level: config.logging.level,
  format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
  defaultMeta: { service: 'securescope-worker' },
  transports: [new winston.transports.Console()],
});

async function main() {
  logger.info('Starting SecureScope Worker', {
    env: config.env,
    concurrency: config.scanners.concurrency,
  });

  // Start the scan pipeline worker
  const pipelineWorker = createScanPipelineWorker();

  logger.info('Scan pipeline worker started');

  // Graceful shutdown
  const shutdown = async () => {
    logger.info('Shutting down workers...');
    await pipelineWorker.close();
    logger.info('Workers shut down');
    process.exit(0);
  };

  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((err) => {
  logger.error('Worker startup failed', { error: err.message });
  process.exit(1);
});
