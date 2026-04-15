// ---------------------------------------------------------------------------
// Centralized configuration — all from environment variables
// ---------------------------------------------------------------------------

import 'dotenv/config';

function required(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`Missing required environment variable: ${key}`);
  return value;
}

function optional(key: string, fallback: string): string {
  return process.env[key] || fallback;
}

export const config = {
  env: optional('NODE_ENV', 'development'),
  port: parseInt(optional('PORT', '4000'), 10),

  // PostgreSQL
  db: {
    host: optional('DB_HOST', 'localhost'),
    port: parseInt(optional('DB_PORT', '5432'), 10),
    name: optional('DB_NAME', 'securescope'),
    user: optional('DB_USER', 'securescope'),
    password: optional('DB_PASSWORD', 'securescope'),
    ssl: optional('DB_SSL', 'false') === 'true',
    get connectionString() {
      return `postgresql://${config.db.user}:${config.db.password}@${config.db.host}:${config.db.port}/${config.db.name}`;
    },
  },

  // Redis
  redis: {
    host: optional('REDIS_HOST', 'localhost'),
    port: parseInt(optional('REDIS_PORT', '6379'), 10),
    password: process.env['REDIS_PASSWORD'] || undefined,
  },

  // Storage
  storage: {
    type: optional('STORAGE_TYPE', 'local') as 'local' | 's3',
    localPath: optional('STORAGE_LOCAL_PATH', './storage'),
    s3Bucket: process.env['S3_BUCKET'],
    s3Region: process.env['S3_REGION'],
  },

  // Security
  security: {
    credentialEncryptionKey: optional('CREDENTIAL_ENCRYPTION_KEY', 'change-me-in-production-32char!'),
    corsOrigins: optional('CORS_ORIGINS', 'http://localhost:3000').split(','),
    rateLimitWindowMs: parseInt(optional('RATE_LIMIT_WINDOW_MS', '60000'), 10),
    rateLimitMax: parseInt(optional('RATE_LIMIT_MAX', '100'), 10),
  },

  // Scanner defaults
  scanners: {
    defaultTimeoutMs: parseInt(optional('SCANNER_DEFAULT_TIMEOUT_MS', '300000'), 10),
    maxRetries: parseInt(optional('SCANNER_MAX_RETRIES', '2'), 10),
    artifactDir: optional('SCANNER_ARTIFACT_DIR', './scan-artifacts'),
    workDir: optional('SCANNER_WORK_DIR', './scanner-workdir'),
  },

  // Logging
  logging: {
    level: optional('LOG_LEVEL', 'info'),
  },
} as const;
