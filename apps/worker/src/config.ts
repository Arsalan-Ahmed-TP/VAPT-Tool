// ---------------------------------------------------------------------------
// Worker configuration
// ---------------------------------------------------------------------------

import 'dotenv/config';

function optional(key: string, fallback: string): string {
  return process.env[key] || fallback;
}

export const config = {
  env: optional('NODE_ENV', 'development'),

  db: {
    host: optional('DB_HOST', 'localhost'),
    port: parseInt(optional('DB_PORT', '5432'), 10),
    name: optional('DB_NAME', 'securescope'),
    user: optional('DB_USER', 'securescope'),
    password: optional('DB_PASSWORD', 'securescope'),
    get connectionString() {
      return `postgresql://${config.db.user}:${config.db.password}@${config.db.host}:${config.db.port}/${config.db.name}`;
    },
  },

  redis: {
    host: optional('REDIS_HOST', 'localhost'),
    port: parseInt(optional('REDIS_PORT', '6379'), 10),
    password: process.env['REDIS_PASSWORD'] || undefined,
  },

  scanners: {
    defaultTimeoutMs: parseInt(optional('SCANNER_DEFAULT_TIMEOUT_MS', '300000'), 10),
    maxRetries: parseInt(optional('SCANNER_MAX_RETRIES', '2'), 10),
    artifactDir: optional('SCANNER_ARTIFACT_DIR', './scan-artifacts'),
    workDir: optional('SCANNER_WORK_DIR', './scanner-workdir'),
    concurrency: parseInt(optional('SCANNER_CONCURRENCY', '3'), 10),
  },

  security: {
    credentialEncryptionKey: optional('CREDENTIAL_ENCRYPTION_KEY', 'change-me-in-production-32char!'),
  },

  logging: {
    level: optional('LOG_LEVEL', 'info'),
  },
} as const;
