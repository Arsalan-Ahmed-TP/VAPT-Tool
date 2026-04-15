// ---------------------------------------------------------------------------
// Structured logger — masks sensitive values
// ---------------------------------------------------------------------------

import winston from 'winston';
import { config } from './config.js';

const sensitiveKeys = /password|secret|token|key|authorization|cookie|credential/i;

/** Recursively mask sensitive values in log metadata */
function maskSensitive(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') return obj;
  if (Array.isArray(obj)) return obj.map(maskSensitive);
  if (typeof obj === 'object') {
    const masked: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      if (sensitiveKeys.test(key) && typeof value === 'string') {
        masked[key] = '[REDACTED]';
      } else {
        masked[key] = maskSensitive(value);
      }
    }
    return masked;
  }
  return obj;
}

const maskFormat = winston.format((info) => {
  if (info.metadata) {
    info.metadata = maskSensitive(info.metadata);
  }
  return info;
});

export const logger = winston.createLogger({
  level: config.logging.level,
  format: winston.format.combine(
    winston.format.timestamp(),
    maskFormat(),
    winston.format.errors({ stack: true }),
    config.env === 'production'
      ? winston.format.json()
      : winston.format.combine(winston.format.colorize(), winston.format.simple()),
  ),
  defaultMeta: { service: 'securescope-api' },
  transports: [new winston.transports.Console()],
});
