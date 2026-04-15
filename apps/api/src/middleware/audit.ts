// ---------------------------------------------------------------------------
// Audit logging middleware and utility
// ---------------------------------------------------------------------------

import { randomUUID } from 'node:crypto';
import { db, schema } from '../db/index.js';
import { logger } from '../logger.js';
import type { AuditAction } from '@securescope/shared-types';

export interface AuditEntry {
  action: AuditAction;
  actor: string;
  target_type: string;
  target_id: string;
  details?: Record<string, unknown>;
  ip_address?: string;
}

export async function recordAuditEvent(entry: AuditEntry): Promise<void> {
  try {
    await db.insert(schema.auditEvents).values({
      id: randomUUID(),
      action: entry.action,
      actor: entry.actor,
      target_type: entry.target_type,
      target_id: entry.target_id,
      details: entry.details || {},
      ip_address: entry.ip_address,
      timestamp: new Date(),
    });
  } catch (err) {
    // Audit logging should never break the main flow
    logger.error('Failed to record audit event', {
      error: (err as Error).message,
      action: entry.action,
    });
  }
}
