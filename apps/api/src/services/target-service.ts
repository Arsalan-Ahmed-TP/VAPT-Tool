// ---------------------------------------------------------------------------
// Target management service
// ---------------------------------------------------------------------------

import { eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { recordAuditEvent } from '../middleware/audit.js';
import { AuditAction } from '@securescope/shared-types';
import type { CreateTargetRequest } from '@securescope/shared-types';

export async function createTarget(data: CreateTargetRequest, actor: string) {
  if (!data.authorization_confirmed) {
    throw new Error('Authorization confirmation is required before scanning any target');
  }

  const [target] = await db.insert(schema.scanTargets).values({
    name: data.name,
    source_type: data.source_type,
    location: data.location,
    ref: data.ref,
    environment: data.environment,
    credential_id: data.credential_id,
    exclusions: data.exclusions || [],
    authorization_confirmed: data.authorization_confirmed,
    metadata: data.metadata || {},
  }).returning();

  await recordAuditEvent({
    action: AuditAction.ScanCreated,
    actor,
    target_type: 'scan_target',
    target_id: target.id,
    details: { source_type: data.source_type, environment: data.environment },
  });

  return target;
}

export async function getTarget(id: string) {
  const [target] = await db.select().from(schema.scanTargets).where(eq(schema.scanTargets.id, id));
  return target || null;
}

export async function listTargets(page = 1, pageSize = 20) {
  const offset = (page - 1) * pageSize;
  const targets = await db.select().from(schema.scanTargets).limit(pageSize).offset(offset);
  return targets;
}
