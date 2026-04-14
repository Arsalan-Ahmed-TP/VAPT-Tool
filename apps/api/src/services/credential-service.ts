// ---------------------------------------------------------------------------
// Credential management — encrypts at rest, never exposes raw values
// ---------------------------------------------------------------------------

import { eq } from 'drizzle-orm';
import { db, schema } from '../db/index.js';
import { encryptCredential } from '../utils/crypto.js';
import { recordAuditEvent } from '../middleware/audit.js';
import { AuditAction } from '@securescope/shared-types';
import type { CreateCredentialRequest, CredentialResponse } from '@securescope/shared-types';

export async function createCredential(data: CreateCredentialRequest, actor: string): Promise<CredentialResponse> {
  const encrypted = encryptCredential(data.value);

  const [cred] = await db.insert(schema.credentialProfiles).values({
    name: data.name,
    type: data.type,
    encrypted_value: encrypted,
    config: data.config || {},
  }).returning();

  await recordAuditEvent({
    action: AuditAction.CredentialCreated,
    actor,
    target_type: 'credential',
    target_id: cred.id,
    details: { type: data.type, name: data.name },
  });

  // Never return the encrypted value
  const { encrypted_value, ...safe } = cred;
  return safe as CredentialResponse;
}

export async function getCredential(id: string): Promise<CredentialResponse | null> {
  const [cred] = await db.select().from(schema.credentialProfiles).where(eq(schema.credentialProfiles.id, id));
  if (!cred) return null;
  const { encrypted_value, ...safe } = cred;
  return safe as CredentialResponse;
}

export async function listCredentials(): Promise<CredentialResponse[]> {
  const creds = await db.select({
    id: schema.credentialProfiles.id,
    name: schema.credentialProfiles.name,
    type: schema.credentialProfiles.type,
    config: schema.credentialProfiles.config,
    last_used_at: schema.credentialProfiles.last_used_at,
    created_at: schema.credentialProfiles.created_at,
    updated_at: schema.credentialProfiles.updated_at,
  }).from(schema.credentialProfiles);
  return creds as CredentialResponse[];
}

export async function deleteCredential(id: string): Promise<boolean> {
  const result = await db.delete(schema.credentialProfiles).where(eq(schema.credentialProfiles.id, id));
  return true;
}
