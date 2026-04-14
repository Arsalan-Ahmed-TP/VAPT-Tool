// ---------------------------------------------------------------------------
// Credential encryption/decryption utilities
// Uses AES-256-GCM for authenticated encryption
// ---------------------------------------------------------------------------

import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { config } from '../config.js';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;

function deriveKey(salt: Buffer): Buffer {
  return scryptSync(config.security.credentialEncryptionKey, salt, KEY_LENGTH);
}

/** Encrypt a credential value. Returns base64-encoded ciphertext with embedded salt, IV, and auth tag. */
export function encryptCredential(plaintext: string): string {
  const salt = randomBytes(SALT_LENGTH);
  const key = deriveKey(salt);
  const iv = randomBytes(IV_LENGTH);

  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Format: salt(32) + iv(16) + tag(16) + ciphertext
  const result = Buffer.concat([salt, iv, tag, encrypted]);
  return result.toString('base64');
}

/** Decrypt a credential value. Throws on tampered data. */
export function decryptCredential(encoded: string): string {
  const data = Buffer.from(encoded, 'base64');

  const salt = data.subarray(0, SALT_LENGTH);
  const iv = data.subarray(SALT_LENGTH, SALT_LENGTH + IV_LENGTH);
  const tag = data.subarray(SALT_LENGTH + IV_LENGTH, SALT_LENGTH + IV_LENGTH + TAG_LENGTH);
  const ciphertext = data.subarray(SALT_LENGTH + IV_LENGTH + TAG_LENGTH);

  const key = deriveKey(salt);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  return decipher.update(ciphertext) + decipher.final('utf8');
}
