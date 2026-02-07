/**
 * Encryption utilities for secrets at rest (AES-256-GCM).
 *
 * Used to encrypt community app passwords and API keys before
 * storing them in Postgres, and decrypt them when needed for PDS login.
 *
 * Requires ENCRYPTION_KEY env var — a 64-char hex string (32 bytes).
 * Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 */

import crypto from 'crypto';
import { config } from '../config';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // GCM recommended
const AUTH_TAG_LENGTH = 16;

/**
 * Derive the 32-byte key from the hex config value.
 * Throws at startup if ENCRYPTION_KEY is missing or malformed.
 */
function getKey(): Buffer {
  const hex = config.encryptionKey;
  if (!hex || hex.length !== 64) {
    throw new Error(
      'ENCRYPTION_KEY must be a 64-character hex string (32 bytes). ' +
      'Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Encrypt a plaintext string.
 * Returns a base64 string of: iv (12 B) + authTag (16 B) + ciphertext.
 */
export function encrypt(plaintext: string): string {
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // Pack: iv + authTag + ciphertext
  const packed = Buffer.concat([iv, authTag, encrypted]);
  return packed.toString('base64');
}

/**
 * Decrypt a value produced by encrypt().
 * Returns the original plaintext string.
 */
export function decrypt(encoded: string): string {
  const key = getKey();
  const packed = Buffer.from(encoded, 'base64');

  const iv = packed.subarray(0, IV_LENGTH);
  const authTag = packed.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
  const ciphertext = packed.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}

/**
 * Check whether a string looks like it was encrypted by us.
 * Encrypted values are base64 and at least iv+authTag bytes long.
 * Plain-text hex passwords (64 chars) will NOT match this pattern.
 */
export function isEncrypted(value: string): boolean {
  // Our encrypted output is base64. A 64-char hex password won't decode
  // to a buffer that has the right minimum length (12+16 = 28 bytes).
  try {
    const buf = Buffer.from(value, 'base64');
    // Must have at least IV + authTag + 1 byte of ciphertext
    if (buf.length < IV_LENGTH + AUTH_TAG_LENGTH + 1) return false;
    // If re-encoding to base64 gives back the same string, it's valid base64
    return buf.toString('base64') === value;
  } catch {
    return false;
  }
}

/**
 * Safely decrypt a value that might still be in plaintext (migration helper).
 * If the value doesn't look like an encrypted blob, returns it as-is.
 */
export function decryptIfNeeded(value: string): string {
  if (isEncrypted(value)) {
    return decrypt(value);
  }
  return value;
}

/**
 * Hash an API key for storage. Uses SHA-256 — one-way, so the original
 * key cannot be recovered. The key is shown to the user once at creation
 * and then only the hash is stored.
 */
export function hashApiKey(apiKey: string): string {
  return crypto.createHash('sha256').update(apiKey).digest('hex');
}

/**
 * Compare a raw API key against a stored hash.
 */
export function verifyApiKey(rawKey: string, storedHash: string): boolean {
  const hash = hashApiKey(rawKey);
  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(storedHash));
}
