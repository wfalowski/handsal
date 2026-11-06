import argon2 from "argon2";
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "crypto";

/** Thrown when too many password hashes are in flight; mapped to HTTP 503. */
export class ServiceOverloadError extends Error {
  constructor(message = "Service temporarily overloaded") {
    super(message);
    this.name = "ServiceOverloadError";
  }
}

// argon2id at 64 MiB / t=3 / p=4 is deliberately expensive. Every token,
// introspect and revoke request runs a verify (including a dummy verify for
// unknown/malformed clients, to stay timing-safe), so an unauthenticated flood
// can saturate CPU and the libuv threadpool. Cap concurrent verifications and
// shed load beyond the ceiling instead of queueing unbounded work.
const MAX_INFLIGHT_HASH_OPS = 10;
let inflightHashOps = 0;

export async function hashSecret(secret: string): Promise<string> {
  if (inflightHashOps >= MAX_INFLIGHT_HASH_OPS) {
    throw new ServiceOverloadError();
  }
  inflightHashOps++;
  try {
    return await argon2.hash(secret, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 4,
    });
  } finally {
    inflightHashOps--;
  }
}

export async function verifySecret(secret: string, hash: string): Promise<boolean> {
  if (inflightHashOps >= MAX_INFLIGHT_HASH_OPS) {
    throw new ServiceOverloadError();
  }
  inflightHashOps++;
  try {
    return await argon2.verify(hash, secret);
  } catch {
    // A malformed hash or mismatch — not an overload; treat as auth failure.
    return false;
  } finally {
    inflightHashOps--;
  }
}

const BASE32_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";
const BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/** Uniformly random string over `alphabet` (rejection sampling, no modulo bias). */
function randomString(alphabet: string, length: number): string {
  const limit = 256 - (256 % alphabet.length);
  let out = "";
  while (out.length < length) {
    for (const byte of randomBytes(length * 2)) {
      if (byte < limit) out += alphabet[byte % alphabet.length];
      if (out.length === length) break;
    }
  }
  return out;
}

/** `app_` + 20 lowercase base32 chars (100 bits). */
export function generateClientId(): string {
  return `app_${randomString(BASE32_ALPHABET, 20)}`;
}

/** `hs_` + 48 base62 chars (~285 bits). Shown once, stored Argon2id-hashed. */
export function generateClientSecret(): string {
  return `hs_${randomString(BASE62_ALPHABET, 48)}`;
}

/**
 * Derive a purpose-specific key from the master encryption key using HKDF.
 * Each unique `purpose` string produces a cryptographically independent key.
 */
export function deriveKey(masterKeyHex: string, purpose: string, lengthBytes = 32): Buffer {
  return Buffer.from(
    hkdfSync("sha256", Buffer.from(masterKeyHex, "hex"), "", purpose, lengthBytes),
  );
}

const SIGNING_KEY_PURPOSE = "signing-key";

/** AES-256-GCM encrypt a PEM; output `base64(iv).base64(tag).base64(ciphertext)`. */
export function encryptPrivateKey(pem: string, masterKeyHex: string): string {
  const key = deriveKey(masterKeyHex, SIGNING_KEY_PURPOSE);
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(pem, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [iv, authTag, encrypted].map((b) => b.toString("base64")).join(".");
}

/** Inverse of {@link encryptPrivateKey}; throws on malformed or tampered input. */
export function decryptPrivateKey(encrypted: string, masterKeyHex: string): string {
  const parts = encrypted.split(".");
  if (parts.length !== 3) {
    throw new Error("Malformed encrypted private key");
  }
  const [iv, authTag, ciphertext] = parts.map((p) => Buffer.from(p, "base64"));
  const key = deriveKey(masterKeyHex, SIGNING_KEY_PURPOSE);
  // Pin the tag length: GCM would otherwise accept truncated tags.
  const decipher = createDecipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
  decipher.setAuthTag(authTag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
}
