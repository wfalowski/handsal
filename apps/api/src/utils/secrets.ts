// MERGE-NOTE: fold into utils/crypto.ts (Task 2.1)
import { randomInt } from "node:crypto";
import argon2 from "argon2";

const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
const BASE62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

function randomString(alphabet: string, length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += alphabet[randomInt(alphabet.length)];
  return out;
}

/** `app_` + 20 lowercase base32 chars (matches CLIENT_ID_REGEX). */
export function generateClientId(): string {
  return `app_${randomString(BASE32, 20)}`;
}

/** `hs_` + 48 base62 chars (~285 bits). */
export function generateClientSecret(): string {
  return `hs_${randomString(BASE62, 48)}`;
}

// shortcut: no in-flight cap / ServiceOverloadError here; Task 2.1's crypto.ts has it and replaces this file.
export async function hashSecret(secret: string): Promise<string> {
  return argon2.hash(secret, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4,
  });
}

export async function verifySecret(secret: string, hash: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, secret);
  } catch {
    // Malformed hash — treat as auth failure.
    return false;
  }
}
