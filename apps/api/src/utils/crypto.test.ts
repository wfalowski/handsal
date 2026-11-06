import { CLIENT_ID_REGEX } from "@handsal/shared";
import { describe, expect, it } from "vitest";
import {
  decryptPrivateKey,
  deriveKey,
  encryptPrivateKey,
  generateClientId,
  generateClientSecret,
  hashSecret,
  ServiceOverloadError,
  verifySecret,
} from "./crypto.js";

const TEST_KEY_HEX = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER_KEY_HEX = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const PEM = "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----\n";

describe("hashSecret / verifySecret", () => {
  it("hashes with argon2id and verifies", async () => {
    const hash = await hashSecret("correct-secret");
    expect(hash).toMatch(/^\$argon2id\$/);
    expect(await verifySecret("correct-secret", hash)).toBe(true);
    expect(await verifySecret("wrong-secret", hash)).toBe(false);
  });

  it("returns false (not throw) for a corrupted hash", async () => {
    expect(await verifySecret("any-secret", "not-a-valid-hash")).toBe(false);
  });

  it("sheds load with ServiceOverloadError beyond the concurrency ceiling", async () => {
    const results = await Promise.allSettled(
      Array.from({ length: 15 }, () => verifySecret("pw", "not-a-valid-hash")),
    );
    const rejected = results.filter((r) => r.status === "rejected");
    expect(rejected).toHaveLength(5);
    for (const r of rejected) {
      expect((r as PromiseRejectedResult).reason).toBeInstanceOf(ServiceOverloadError);
    }
  });
});

describe("generateClientId / generateClientSecret", () => {
  it("client id is app_ + 20 base32 chars", () => {
    for (let i = 0; i < 50; i++) expect(generateClientId()).toMatch(CLIENT_ID_REGEX);
  });

  it("client secret is hs_ + 48 base62 chars and unique", () => {
    const a = generateClientSecret();
    expect(a).toMatch(/^hs_[0-9A-Za-z]{48}$/);
    expect(generateClientSecret()).not.toBe(a);
  });
});

describe("deriveKey", () => {
  it("is deterministic per purpose and independent across purposes", () => {
    const a = deriveKey(TEST_KEY_HEX, "signing-key");
    expect(a).toHaveLength(32);
    expect(deriveKey(TEST_KEY_HEX, "signing-key").equals(a)).toBe(true);
    expect(deriveKey(TEST_KEY_HEX, "session").equals(a)).toBe(false);
  });
});

describe("encryptPrivateKey / decryptPrivateKey", () => {
  it("roundtrips with format iv.tag.ciphertext", () => {
    const enc = encryptPrivateKey(PEM, TEST_KEY_HEX);
    expect(enc.split(".")).toHaveLength(3);
    expect(enc).not.toContain("PRIVATE KEY");
    expect(decryptPrivateKey(enc, TEST_KEY_HEX)).toBe(PEM);
  });

  it("uses a fresh IV per call", () => {
    expect(encryptPrivateKey(PEM, TEST_KEY_HEX)).not.toBe(encryptPrivateKey(PEM, TEST_KEY_HEX));
  });

  it("throws on tampered ciphertext", () => {
    const [iv, tag, ct] = encryptPrivateKey(PEM, TEST_KEY_HEX).split(".");
    const bytes = Buffer.from(ct, "base64");
    bytes[0] ^= 1;
    const tampered = `${iv}.${tag}.${bytes.toString("base64")}`;
    expect(() => decryptPrivateKey(tampered, TEST_KEY_HEX)).toThrow();
  });

  it("throws on a tampered or truncated tag", () => {
    const [iv, tag, ct] = encryptPrivateKey(PEM, TEST_KEY_HEX).split(".");
    const bytes = Buffer.from(tag, "base64");
    bytes[0] ^= 1;
    expect(() =>
      decryptPrivateKey(`${iv}.${bytes.toString("base64")}.${ct}`, TEST_KEY_HEX),
    ).toThrow();
    const short = Buffer.from(tag, "base64").subarray(0, 4).toString("base64");
    expect(() => decryptPrivateKey(`${iv}.${short}.${ct}`, TEST_KEY_HEX)).toThrow();
  });

  it("throws with the wrong master key or a malformed value", () => {
    const enc = encryptPrivateKey(PEM, TEST_KEY_HEX);
    expect(() => decryptPrivateKey(enc, OTHER_KEY_HEX)).toThrow();
    expect(() => decryptPrivateKey("not-encrypted", TEST_KEY_HEX)).toThrow();
  });
});
