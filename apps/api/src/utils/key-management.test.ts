import { createPrivateKey, createPublicKey, sign, verify } from "crypto";
import { describe, expect, it } from "vitest";
import { generateEs256KeyPair, makeKid } from "./key-management.js";

describe("generateEs256KeyPair", () => {
  it("returns a matching P-256 PEM pair", () => {
    const { publicKeyPem, privateKeyPem } = generateEs256KeyPair();
    expect(publicKeyPem).toContain("BEGIN PUBLIC KEY");
    expect(privateKeyPem).toContain("BEGIN PRIVATE KEY");
    const pub = createPublicKey(publicKeyPem);
    expect(pub.asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
    const sig = sign("sha256", Buffer.from("x"), createPrivateKey(privateKeyPem));
    expect(verify("sha256", Buffer.from("x"), pub, sig)).toBe(true);
  });
});

describe("makeKid", () => {
  it("formats k_YYYY-MM-DD_xxxx from the UTC date", () => {
    expect(makeKid(new Date("2026-03-04T23:59:59Z"))).toMatch(/^k_2026-03-04_[0-9a-f]{4}$/);
  });

  it("defaults to today", () => {
    const today = new Date().toISOString().slice(0, 10);
    expect(makeKid()).toMatch(new RegExp(`^k_${today}_[0-9a-f]{4}$`));
  });
});
