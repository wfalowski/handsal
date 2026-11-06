import { createPublicKey } from "crypto";
import { exportJWK, generateKeyPair, importPKCS8, type JSONWebKeySet, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import { decodeHeader, signAccessToken, verifyAccessToken } from "./jwt.js";
import { generateEs256KeyPair } from "./key-management.js";

const ISSUER = "https://test.example.com/t/acme";
const AUDIENCE = "https://api.acme.io/payments";
const KID = "k_2026-01-01_abcd";

let privateKeyPem: string;
let jwks: JSONWebKeySet;

function claims(over: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, sub: "app_x", aud: AUDIENCE, iat: now, exp: now + 300, jti: "j1", ...over };
}

beforeAll(async () => {
  const pair = generateEs256KeyPair();
  privateKeyPem = pair.privateKeyPem;
  const jwk = await exportJWK(createPublicKey(pair.publicKeyPem));
  jwks = { keys: [{ ...jwk, kid: KID, use: "sig", alg: "ES256" }] };
});

describe("signAccessToken / verifyAccessToken", () => {
  it("roundtrips with ES256 / at+jwt header and claims as given", async () => {
    const token = await signAccessToken(privateKeyPem, KID, claims({ scope: "a b" }));
    expect(decodeHeader(token)).toEqual({ kid: KID, alg: "ES256" });
    const payload = await verifyAccessToken(token, jwks, { issuer: ISSUER, audience: AUDIENCE });
    expect(payload).toMatchObject({ iss: ISSUER, sub: "app_x", aud: AUDIENCE, scope: "a b" });
  });

  it("rejects a wrong issuer", async () => {
    const token = await signAccessToken(privateKeyPem, KID, claims());
    await expect(verifyAccessToken(token, jwks, { issuer: "https://evil" })).rejects.toThrow();
  });

  it("rejects a wrong audience", async () => {
    const token = await signAccessToken(privateKeyPem, KID, claims());
    await expect(
      verifyAccessToken(token, jwks, { issuer: ISSUER, audience: "https://other" }),
    ).rejects.toThrow();
  });

  it("rejects an expired token", async () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    const token = await signAccessToken(privateKeyPem, KID, claims({ iat: past, exp: past + 60 }));
    await expect(verifyAccessToken(token, jwks, { issuer: ISSUER })).rejects.toThrow(/exp/);
  });

  it("rejects an RS256 token even when its kid is in the JWKS", async () => {
    const rsa = await generateKeyPair("RS256");
    const rsaJwk = await exportJWK(rsa.publicKey);
    const mixed: JSONWebKeySet = { keys: [...jwks.keys, { ...rsaJwk, kid: "rsa", alg: "RS256" }] };
    for (const kid of [KID, "rsa"]) {
      const token = await new SignJWT(claims())
        .setProtectedHeader({ alg: "RS256", kid, typ: "at+jwt" })
        .sign(rsa.privateKey);
      await expect(verifyAccessToken(token, mixed, { issuer: ISSUER })).rejects.toThrow();
    }
  });

  it("rejects a token without typ at+jwt", async () => {
    const key = await importPKCS8(privateKeyPem, "ES256");
    const token = await new SignJWT(claims())
      .setProtectedHeader({ alg: "ES256", kid: KID })
      .sign(key);
    await expect(verifyAccessToken(token, jwks, { issuer: ISSUER })).rejects.toThrow();
  });

  it("rejects a token signed by a key not in the JWKS", async () => {
    const other = generateEs256KeyPair();
    const token = await signAccessToken(other.privateKeyPem, KID, claims());
    await expect(verifyAccessToken(token, jwks, { issuer: ISSUER })).rejects.toThrow();
  });
});

describe("decodeHeader", () => {
  it("returns {} for garbage", () => {
    expect(decodeHeader("not-a-jwt")).toEqual({});
  });
});
