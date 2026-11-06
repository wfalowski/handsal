import { describe, expect, it } from "vitest";
import { CLIENT_ID_REGEX, DEFAULTS } from "../constants/index.js";
import {
  applicationCreateSchema,
  applicationUpdateSchema,
  grantsReplaceSchema,
  introspectRequestSchema,
  loginSchema,
  memberCreateSchema,
  memberUpdateSchema,
  resourceCreateSchema,
  rotateSecretSchema,
  scopeCreateSchema,
  tenantCreateSchema,
  tenantUpdateSchema,
  tokenEventsQuerySchema,
  tokenRequestSchema,
  tokenStatsDtoSchema,
} from "./index.js";

const ok = (s: { safeParse: (v: unknown) => { success: boolean } }, v: unknown) =>
  s.safeParse(v).success;

describe("tenant", () => {
  it("accepts valid create", () => {
    expect(ok(tenantCreateSchema, { name: "Acme", slug: "acme-1" })).toBe(true);
  });
  it.each(["Acme", "-a", "a-", "a_b", ""])("rejects bad slug %j", (slug) => {
    expect(ok(tenantCreateSchema, { name: "Acme", slug })).toBe(false);
  });
  it("rejects empty name", () => {
    expect(ok(tenantCreateSchema, { name: "", slug: "acme" })).toBe(false);
  });
  it("update: TTL bounds and nullable rotation", () => {
    expect(ok(tenantUpdateSchema, { defaultTokenTtlSeconds: 60, keyRotationDays: null })).toBe(
      true,
    );
    expect(ok(tenantUpdateSchema, { defaultTokenTtlSeconds: 59 })).toBe(false);
    expect(ok(tenantUpdateSchema, { defaultTokenTtlSeconds: 86401 })).toBe(false);
  });
});

describe("application", () => {
  it("accepts valid create", () => {
    expect(
      ok(applicationCreateSchema, {
        name: "billing",
        tokenEndpointAuthMethod: "client_secret_post",
        tokenTtlSeconds: 3600,
      }),
    ).toBe(true);
  });
  it("rejects TTL 59 and 86401", () => {
    expect(ok(applicationCreateSchema, { name: "a", tokenTtlSeconds: 59 })).toBe(false);
    expect(ok(applicationCreateSchema, { name: "a", tokenTtlSeconds: 86401 })).toBe(false);
    expect(ok(applicationUpdateSchema, { tokenTtlSeconds: 59 })).toBe(false);
  });
  it("refuses private_key_jwt with message", () => {
    const r = applicationCreateSchema.safeParse({
      name: "a",
      tokenEndpointAuthMethod: "private_key_jwt",
    });
    expect(r.success).toBe(false);
    expect(JSON.stringify(r.error?.issues)).toContain("private_key_jwt is not available yet");
    expect(ok(applicationUpdateSchema, { tokenEndpointAuthMethod: "private_key_jwt" })).toBe(false);
  });
  it("rejects unknown auth method", () => {
    expect(ok(applicationCreateSchema, { name: "a", tokenEndpointAuthMethod: "none" })).toBe(false);
  });
  it("rotateSecret defaults grace and bounds it", () => {
    expect(rotateSecretSchema.parse({}).graceSeconds).toBe(DEFAULTS.SECRET_GRACE_SECONDS);
    expect(ok(rotateSecretSchema, { graceSeconds: 604801 })).toBe(false);
    expect(ok(rotateSecretSchema, { graceSeconds: -1 })).toBe(false);
  });
  it("grants: uuid[] max 500", () => {
    const ids = (n: number) => Array.from({ length: n }, () => crypto.randomUUID());
    expect(ok(grantsReplaceSchema, { scopeIds: ids(500) })).toBe(true);
    expect(ok(grantsReplaceSchema, { scopeIds: ids(501) })).toBe(false);
    expect(ok(grantsReplaceSchema, { scopeIds: ["nope"] })).toBe(false);
  });
  it("CLIENT_ID_REGEX", () => {
    expect(CLIENT_ID_REGEX.test("app_abcdefghijklmnopqrst")).toBe(true);
    expect(CLIENT_ID_REGEX.test("app_ABCDEFGHIJKLMNOPQRST")).toBe(false);
  });
});

describe("resource", () => {
  it("accepts URL and URN audiences", () => {
    expect(ok(resourceCreateSchema, { name: "api", audience: "https://api.example.com" })).toBe(
      true,
    );
    expect(ok(resourceCreateSchema, { name: "api", audience: "urn:example:api" })).toBe(true);
  });
  it("rejects bad audience, bad kind, >512", () => {
    expect(ok(resourceCreateSchema, { name: "api", audience: "not a url" })).toBe(false);
    expect(ok(resourceCreateSchema, { name: "api", audience: "https://a.io", kind: "x" })).toBe(
      false,
    );
    expect(
      ok(resourceCreateSchema, { name: "api", audience: `https://a.io/${"a".repeat(512)}` }),
    ).toBe(false);
  });
});

describe("scope", () => {
  it("accepts valid name", () => {
    expect(ok(scopeCreateSchema, { name: "read:users.v1" })).toBe(true);
  });
  it("rejects name with space, leading symbol, long description", () => {
    expect(ok(scopeCreateSchema, { name: "read users" })).toBe(false);
    expect(ok(scopeCreateSchema, { name: ":read" })).toBe(false);
    expect(ok(scopeCreateSchema, { name: "a", description: "x".repeat(1001) })).toBe(false);
  });
});

describe("member + auth", () => {
  it("member create/update", () => {
    expect(ok(memberCreateSchema, { email: "a@b.co", role: "auditor" })).toBe(true);
    expect(ok(memberCreateSchema, { email: "nope", role: "auditor" })).toBe(false);
    expect(ok(memberCreateSchema, { email: "a@b.co", role: "root" })).toBe(false);
    expect(ok(memberUpdateSchema, { role: "owner" })).toBe(true);
  });
  it("login password 8..256", () => {
    expect(ok(loginSchema, { email: "a@b.co", password: "12345678" })).toBe(true);
    expect(ok(loginSchema, { email: "a@b.co", password: "1234567" })).toBe(false);
    expect(ok(loginSchema, { email: "a@b.co", password: "x".repeat(257) })).toBe(false);
  });
});

describe("oauth requests", () => {
  it("token request requires grant_type and resource", () => {
    expect(
      ok(tokenRequestSchema, { grant_type: "client_credentials", resource: "https://api" }),
    ).toBe(true);
    expect(ok(tokenRequestSchema, { grant_type: "password", resource: "x" })).toBe(true);
    expect(ok(tokenRequestSchema, { grant_type: "client_credentials" })).toBe(false);
    expect(ok(tokenRequestSchema, { resource: "x" })).toBe(false);
    expect(ok(tokenRequestSchema, { grant_type: "client_credentials", resource: "" })).toBe(false);
  });
  it("introspect requires token", () => {
    expect(ok(introspectRequestSchema, { token: "t", token_type_hint: "access_token" })).toBe(true);
    expect(ok(introspectRequestSchema, {})).toBe(false);
  });
});

describe("token events", () => {
  it("query defaults and coerces limit", () => {
    expect(tokenEventsQuerySchema.parse({}).limit).toBe(50);
    expect(tokenEventsQuerySchema.parse({ limit: "200" }).limit).toBe(200);
    expect(ok(tokenEventsQuerySchema, { limit: "201" })).toBe(false);
    expect(ok(tokenEventsQuerySchema, { limit: "0" })).toBe(false);
    expect(ok(tokenEventsQuerySchema, { outcome: "bogus" })).toBe(false);
  });
  it("stats are non-negative ints", () => {
    const s = {
      issued24h: 1,
      issuedPrev24h: 0,
      denied24h: 0,
      requests24h: 1,
      activeApps24h: 1,
      totalApps: 2,
    };
    expect(ok(tokenStatsDtoSchema, s)).toBe(true);
    expect(ok(tokenStatsDtoSchema, { ...s, denied24h: -1 })).toBe(false);
  });
});
