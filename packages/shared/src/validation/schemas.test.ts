import { describe, expect, it } from "vitest";
import {
  APPROVAL_WEBHOOK,
  CLIENT_ASSERTION_TYPES,
  CLIENT_ID_REGEX,
  DEFAULTS,
  GRANT_TYPES,
  TOKEN_TYPE_URNS,
} from "../constants/index.js";
import {
  applicationCreateSchema,
  applicationDtoSchema,
  applicationKeyCreateSchema,
  applicationKeyRetireSchema,
  applicationUpdateSchema,
  approvalConditionSchema,
  approvalCountsDtoSchema,
  approvalDtoSchema,
  approvalGrantSchema,
  approvalRuleCreateSchema,
  approvalRuleDtoSchema,
  approvalsQuerySchema,
  externalIdpSchema,
  grantsReplaceSchema,
  introspectRequestSchema,
  loginSchema,
  memberCreateSchema,
  memberUpdateSchema,
  resourceCreateSchema,
  rotateSecretSchema,
  scopeCreateSchema,
  tasksQuerySchema,
  tenantCreateSchema,
  tenantDtoSchema,
  tenantUpdateSchema,
  tokenEventsQuerySchema,
  tokenExchangeSchema,
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
  it("externalIdp: https jwksUri, nullable on update", () => {
    const idp = {
      issuer: "https://idp.example.com/",
      jwksUri: "https://idp.example.com/.well-known/jwks.json",
      audience: "handsal",
    };
    expect(ok(tenantUpdateSchema, { externalIdp: idp })).toBe(true);
    expect(ok(tenantUpdateSchema, { externalIdp: null })).toBe(true);
    expect(ok(externalIdpSchema, { ...idp, jwksUri: "http://idp.example.com/jwks" })).toBe(false);
    expect(ok(externalIdpSchema, { ...idp, issuer: "not a url" })).toBe(false);
    expect(ok(externalIdpSchema, { ...idp, audience: "" })).toBe(false);
    expect(ok(tenantDtoSchema.shape.externalIdp, idp)).toBe(true);
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
  it("accepts private_key_jwt", () => {
    expect(
      ok(applicationCreateSchema, { name: "a", tokenEndpointAuthMethod: "private_key_jwt" }),
    ).toBe(true);
    expect(ok(applicationUpdateSchema, { tokenEndpointAuthMethod: "private_key_jwt" })).toBe(true);
  });
  it("kind is optional and accepts agent with guardrails", () => {
    expect(applicationCreateSchema.parse({ name: "a" }).kind).toBeUndefined();
    const agent = {
      name: "a",
      kind: "agent",
      agentRuntime: "langgraph",
      operatorEmail: "ops@example.com",
      allowedCidrs: ["10.0.0.0/8", "2001:db8::/32"],
      maxScopesPerToken: 3,
      tokenBudgetPerHour: 120,
    };
    expect(ok(applicationCreateSchema, agent)).toBe(true);
    expect(ok(applicationCreateSchema, { name: "a", kind: "robot" })).toBe(false);
  });
  it("agent field bounds", () => {
    const bad = [
      { allowedCidrs: ["10.0.0.0"] },
      { allowedCidrs: ["10.0.0.0/33"] },
      { allowedCidrs: Array.from({ length: 21 }, () => "10.0.0.0/8") },
      { maxScopesPerToken: 0 },
      { maxScopesPerToken: 51 },
      { tokenBudgetPerHour: 0 },
      { tokenBudgetPerHour: 100001 },
      { operatorEmail: "nope" },
      { agentRuntime: "" },
    ];
    for (const b of bad)
      expect(
        ok(applicationCreateSchema, { name: "a", kind: "agent", ...b }),
        JSON.stringify(b),
      ).toBe(false);
  });
  it("update: agent fields nullable, kind not accepted", () => {
    expect(ok(applicationUpdateSchema, { allowedCidrs: null, tokenBudgetPerHour: null })).toBe(
      true,
    );
    expect(ok(applicationUpdateSchema.strict(), { kind: "agent" })).toBe(false);
  });
  it("delegation settings: mayActFor enum array, scope mode enum", () => {
    expect(
      ok(applicationUpdateSchema, {
        mayActFor: ["users", "tenant", "services"],
        delegationScopeMode: "agent_only",
      }),
    ).toBe(true);
    expect(ok(applicationCreateSchema, { name: "a", kind: "agent", mayActFor: [] })).toBe(true);
    expect(ok(applicationUpdateSchema, { mayActFor: ["admins"] })).toBe(false);
    expect(ok(applicationUpdateSchema, { mayActFor: ["users", "users", "users", "users"] })).toBe(
      false,
    );
    expect(ok(applicationUpdateSchema, { mayActFor: null })).toBe(false);
    expect(ok(applicationUpdateSchema, { delegationScopeMode: "union" })).toBe(false);
    expect(ok(applicationDtoSchema.shape.delegationScopeMode, "intersection")).toBe(true);
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
  it("token request: client_assertion and task_id", () => {
    const base = { grant_type: "client_credentials", resource: "https://api" };
    expect(
      ok(tokenRequestSchema, {
        ...base,
        client_assertion: "a.b.c",
        client_assertion_type: CLIENT_ASSERTION_TYPES.JWT_BEARER,
        task_id: "run-42:step.1",
      }),
    ).toBe(true);
    expect(ok(tokenRequestSchema, { ...base, client_assertion: "x".repeat(4097) })).toBe(false);
    expect(ok(tokenRequestSchema, { ...base, task_id: "has space" })).toBe(false);
    expect(ok(tokenRequestSchema, { ...base, task_id: "" })).toBe(false);
    expect(ok(tokenRequestSchema, { ...base, task_id: "a".repeat(129) })).toBe(false);
  });
  it("token exchange request", () => {
    const base = {
      subject_token: "a.b.c",
      subject_token_type: TOKEN_TYPE_URNS.ACCESS_TOKEN,
      resource: "https://api",
    };
    expect(GRANT_TYPES.TOKEN_EXCHANGE).toBe("urn:ietf:params:oauth:grant-type:token-exchange");
    expect(ok(tokenExchangeSchema, base)).toBe(true);
    expect(
      ok(tokenExchangeSchema, {
        ...base,
        subject_token_type: TOKEN_TYPE_URNS.JWT,
        scope: "a b",
        task_id: "t-1",
      }),
    ).toBe(true);
    expect(ok(tokenExchangeSchema, { ...base, subject_token: "" })).toBe(false);
    expect(ok(tokenExchangeSchema, { ...base, subject_token: "x".repeat(8193) })).toBe(false);
    expect(
      ok(tokenExchangeSchema, {
        ...base,
        subject_token_type: "urn:ietf:params:oauth:token-type:id_token",
      }),
    ).toBe(false);
    expect(ok(tokenExchangeSchema, { ...base, resource: undefined })).toBe(false);
    expect(ok(tokenExchangeSchema, { ...base, actor_token: "x" })).toBe(false);
    expect(ok(tokenExchangeSchema, { ...base, actor_token_type: TOKEN_TYPE_URNS.JWT })).toBe(false);
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
  it("tasks query defaults and bounds limit", () => {
    expect(tasksQuerySchema.parse({}).limit).toBe(20);
    expect(ok(tasksQuerySchema, { limit: "101" })).toBe(false);
    expect(ok(tokenEventsQuerySchema, { taskId: "x".repeat(129) })).toBe(false);
  });
});

describe("approvals", () => {
  const dto = {
    id: "8d3c1f9e-2b4a-4c6d-9e8f-1a2b3c4d5e6f",
    applicationId: "8d3c1f9e-2b4a-4c6d-9e8f-1a2b3c4d5e70",
    applicationName: "agent",
    clientId: "app_aaaaaaaaaaaaaaaaaaaa",
    audience: "https://api.example",
    scopes: ["x:write"],
    actorHint: null,
    taskId: null,
    justification: null,
    status: "pending",
    expiresAt: "2026-11-06T12:30:00.000Z",
    createdAt: "2026-11-06T12:00:00.000Z",
    decidedAt: null,
    decidedBy: null,
  };
  it("grant requires a uuid approval_id", () => {
    expect(ok(approvalGrantSchema, { approval_id: dto.id })).toBe(true);
    expect(ok(approvalGrantSchema, { approval_id: "nope" })).toBe(false);
    expect(ok(approvalGrantSchema, {})).toBe(false);
  });
  it("token request accepts actor_hint and justification within limits", () => {
    const base = { grant_type: "client_credentials", resource: "https://api" };
    expect(ok(tokenRequestSchema, { ...base, actor_hint: "alice", justification: "why" })).toBe(
      true,
    );
    expect(ok(tokenRequestSchema, { ...base, actor_hint: "a".repeat(256) })).toBe(false);
    expect(ok(tokenRequestSchema, { ...base, justification: "j".repeat(2001) })).toBe(false);
    expect(GRANT_TYPES.APPROVAL).toBe("urn:handsal:params:grant-type:approval");
  });
  it("query defaults and bounds", () => {
    expect(approvalsQuerySchema.parse({})).toEqual({ status: "pending", limit: 50 });
    expect(approvalsQuerySchema.parse({ status: "resolved", limit: "100" }).limit).toBe(100);
    expect(ok(approvalsQuerySchema, { limit: "101" })).toBe(false);
    expect(ok(approvalsQuerySchema, { status: "approved" })).toBe(false);
    expect(ok(approvalsQuerySchema, { cursor: "c".repeat(257) })).toBe(false);
  });
  it("dto: decidedBy kinds and status enum", () => {
    expect(ok(approvalDtoSchema, dto)).toBe(true);
    expect(
      ok(approvalDtoSchema, {
        ...dto,
        status: "approved",
        decidedAt: dto.createdAt,
        decidedBy: { kind: "api-key", label: "API key" },
      }),
    ).toBe(true);
    expect(ok(approvalDtoSchema, { ...dto, decidedBy: { kind: "bot", label: "x" } })).toBe(false);
    expect(ok(approvalDtoSchema, { ...dto, status: "consumed" })).toBe(false);
  });
  it("counts allow null oldest and median", () => {
    const c = {
      pending: 0,
      oldestPendingAt: null,
      approvedToday: 0,
      deniedToday: 0,
      medianWaitSeconds: null,
      rules: 0,
    };
    expect(ok(approvalCountsDtoSchema, c)).toBe(true);
    expect(ok(approvalCountsDtoSchema, { ...c, pending: -1 })).toBe(false);
  });
  it("token events accept the pending outcome", () => {
    expect(ok(tokenEventsQuerySchema, { outcome: "pending" })).toBe(true);
  });
});

describe("application keys", () => {
  it("kid charset and length", () => {
    expect(ok(applicationKeyCreateSchema, { kid: "key-1:v2.a_b", publicKeyPem: "pem" })).toBe(true);
    expect(ok(applicationKeyCreateSchema, { kid: "has space", publicKeyPem: "pem" })).toBe(false);
    expect(ok(applicationKeyCreateSchema, { kid: "k".repeat(129), publicKeyPem: "pem" })).toBe(
      false,
    );
    expect(ok(applicationKeyCreateSchema, { kid: "k", publicKeyPem: "" })).toBe(false);
  });
  it("retire defaults grace", () => {
    expect(applicationKeyRetireSchema.parse({}).graceSeconds).toBe(DEFAULTS.SECRET_GRACE_SECONDS);
    expect(ok(applicationKeyRetireSchema, { graceSeconds: 604801 })).toBe(false);
  });
});

describe("approval rules + webhook (6.5)", () => {
  const uuid = "8d3c1f9e-2b4a-4c6d-9e8f-1a2b3c4d5e6f";
  it("condition: all keys optional, strict, bounded", () => {
    expect(ok(approvalConditionSchema, {})).toBe(true);
    expect(
      ok(approvalConditionSchema, {
        application_ids: [uuid],
        task_id_prefix: "INC-",
        max_scopes: 2,
      }),
    ).toBe(true);
    expect(ok(approvalConditionSchema, { amount_lt: 20 })).toBe(false);
    expect(ok(approvalConditionSchema, { application_ids: ["nope"] })).toBe(false);
    expect(ok(approvalConditionSchema, { application_ids: Array(51).fill(uuid) })).toBe(false);
    expect(ok(approvalConditionSchema, { task_id_prefix: "" })).toBe(false);
    expect(ok(approvalConditionSchema, { max_scopes: 0 })).toBe(false);
    expect(ok(approvalConditionSchema, { max_scopes: 1.5 })).toBe(false);
  });
  it("create defaults condition to {}", () => {
    expect(approvalRuleCreateSchema.parse({ scopeId: uuid }).condition).toEqual({});
    expect(ok(approvalRuleCreateSchema, { scopeId: "nope" })).toBe(false);
  });
  it("dto action is auto_approve only", () => {
    const dto = {
      id: uuid,
      scopeId: uuid,
      scopeName: "refunds:write",
      resourceName: "Payments",
      condition: {},
      action: "auto_approve",
      createdBy: null,
      createdAt: "2026-11-06T12:00:00.000Z",
    };
    expect(ok(approvalRuleDtoSchema, dto)).toBe(true);
    expect(ok(approvalRuleDtoSchema, { ...dto, action: "deny" })).toBe(false);
  });
  it("tenant update: webhook url and write-only secret", () => {
    expect(
      ok(tenantUpdateSchema, {
        approvalWebhookUrl: "https://hooks.slack.com/services/x",
        approvalWebhookSecret: "s".repeat(16),
      }),
    ).toBe(true);
    expect(ok(tenantUpdateSchema, { approvalWebhookUrl: null, approvalWebhookSecret: null })).toBe(
      true,
    );
    expect(ok(tenantUpdateSchema, { approvalWebhookUrl: "not a url" })).toBe(false);
    expect(ok(tenantUpdateSchema, { approvalWebhookSecret: "short" })).toBe(false);
    expect(ok(tenantUpdateSchema, { approvalWebhookSecret: "s".repeat(256) })).toBe(false);
  });
  it("tenant dto exposes secretSet, never the secret; counts gain rules", () => {
    expect(tenantDtoSchema.shape.approvalWebhookSecretSet).toBeDefined();
    expect("approvalWebhookSecret" in tenantDtoSchema.shape).toBe(false);
    expect(approvalCountsDtoSchema.shape.rules).toBeDefined();
    expect(APPROVAL_WEBHOOK.SIGNATURE_HEADER).toBe("X-Handsal-Signature");
  });
});
