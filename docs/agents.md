# Handsal — AI agents (Phase 6) design note

Written 2026-11-06 by two `deep-reasoner` passes before implementation; the source of truth for tasks 6.1–6.6 in `Tasks.md`. Part 1 covers 6.1 (`private_key_jwt`), 6.2 (agent kind + guardrails) and 6.6 (agent activity); Part 2 covers 6.3 (approvals), 6.4 (token exchange) and 6.5 (notifications + rules). Column naming reconciled: `token_events.actor_sub` is defined in 6.6 and written only by 6.4.

---

# Part 1 — 6.1, 6.2, 6.6


Scope: `private_key_jwt` client authentication, agent application kind + guardrails, agent task activity. Tasks 6.3–6.5 (approvals, token exchange, notifications) are covered by a separate note and only consume the `task_id` and `actor_sub` columns defined in 6.6 here.

---

## 6.1 — `private_key_jwt` (RFC 7523)

### 1. Decision summary

- Ships: `application_keys` table (one or more registered ES256 public keys per application), `client_assertion` authentication on **all three** form-encoded OAuth endpoints (token, introspect, revoke), management CRUD for keys, and the artboard-08 "Registered public keys" UI. `private_key_jwt` becomes selectable as `token_endpoint_auth_method`.
- Public keys are accepted as **SPKI PEM only**. JWK bodies and `jwks_uri` registration are out of scope (jose's `importSPKI` is the one code path the server already uses, `signing-key.service.ts:238`).
- `client_secret` behaviour is unchanged: `createApplication` still generates and hashes one, and `authenticateClient` already rejects a credential presented through the wrong method (`client-auth.service.ts:86-90`). No nullability change, no secret deletion on method switch.
- Assertion `aud` must equal the tenant **token endpoint** URL, for all three endpoints. Accepting the issuer identifier as an alternative `aud` is out of scope.
- Replay protection is a process-local `MemoryStore` keyed `tenant:client:jti`. Out of scope: shared replay state across replicas (same deferral as the rate limiter, `Tasks.md` line 37).
- Out of scope: assertion-based authentication for management `/api` routes, key rollover automation, public-key import caching.

### 2. Schema delta

New file `packages/db/src/schema/application-keys.ts`, exported from `packages/db/src/schema/index.ts`.

| Column | Type | Notes |
|---|---|---|
| `id` | `uuid` pk `defaultRandom()` | |
| `tenant_id` | `uuid not null` | FK -> `tenants.id` `onDelete: "cascade"` |
| `application_id` | `uuid not null` | no direct FK; composite FK below |
| `kid` | `varchar(128) not null` | selected by the assertion header |
| `algorithm` | `varchar(10) not null default 'ES256'` | mirrors `signing_keys.algorithm` |
| `public_key_pem` | `text not null` | SPKI PEM |
| `fingerprint_sha256` | `varchar(64) not null` | lowercase hex of SHA-256 over the DER SPKI |
| `status` | `application_key_status not null default 'active'` | new `pgEnum("application_key_status", ["active","retiring"])` |
| `retires_at` | `timestamptz null` | |
| `created_at` / `updated_at` | `timestamptz not null defaultNow()` (`$onUpdate` on the latter) | |

Indexes and constraints, in the style of `scopes.ts:28-41`:

- `unique("uq_application_keys_application_id_kid").on(applicationId, kid)`
- `unique("uq_application_keys_application_id_fingerprint").on(applicationId, fingerprintSha256)` — blocks the same key registered twice under two kids
- `index("idx_application_keys_application_id").on(applicationId)`
- `foreignKey({ columns: [tenantId, applicationId], foreignColumns: [applications.tenantId, applications.id], name: "fk_application_keys_application" }).onDelete("cascade")` — same-tenant invariant plus cascade on application delete

A new enum rather than reusing `signing_key_status`: that enum permits `retired`, which has no meaning here, and coupling two tables' lifecycles to one type would block either from changing.

Migration: generated with `pnpm db:generate`, never hand-edited. See section 8 — 6.1, 6.2 and 6.6 share a **single** migration `packages/db/drizzle/0002_<generated>.sql` produced by one schema slice, so no rebase-and-regenerate step exists.

### 3. Shared package delta

`packages/shared/src/validation/application-key.schema.ts` (new, re-exported from `validation/index.ts`):

```ts
export const applicationKeyCreateSchema = z.object({
  kid: z.string().min(1).max(128).regex(/^[A-Za-z0-9._:-]+$/),
  publicKeyPem: z.string().min(1).max(4096),
});
export const applicationKeyRetireSchema = z.object({
  graceSeconds: z.number().int().min(0).max(604800).default(DEFAULTS.SECRET_GRACE_SECONDS),
});
export const applicationKeyDtoSchema = z.object({
  id: z.uuid(), applicationId: z.uuid(), kid: z.string(), algorithm: z.string(),
  fingerprintSha256: z.string(), status: z.enum(["active", "retiring"]),
  retiresAt: z.iso.datetime().nullable(),
  createdAt: z.iso.datetime(), updatedAt: z.iso.datetime(),
});
```

The DTO deliberately omits `publicKeyPem`: nothing in the UI needs it, and it keeps the "no key material in responses" assertion trivial.

Other edits:

- `application.schema.ts`: delete the `mvpAuthMethod` refine (lines 6-8) and use `authMethodEnum` in `applicationCreateSchema` and `applicationUpdateSchema`.
- `constants/oauth.ts`: `CLIENT_ASSERTION_TYPES = { JWT_BEARER: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" } as const`; `ASSERTION_MAX_LIFETIME_SECONDS = 300`; `ASSERTION_CLOCK_TOLERANCE_SECONDS = 60`.
- `oauth.schema.ts`: add `client_assertion: z.string().max(4096).optional()` and `client_assertion_type: z.string().max(128).optional()` to `tokenRequestSchema`.
- `types/api.ts`: `export type ApplicationKeyDto = z.infer<typeof applicationKeyDtoSchema>;`

### 4. API delta

OAuth (RFC-exact codes; `OAuthError(code, status, description)`):

| Condition | Code | Status |
|---|---|---|
| `client_assertion_type` present and not the JWT-bearer URN | `invalid_request` | 400 |
| `client_assertion` without `client_assertion_type` (or the reverse) | `invalid_request` | 400 |
| Assertion plus Basic header or body `client_secret` | `invalid_request` | 400 |
| Any assertion content failure (signature, `alg`, `kid`, `iss`/`sub`, `aud`, `exp`, `jti`, replay, unknown client, method mismatch, disabled client) | `invalid_client` | 401 + `WWW-Authenticate: Basic realm="handsal"` |

The 401 body is the same for every assertion failure; the distinguishing detail lives only in `token_events.reason` and the security log, matching the existing `fail()` helper at `client-auth.service.ts:29-48`.

Management (`ApiError(status, code, description)`), mounted from a new `routes/management/application-keys.ts`:

| Method | Path | Role | Request | Response |
|---|---|---|---|---|
| GET | `/api/tenants/:tenantId/applications/:appId/keys` | auditor | — | `200 {items: ApplicationKeyDto[]}` |
| POST | same | admin | `applicationKeyCreateSchema` | `201 ApplicationKeyDto` |
| POST | `.../keys/:keyId/retire` | admin | `applicationKeyRetireSchema` | `200 ApplicationKeyDto` |
| DELETE | `.../keys/:keyId` | admin | — | `204` |

Errors: `400 invalid_public_key` (not a P-256 SPKI PEM), `409 application_key_exists` (duplicate kid or fingerprint), `404 application_key_not_found`, `404 application_not_found` (reuse `appIdParam` from `routes/management/grants.ts:11`), `403` from `requireTenantAccess`.

Also: `applicationRoutes.route("/", applicationKeyRoutes)` appended at the end of `routes/management/applications.ts` (same pattern as `grantRoutes`, line 131) so `routes/management/index.ts` needs no edit at all.

Discovery (`routes/oauth/discovery.ts:7`): `AUTH_METHODS` becomes `["client_secret_basic", "client_secret_post", "private_key_jwt"]`, which updates all three advertised lists.

### 5. Service logic

New `authenticateClientAssertion(tenant, assertion, sourceIp)` in `apps/api/src/services/client-auth.service.ts`, reusing the existing `fail()` so the security log and `err.reason` contract are identical:

1. `decodeHeader(assertion)` (`utils/jwt.ts:61`). `alg !== "ES256"` or missing `kid` -> `fail(..., "bad_assertion")`.
2. Decode the payload unverified; require `iss` and `sub` present, non-empty and equal. That value is the `clientId`. Mismatch -> `bad_assertion`.
3. Load the application by `(tenant.id, clientId)`. Miss -> `unknown_client`.
4. `application.tokenEndpointAuthMethod !== "private_key_jwt"` -> `auth_method_mismatch`.
5. Load the `application_keys` row by `(tenantId, applicationId, kid)` where `status = 'active'` or (`status = 'retiring'` and `retires_at > now()`). Miss -> `unknown_assertion_key`.
6. `jwtVerify(assertion, await importSPKI(pem, "ES256"), { algorithms: ["ES256"], issuer: clientId, subject: clientId, audience: `${env.PUBLIC_URL}/t/${tenant.slug}/oauth/token`, clockTolerance: 60 })`. Any throw -> `bad_assertion`, except a `JWTExpired` / `JWTClaimValidationFailed` on `exp`/`nbf` -> `assertion_expired`.
7. Require `jti`; require `exp - now <= 300`; reject `iat > now + 60`. Failure -> `bad_assertion`.
8. Replay: module-level `const assertionJtis = new MemoryStore<true>()`. `has(`${tenant.id}:${clientId}:${jti}`)` -> `assertion_replayed`. Otherwise `set(key, true, (exp * 1000 - Date.now()) + 60_000)` clamped to `[1, 360_000]`. The `set` happens only **after** step 6 verifies, so an unsigned forgery cannot burn a real `jti`.
9. `application.status === "disabled"` -> `client_disabled`, checked last so status is not an oracle for unauthenticated callers (mirrors line 96-99).
10. Strip the secret hashes and return `{ application }`.

Helper `assertionClientId(assertion): string | undefined` in the same file: decodes the payload and returns `iss` when `iss === sub`. Used by the route for the denied-event client id and by `clientIdKey`.

Route wiring in `apps/api/src/routes/oauth/token.ts`:

- Fold the duplicated credential block (lines 106-118) into `authenticateFormClient(c)`, which gains the assertion branch at its top. The token route then calls `application = await authenticateFormClient(c)` — a net deletion, and introspect/revoke get `private_key_jwt` for free. Without this, a `private_key_jwt` client could never revoke its own tokens (RFC 7009 section 2.2 requires the owning client).
- `clientId` for the denied event becomes `basic?.clientId ?? body?.client_id ?? assertionClientId(body?.client_assertion)`.
- When both `client_id` and an assertion are present, require equality (RFC 7523 section 3 permits sending both) -> mismatch is `invalid_client`.

`apps/api/src/middleware/rate-limit.ts:40` — `clientIdKey` falls back to `assertionClientId(c.var.formBody?.client_assertion)` after `formBody?.client_id`. Without it, assertion-authenticated clients have no per-client bucket and are bounded only by the per-IP limiter.

`updateApplication` guard (implemented in slice C, see section 8): switching `tokenEndpointAuthMethod` to `private_key_jwt` when the application has no usable key -> `ApiError(409, "no_application_key", ...)`. Prevents a silent total outage for that client.

### 6. Web UI delta

| File | Change |
|---|---|
| `apps/web/src/components/ApplicationForm.tsx:35` | drop `disabled: true` from the `private_key_jwt` entry and the "coming soon" span; for agents label it `private_key_jwt (recommended for agents)` |
| `apps/web/src/components/RegisteredKeys.tsx` (new) | section label **Registered public keys**; one row per key: mono `{kid}`, secondary line `ES256 · SHA-256 {fp}` (hex rendered colon-grouped, elided in the middle), meta `added <date>` or `retires <date>`, status `Badge` **Active** / **Retiring**; row actions Retire and Delete for non-auditors; helper copy verbatim from the artboard: "The runtime signs a short-lived assertion with its private key on every token request. Keys can live in a KMS or the runtime's secret store; Handsal only ever sees the public half." |
| `apps/web/src/components/RegisterKeyDialog.tsx` (new) | **Register key** button in the Credentials card header; fields Key ID + Public key (PEM textarea); surfaces 400/409 inline |
| `apps/web/src/routes/t.$tenantId.applications.$appId.tsx` | render `<RegisteredKeys>` inside the Credentials card when `app.tokenEndpointAuthMethod === "private_key_jwt"` or `app.kind === "agent"`; when the method is private_key_jwt also replace the masked client-secret row with the key list |

Role gating: every mutation hidden when `role === "auditor"` (the page already derives `canEdit` at line 64).

`apps/web/src/lib/queries.ts` additions: `useApplicationKeys(tenantId, appId)`, `useRegisterApplicationKey`, `useRetireApplicationKey`, `useDeleteApplicationKey` — all invalidating `["application-keys", { tenantId, appId }]` and `["application", { tenantId, appId }]`.

### 7. Tests

Integration against real Postgres. `apps/api/src/services/client-auth.service.test.ts` and `apps/api/src/routes/oauth/token.test.ts` additions:

1. assertion signed by a registered active key -> 200 and the JWT's `client_id` is the application's
2. `aud` set to the issuer instead of the token endpoint -> 401 `invalid_client`, event reason `bad_assertion`
3. the same assertion posted twice -> 200 then 401, reason `assertion_replayed`
4. `exp` ten minutes out -> 401; `exp` two minutes in the past -> 401 reason `assertion_expired`
5. `iss !== sub` -> 401
6. `kid` belonging to another application's key -> 401 `unknown_assertion_key`
7. key `status='retiring'` with a future `retires_at` -> 200; with a past `retires_at` -> 401
8. application registered `client_secret_basic` sending an assertion -> 401 `auth_method_mismatch`; registered `private_key_jwt` sending Basic -> 401 `auth_method_mismatch`
9. assertion plus body `client_secret` -> 400 `invalid_request`; unknown `client_assertion_type` -> 400
10. RS256-signed assertion -> 401
11. disabled application with a valid assertion -> 401 reason `client_disabled`
12. `client_id` present and different from `iss` -> 401
13. a `private_key_jwt` client introspects and revokes its own token with an assertion -> both 200
14. discovery lists `private_key_jwt` in all three `*_auth_methods_supported` arrays

`apps/api/src/routes/management/application-keys.test.ts`:

15. P-384 PEM -> 400 `invalid_public_key`; duplicate kid -> 409; same key under a new kid -> 409
16. `expect(JSON.stringify(body)).not.toContain("PRIVATE")` on every key response
17. auditor POST -> 403; a key of another tenant's application -> 404
18. deleting the application cascades its keys; deleting the tenant cascades them
19. switching an application with no keys to `private_key_jwt` -> 409 `no_application_key`

---

## 6.2 — Agent application kind + guardrails

### 1. Decision summary

- Ships: `kind: "agent"` accepted on create, five guardrail columns on `applications`, enforcement of source-IP CIDR, per-token scope ceiling and hourly token budget inside `issueToken`, the Type column and "AI agents" filter on the applications list, and the artboard-08 Runtime binding / Guardrails sections.
- `kind` is **immutable after create** (not in `applicationUpdateSchema`). A service application cannot silently become a guarded agent.
- Guardrail columns are rejected on service applications (`400 agent_fields_on_service`) rather than silently ignored.
- Agent TTLs of 1/5/15 minutes are **UI options only**; `DEFAULTS.TTL_MIN` is already 60 and the TTL precedence rule in `token.service.ts:76` is untouched. No backend default per kind.
- `allowed_cidrs` empty means unrestricted. A corrupt stored CIDR **fails closed**.
- Out of scope: per-scope approval toggles and the Delegation / Claims-preview panels of artboard 08 (tasks 6.3 and 6.4), a distinct agent route (the existing detail route renders agent sections conditionally), budget enforcement that is exact under concurrency.

### 2. Schema delta

`packages/db/src/schema/applications.ts`, appended to the existing column list:

| Column | Type |
|---|---|
| `agent_runtime` | `varchar(64) null` |
| `operator_email` | `varchar(255) null` |
| `allowed_cidrs` | `text("allowed_cidrs").array().notNull().default(sql`'{}'::text[]`)` |
| `max_scopes_per_token` | `integer null` |
| `token_budget_per_hour` | `integer null` |

`packages/db/src/schema/token-events.ts`, new index: `index("idx_token_events_application_id_created_at").on(t.applicationId, t.createdAt.desc())`. The budget count filters `(tenant_id, application_id, outcome, created_at)` and the existing `(tenant_id, created_at desc)` index would scan the whole tenant's last hour. The same index also fixes the already-shipped per-application listing at `routes/management/token-events.ts:37`, which has none today.

Same single migration as 6.1 (see section 8).

### 3. Shared package delta

`constants/regex.ts`: a deliberately loose shape check, because `constants/regex.ts` is zod-free and browser-bound, so `node:net` cannot be used there.

```ts
export const CIDR_REGEX =
  /^(?:\d{1,3}(?:\.\d{1,3}){3}\/(?:3[0-2]|[12]?\d)|[0-9A-Fa-f:]{2,45}\/(?:12[0-8]|1[01]\d|[1-9]?\d))$/;
```

The authoritative check runs server-side in `application.service.ts` via `net.BlockList.addSubnet` inside a try/catch -> `ApiError(400, "invalid_cidr", ...)`. Node's own parser is what enforces the rule at request time, so validating with it is both shorter and strictly more correct than any regex.

`constants/defaults.ts`: `AGENT_TTL_OPTIONS = [60, 300, 900] as const`, `AGENT_MAX_SCOPES_MIN = 1`, `AGENT_MAX_SCOPES_MAX = 50`, `AGENT_BUDGET_MIN = 1`, `AGENT_BUDGET_MAX = 100000`, `AGENT_CIDRS_MAX = 20`.

`application.schema.ts`:

```ts
const agentFields = {
  agentRuntime: z.string().min(1).max(64).optional(),
  operatorEmail: z.email().max(255).optional(),
  allowedCidrs: z.array(z.string().max(49).regex(CIDR_REGEX)).max(20).optional(),
  maxScopesPerToken: z.number().int().min(1).max(50).optional(),
  tokenBudgetPerHour: z.number().int().min(1).max(100000).optional(),
};
// create: { ...existing, kind: z.enum(["service","agent"]).default("service"), ...agentFields }
// update: existing + nullable()+optional() variants of every agentField; no `kind`
```

`applicationDtoSchema` gains `kind` (already present), `agentRuntime`, `operatorEmail`, `allowedCidrs: z.array(z.string())`, `maxScopesPerToken`, `tokenBudgetPerHour` — all nullable except the array.

### 4. API delta

- `GET /api/tenants/:tenantId/applications` — `listQuerySchema` in `routes/management/applications.ts:30` gains `kind: z.enum(["service","agent"]).optional()`, passed through to `listApplications`, which adds one `eq(applications.kind, ...)` condition. Backs the "AI agents" filter chip.
- `POST /api/tenants/:tenantId/applications` — `createBodySchema` stays `.strict()`; the comment at line 27 is removed and `kind` plus the agent fields are now legal keys.
- `PATCH .../applications/:appId` — accepts the agent fields; `kind` remains an unknown key.
- `GET .../applications/:appId` — response gains `agentBudgetUsed: number | null` (issued count in the trailing hour, non-null only for an agent with a budget set). Feeds the artboard's "Used this hour: N of 120".
- New errors: `400 agent_fields_on_service`, `400 invalid_cidr`, `409 no_application_key` (shared with 6.1).
- OAuth denials, all recorded by the **existing** catch block at `token.ts:142-154` with no change to the recording path:

| Guardrail | Code | Status | `token_events.reason` |
|---|---|---|---|
| source IP outside `allowed_cidrs` | `unauthorized_client` | 400 | `cidr_denied` |
| token scope count above `max_scopes_per_token` | `invalid_scope` | 400 | `scope_ceiling` |
| hourly issued count at `token_budget_per_hour` | `too_many_requests` | 429 + `Retry-After` | `budget_exhausted` |

Justification for the three codes. `unauthorized_client` is RFC 6749 section 5.2's "the authenticated client is not authorized" slot; `invalid_client` would be wrong because authentication succeeded, and a 401 would make clients retry their credentials. `invalid_scope` is a literal fit ("the requested scope ... exceeds the scope granted"), and the client's fix is to request fewer scopes. For the budget, RFC 6749 defines no quota code, and this server **already** answers exactly this condition with `429 {error:"too_many_requests"}` at `middleware/rate-limit.ts:62`; reusing it means clients that already handle the limiter handle the budget, whereas inventing a code would be worse than reusing a shipped one.

`OAuthError` gains `public retryAfterSeconds?: number` and `errorHandler` emits the header when set (`middleware/error-handler.ts`, three lines) — the handler currently sets `Retry-After` only for `ServiceOverloadError`.

### 5. Service logic

New `apps/api/src/utils/cidr.ts`:

```ts
/** True when `ip` is in any of `cidrs`; `cidrs` empty means unrestricted. Throws on a malformed entry. */
export function ipInCidrs(ip: string, cidrs: string[]): boolean
```

Built on `node:net.BlockList` — no new dependency. Normalise an IPv4-mapped form (`::ffff:a.b.c.d` -> `a.b.c.d`) first, pick the family with `net.isIPv4` / `net.isIPv6`, call `addSubnet(addr, Number(prefix), family)` per entry, then `check(ip, family)`.

`issueToken` (`apps/api/src/services/token.service.ts`) — the new checks slot in **after** the existing `agent_policy === "never"` check (lines 54-74) and **before** the TTL/sign block (line 76). Full order:

1. tenant paused -> `invalid_request` (unchanged, line 37)
2. resource resolution -> `invalid_target` (unchanged, line 42)
3. requested subset of granted -> `invalid_scope` (unchanged, line 49)
4. agent + `agent_policy = never` -> `invalid_scope` (unchanged, line 54)
5. **new** `kind === "agent"` and `allowedCidrs.length > 0`: `ipInCidrs(ctx.sourceIp, allowedCidrs)` false -> deny `unauthorized_client` / `cidr_denied`. A throw from `ipInCidrs` is logged and treated as **deny**, not allow.
6. **new** `kind === "agent"` and `maxScopesPerToken !== null` and `tokenScopes.length > maxScopesPerToken` -> deny `invalid_scope` / `scope_ceiling`.
7. **new** `kind === "agent"` and `tokenBudgetPerHour !== null`: one query `select count(*)::int, min(created_at) from token_events where tenant_id = $1 and application_id = $2 and outcome = 'issued' and created_at >= now() - interval '1 hour'`. When `count >= budget` -> deny with `retryAfterSeconds = clamp(ceil((min + 1h - now)/1000), 1, 3600)`.
8. TTL precedence, sign, `recordTokenEvent({outcome:"issued"})`, `last_token_at` (unchanged).

Placing the guardrails after steps 2-4 means an agent that is not granted a resource still gets `invalid_target`, so guardrail configuration never becomes an oracle for grants it does not hold.

Two documented limitations, each as a one-line `shortcut:` comment:

- The budget read is not serialised with the insert, so concurrent requests at the boundary can overshoot by the number of in-flight requests. Same class as the limiter's documented race at `rate-limit.ts:79`. Exactness would need a serializable transaction or a counter row.
- With `scope` omitted, `tokenScopes` is the whole grant (line 52), so an agent granted more scopes than its ceiling is denied until it requests explicitly. That is the intended "forces least-privilege requests" behaviour from the artboard and must be stated in the UI helper text.

The count is shared with the detail endpoint as `countIssuedLastHour(tenantId, applicationId): Promise<{count, oldestAt}>` in `token-event.service.ts`.

`application.service.ts`:

- `createApplication` passes `input.kind ?? "service"` instead of the hardcoded `"service"` (line 63) and persists the agent fields; when `kind !== "agent"` and any agent field is present -> `ApiError(400, "agent_fields_on_service", ...)`.
- `updateApplication` reads the row with `getApplication` **only** when the patch contains an agent field or an auth-method change, then applies the `agent_fields_on_service` and `no_application_key` guards. The common patch path keeps its single-statement update (lines 150-163).
- Both validate `allowedCidrs` through `ipInCidrs`'s parser before writing.

### 6. Web UI delta

| File | Change |
|---|---|
| `routes/t.$tenantId.applications.tsx` | `FILTERS` (line 28) becomes **All / Active / AI agents / Needs attention**, the agents entry sending `kind=agent`; add a **Type** column after Application rendering `Badge` **AI agent** (accent) or **Service** (neutral), per the artboard's column order |
| `components/ApplicationForm.tsx` | Type radio **Service** / **AI agent**; selecting AI agent preselects `private_key_jwt` and TTL `300` |
| `components/AgentGuardrails.tsx` (new) | header **Guardrails**, subtitle "Limits enforced by the issuer on every token this agent requests."; **Token lifetime** select 1 minute / 5 minutes / 15 minutes with helper "Agents get short leases, one per task."; **Max scopes per token** number input `min=1` with helper "Forces least-privilege requests."; **Token budget** number with a `/ hour` suffix, helper "Used this hour: {agentBudgetUsed} of {tokenBudgetPerHour}" and a progress bar; Discard / Save |
| `components/RuntimeBinding.tsx` (new) | label **Runtime binding** with three fields **Runtime**, **Allowed origins** (comma-separated CIDR list, inline `CIDR_REGEX` feedback), **Operator** |
| `routes/t.$tenantId.applications.$appId.tsx` | **AI agent** badge in the header; Credentials subtitle for agents: "Held by the agent runtime, never by the model. Key-based auth means there is no shared secret to leak into a prompt."; render `<RuntimeBinding>` and `<AgentGuardrails>` when `kind === "agent"`; pass `title="Scope ceiling"` and the artboard subtitle to `GrantsMatrix` for agents |
| `components/TokenEventsTable.tsx:7` | `REASONS` gains `cidr_denied: "source IP not allowed"`, `scope_ceiling: "above scope ceiling"`, `budget_exhausted: "token budget exhausted"`, plus the four 6.1 reasons |

Deviation from the artboard, deliberate: the header action stays **Disable** / **Enable** rather than "Pause agent", so agents and services share one status vocabulary and one mutation.

`queries.ts`: `useApplicationUpdate`'s input type gains the five agent fields; `ApplicationDetail` gains `agentBudgetUsed: number | null`; `useApplicationsList` filters gain `kind`.

Role gating: the whole Guardrails and Runtime binding block is read-only for auditors (reuse `canEdit`).

### 7. Tests

`apps/api/src/services/token.service.test.ts`, `apps/api/src/utils/cidr.test.ts` (unit), `apps/api/src/routes/management/applications.test.ts`:

1. `createApplication({kind:"agent"})` yields kind agent; omitting `kind` yields service
2. agent field on a service application, on create and on patch -> 400 `agent_fields_on_service`
3. `kind` in a PATCH body leaves the stored kind unchanged
4. source IP inside `10.40.0.0/16` -> 200; outside -> 400 `unauthorized_client` with event reason `cidr_denied`
5. empty `allowed_cidrs` -> any source IP allowed
6. `2001:db8::/32` matches `2001:db8::1`; `::ffff:10.40.0.5` matches `10.40.0.0/16`
7. a malformed stored CIDR -> request denied, not allowed
8. `max_scopes_per_token = 2`: two requested scopes -> 200, three -> 400 `invalid_scope` reason `scope_ceiling`
9. omitted `scope` with three granted scopes and a ceiling of two -> denied
10. `token_budget_per_hour = 3`: requests 1-3 -> 200, request 4 -> 429 with `Retry-After`, reason `budget_exhausted` (the N versus N+1 boundary)
11. an `issued` event backdated 61 minutes does not count toward the budget
12. `denied` events do not count toward the budget
13. a **service** application with all five columns populated issues tokens from any IP, any scope count, any volume
14. ordering: an agent requesting an ungranted resource from a disallowed IP gets `invalid_target`, not `unauthorized_client`
15. `GET .../applications/:appId` returns a number for `agentBudgetUsed` on a budgeted agent and `null` on a service application

No factory change: `createApplication(tenantId, { kind: "agent", ... })` already forwards `over` into the create input (`test/factories.ts:42-47`).

---

## 6.6 — Agent activity

### 1. Decision summary

- Ships: an optional `task_id` form parameter on `POST /t/:slug/oauth/token`, persisted on `token_events` and emitted as a `task_id` JWT claim when present; a tasks-grouping endpoint; a "Recent tasks" view on the Tokens page and on the agent detail page; an "agent · for <actor>" column on the token events table.
- 6.6 also **defines** `token_events.actor_sub varchar(255) null` and surfaces it as `actorSub`, but writes it nowhere. Task 6.4 fills it from the `act` claim. This keeps 6.4 from needing another migration and gives the column a single owner. **The 6.3/6.4 note must be told this column already exists.**
- `task_id` validation is a charset regex; an invalid value falls out of the existing `tokenRequestSchema` parse as `invalid_request`. No dedicated error branch, so the description stays the generic "Invalid or missing required parameters".
- The tasks query is bounded to the last 24 hours and reuses `idx_token_events_tenant_id_created_at`. No grouping-specific index.
- Out of scope: `task_id` in the introspection response, task-level retention separate from `TOKEN_EVENTS_RETENTION_DAYS`, cross-application tasks (the summary takes `max(application_client_id)`, which is only meaningful when a task belongs to one client).

### 2. Schema delta

`packages/db/src/schema/token-events.ts`:

| Column | Type |
|---|---|
| `task_id` | `varchar(128) null` |
| `actor_sub` | `varchar(255) null` |

Index: `index("idx_token_events_task_id").on(t.taskId)`, mirroring the existing `idx_token_events_jti` (line 36). Same single migration as 6.1 and 6.2.

### 3. Shared package delta

- `constants/regex.ts`: `export const TASK_ID_REGEX = /^[A-Za-z0-9._:-]{1,128}$/;` — no whitespace or control characters, so the value is safe in logs, URLs and the UI without escaping.
- `oauth.schema.ts`: `tokenRequestSchema` gains `task_id: z.string().regex(TASK_ID_REGEX).optional()`.
- `token-events.schema.ts`: `tokenEventDtoSchema` gains `taskId: z.string().nullable()` and `actorSub: z.string().nullable()`; `tokenEventsQuerySchema` gains `taskId: z.string().max(128).optional()`; new `taskSummaryDtoSchema`:

```ts
export const taskSummaryDtoSchema = z.object({
  taskId: z.string(),
  applicationId: z.uuid().nullable(),
  applicationClientId: z.string().nullable(),
  actorSub: z.string().nullable(),
  scopes: z.array(z.string()),
  tokenCount: z.number().int(),
  deniedCount: z.number().int(),
  firstSeenAt: z.iso.datetime(),
  lastSeenAt: z.iso.datetime(),
});
export const tasksQuerySchema = z.object({
  applicationId: z.uuid().optional(),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});
```

`types/api.ts`: `export type TaskSummaryDto = z.infer<typeof taskSummaryDtoSchema>;`

### 4. API delta

| Method | Path | Role | Query | Response |
|---|---|---|---|---|
| GET | `/api/tenants/:tenantId/token-events/tasks` | auditor | `tasksQuerySchema` | `200 {items: TaskSummaryDto[]}` |

Added to the existing `routes/management/token-events.ts`. It must be registered **before** any `/:tenantId/token-events/:something` pattern; today only `/stats` exists, so append-order is safe.

`GET .../token-events` additionally honours `?taskId=` (one more `eq` condition in `listTokenEvents`).

No OAuth-side route change beyond threading the parsed `task_id`.

### 5. Service logic

`issueToken` — two one-line additions, specified exactly so the owning slice can apply them blind:

- claims object (`token.service.ts:84-95`): `...(request.taskId && { task_id: request.taskId })`. Absent when not supplied, never `null`.
- `recordTokenEvent` call (line 97): `taskId: request.taskId ?? null`.
- signature: `request: { audience: string; requestedScopes?: string[]; taskId?: string }`.

`token.ts` route (line 136): `{ audience: parsed.data.resource, requestedScopes: splitScopes(parsed.data.scope), taskId: parsed.data.task_id }`.

Denied requests: the catch block does not currently carry `task_id`. Add `taskId: body?.task_id?.slice(0, 128) ?? null` to the `recordTokenEvent` call at `token.ts:144`, so a denied attempt still shows up under its task (the artboard's last row is `customers.write · denied: not in ceiling`).

`listTasks(tenantId, query)` in `token-event.service.ts`, raw `db.execute(sql`...`)` because of the lateral (precedent: `signing-key.service.ts:130`):

```sql
select te.task_id,
       max(te.application_id::text)        as application_id,
       max(te.application_client_id)       as application_client_id,
       max(te.actor_sub)                   as actor_sub,
       count(distinct te.id)::int          as token_count,
       count(distinct te.id) filter (where te.outcome = 'denied')::int as denied_count,
       coalesce(array_agg(distinct s.name) filter (where s.name is not null), '{}') as scopes,
       min(te.created_at) as first_seen_at,
       max(te.created_at) as last_seen_at
from token_events te
left join lateral unnest(te.scopes) as s(name) on true
where te.tenant_id = $1 and te.task_id is not null
  and te.created_at >= now() - interval '24 hours'
  and ($2::uuid is null or te.application_id = $2)
group by te.task_id
order by max(te.created_at) desc
limit $3
```

`count(distinct te.id)` is what makes the lateral safe: the unnest multiplies rows, and a plain `count(*)` would report scope-count times the token count.

### 6. Web UI delta

| File | Change |
|---|---|
| `components/RecentTasks.tsx` (new) | header **Recent tasks** with a **View all** link; one row per task: outcome dot (green all-issued, amber mixed, red all-denied), mono `{taskId}`, detail line `{scopes joined} · for {actorSub}` (scopes only when `actorSub` is null), relative `lastSeenAt`; clicking a row navigates to the Tokens page with `?taskId=` |
| `routes/t.$tenantId.tokens.tsx` | `validateSearch` gains `taskId`; render `<RecentTasks>` above the filter row; pass `taskId` into `useTokenEvents`; a dismissible `Task: {taskId}` chip beside the existing client chip (line 140) |
| `routes/t.$tenantId.applications.$appId.tsx` | for `kind === "agent"`, replace the "Recent tokens" card with `<RecentTasks applicationId={appId}>` (artboard 08, right column) |
| `components/TokenEventsTable.tsx` | new **Agent** column after Client, rendering `agent · for {actorSub}` when the event's application is an agent and `actorSub` is set, `agent` when the actor is unknown, and blank for service clients |

Knowing "is an agent" requires the kind: `useTokenApps` (`queries.ts:152`) changes its `select` from `Map<string, string>` to `Map<string, { name: string; kind: ApplicationKind }>`, with call sites in `t.$tenantId.tokens.tsx:147` and `TokenEventsTable.tsx:63` updated.

`queries.ts` additions: `useTasks(tenantId, { applicationId?, limit? })` on key `["tasks", { tenantId, applicationId }]` with `refetchInterval: 5000` to match the live Tokens page; `TokenEventParams` gains `taskId`.

### 7. Tests

`apps/api/src/routes/oauth/token.test.ts` and `apps/api/src/services/token-event.service.test.ts`:

1. `task_id=run_01JBXA3K` -> the JWT payload carries `task_id` and the `token_events` row stores it
2. no `task_id` -> the claim is absent (not null) and the column is null
3. `task_id` of 129 characters, and one containing a space -> 400 `invalid_request`, no token issued, one denied event
4. a denied request carrying `task_id` records it on the denied event
5. two issued events of one task group into one summary with `tokenCount: 2`, the union of both scope sets, `firstSeenAt` from the older and `lastSeenAt` from the newer
6. a task with one issued and one denied event reports `tokenCount: 2`, `deniedCount: 1`
7. the summary list is ordered by last activity descending and honours `applicationId`
8. an event backdated 25 hours is excluded from the summary list
9. `?taskId=` filters the events list to that task only
10. a task of tenant B never appears in tenant A's list (tenant isolation)
11. `limit=1` returns exactly one summary, the most recent

---

## 8. Task split and agent routing

One **sequenced schema slice** first, then everything else in parallel. This replaces the "6.1 lands first, 6.2 regenerates" plan from the task brief: three features touching `applications`, `token_events` and a new table would produce three migrations plus three Drizzle snapshots and journal entries, and the journal conflicts on every rebase. One generated migration removes that class of merge work entirely. If the orchestrator insists on per-task migrations instead, the fallback order is 6.1 `0002`, then 6.2 regenerates as `0003`, then 6.6 as `0004`.

| Slice | Agent | Files owned (exclusive) |
|---|---|---|
| **A — schema + shared contract** | Opus `developer` | `packages/db/src/schema/{application-keys.ts (new),applications.ts,token-events.ts,index.ts}`, `packages/db/drizzle/0002_*` + `meta/*` (generated), `packages/shared/src/constants/{oauth.ts,defaults.ts,regex.ts}`, `packages/shared/src/validation/{application.schema.ts,application-key.schema.ts (new),oauth.schema.ts,token-events.schema.ts,index.ts}`, `packages/shared/src/types/api.ts`, `packages/shared/src/validation/schemas.test.ts` |
| **B — 6.1 API** | Opus `developer` | `apps/api/src/services/{application-key.service.ts (new),client-auth.service.ts}` + tests, `apps/api/src/routes/oauth/{token.ts,discovery.ts}` + tests, `apps/api/src/routes/management/application-keys.ts (new)` + test, `apps/api/src/middleware/rate-limit.ts` |
| **C — 6.2 API** | Opus `developer` | `apps/api/src/services/{application.service.ts,token.service.ts}` + tests, `apps/api/src/utils/cidr.ts (new)` + test, `apps/api/src/routes/management/applications.ts` + test, `apps/api/src/middleware/error-handler.ts` |
| **D — 6.6 API** | Opus `developer` | `apps/api/src/services/token-event.service.ts` + test, `apps/api/src/routes/management/token-events.ts` + test |
| **E — applications UI (6.1 + 6.2)** | Sonnet `developer` | `apps/web/src/components/{RegisteredKeys.tsx,RegisterKeyDialog.tsx,AgentGuardrails.tsx,RuntimeBinding.tsx}` (new), `components/{ApplicationForm.tsx,GrantsMatrix.tsx}`, `routes/{t.$tenantId.applications.tsx,t.$tenantId.applications.$appId.tsx}` |
| **F — tokens UI (6.6)** | Sonnet `developer` | `apps/web/src/components/{RecentTasks.tsx (new),TokenEventsTable.tsx}`, `routes/t.$tenantId.tokens.tsx` |

Waves: **A alone**, then **B, C, D, E, F in one message**. E and F are written against this spec and only need a running API for their manual check at the end, so they do not wait on B/C/D.

Cross-slice edits, spelled out so no two agents open the same file:

- 6.6 needs three one-line hooks in files owned by B and C. **B** adds `taskId: parsed.data.task_id` to the `issueToken` call and `taskId: body?.task_id?.slice(0,128) ?? null` to the denied `recordTokenEvent` in `routes/oauth/token.ts`. **C** adds the `task_id` claim, the `taskId` event field and the `taskId?: string` request type in `token.service.ts`. Exact lines are in 6.6 section 5.
- The `no_application_key` guard belongs to 6.1 but lives in `application.service.ts`, so **C** implements it. B never opens that file.
- `routes/management/index.ts` is **not** touched: `applicationKeyRoutes` mounts from inside `routes/management/applications.ts` the way `grantRoutes` does (line 131). That file belongs to **C**, so C appends the one `route()` line and the import on B's behalf.
- `apps/web/src/lib/queries.ts` is the known web conflict point. Each of E and F appends its hooks as one contiguous block at the end of the file under a `// --- <feature> (Task 6.x)` banner, never reordering imports. Merge resolution per the established routine: main plus both appended blocks, with the `@handsal/shared` type imports unioned.
- `apps/web/src/routeTree.gen.ts` is regenerated by the router plugin and Biome-ignored; restore it from `git show HEAD:apps/web/src/routeTree.gen.ts` before rebasing. No new web route is added by any slice, so it should not change at all.

Per the project's worktree policy every slice runs in its own worktree, and every slice that runs integration tests needs its own `handsal_test_<slice>` database on port 5434 — tests `TRUNCATE` globally and two agents on one database produce flaky FK failures.

Review and verification: `code-reviewer` (Opus) on each landed slice, deepest pass on B and C (client authentication and a new denial path in the token-issuing path); then `verifier` running `pnpm check && pnpm typecheck && pnpm test` on the combined result with Postgres up and `pnpm db:migrate` applied.

Documentation follow-ups for `docs/integration.md` and `docs/deployment.md`, assignable to a Sonnet docs slice after F: the `private_key_jwt` assertion recipe, the per-process replay-cache limitation, and the `TRUST_PROXY` dependency of CIDR enforcement.

---

## 9. Risks and unknowns

- **CIDR enforcement is only as strong as `TRUST_PROXY`.** `getClientIp` derives the source IP from forwarded headers when configured. A deployment that proxies without setting `TRUST_PROXY_HOP_COUNT` correctly lets a caller spoof `X-Forwarded-For` and defeat `allowed_cidrs` entirely. This is the largest caveat in 6.2 and belongs in the deployment docs and in the UI helper text, not only in code.
- **Replay protection is per-process.** With more than one replica an assertion can be replayed once per replica inside its 5-minute-or-less lifetime. Acceptable given `Tasks.md` already defers the Redis store, but it must be documented rather than implied.
- **Budget is advisory under concurrency.** Burst traffic at the boundary can exceed the configured budget by the number of in-flight requests.
- **`aud` strictness may break real clients.** Requiring the token endpoint URL and rejecting the issuer identifier is the narrower reading of RFC 7523 section 3. Some client libraries default to the issuer. Discovery advertises the token endpoint, so a correct client can find it, but expect support questions; relaxing to accept either value later is a one-line change to the `audience` option.
- **Unverified checks before verification.** Steps 1-5 of the assertion flow read the header and payload without checking the signature, which is unavoidable (the key is selected by `iss`/`kid`). Nothing is persisted and no distinguishing response is returned before step 6, but a reviewer should confirm that the error for every pre-verification failure is the same opaque 401.
- Not verified by running code: `net.BlockList.check` behaviour for IPv4-mapped IPv6 inputs is handled here by explicit normalisation rather than by relying on Node's mapping rules; the `cidr.test.ts` IPv4-mapped case is the gate on that assumption.
- Not verified: whether Hono's route matching registers `/token-events/tasks` ahead of any future `/token-events/:id` pattern. Today no such pattern exists, so append-order is safe; a later slice adding one must register it after `tasks`.
- The tasks grouping query was reasoned about but not run against a populated table. The lateral-unnest plus `count(distinct id)` shape is the load-bearing detail and test 6 of 6.6 is what proves it.


---

# Part 2 — 6.3, 6.4, 6.5


> Written against `main` at 2026-11-06. Assumes **6.1** (`application_keys`, `private_key_jwt`) and **6.2** (`kind:'agent'` creatable; `applications.agent_runtime | operator_email | allowed_cidrs text[] | max_scopes_per_token | token_budget_per_hour`; optional `task_id` form param → `token_events.task_id` + `task_id` JWT claim) have landed. Migration numbers below assume 6.1 = `0002`, 6.2 = `0003`; **never hand-pick a number** — rebase onto `main`, then `pnpm db:generate`.

---

## 6.3 — Scope ceiling with human approval

### Decision summary

- `scopes.agent_policy = 'approval'` becomes enforcing. A token request from an application with `kind='agent'` that resolves to ≥1 `approval` scope does not issue a token. It creates an `approval_requests` row and answers `400 {error:"authorization_pending", error_description, approval_id, interval:5}`.
- The agent polls `POST /t/:slug/oauth/token` with `grant_type=urn:handsal:params:grant-type:approval` + `approval_id`. Client auth is still required and must be the same application in the same tenant.
- Approval issues **exactly one** token, TTL **300 s**, with the scopes recorded on the row. The row stays `approved` and gets `consumed_at`; the next poll is `invalid_grant`.
- **Mixed requests go entirely pending.** A token carries one `scope` string and one TTL; splitting would mean either two tokens or silently dropping the approval scope with no signal to poll. The approved token then carries exactly what was asked for.
- Consequence to document: an agent that omits `scope` requests all its granted scopes, so one `approval` scope in its grants sends every request to the queue. That is the intended pressure toward explicit least-privilege ("Forces least-privilege requests", artboard 08).
- `slow_down` is **omitted**: it needs per-approval last-poll state, and the existing per-`client_id` limit (600/min) already bounds polling. Say so in the docs.
- Out of scope: editing scopes while approving (artboard 09 offers only "Approve once" / "Deny"), approval of non-agent applications, approval + token exchange (see 6.4), notifications and rules (6.5).
- **Dependency:** 6.3 is only exercisable through the UI if something can set `agent_policy='approval'`. 6.2 owns the Scope ceiling section of artboard 08. If 6.2 shipped it read-only, 6.3 must add the Agent policy cell to `apps/web/src/components/ScopeTable.tsx` (the column artboard 05 omitted for MVP).

### Schema delta

New file `packages/db/src/schema/approval-requests.ts`; export from `packages/db/src/schema/index.ts` (append). Migration `packages/db/drizzle/0004_<name>.sql` via `pnpm db:generate`.

| Column | Type / rule |
|---|---|
| `id` | `uuid pk default gen_random_uuid()` |
| `tenant_id` | `uuid not null references tenants(id) on delete cascade` |
| `application_id` | `uuid not null`; composite FK `(tenant_id, application_id) → applications(tenant_id, id) on delete cascade` |
| `resource_id` | `uuid not null`; composite FK `(tenant_id, resource_id) → resources(tenant_id, id) on delete cascade` |
| `audience` | `varchar(512) not null` (denormalised: survives a resource rename) |
| `scopes` | `text[] not null default '{}'::text[]` — scope **names** |
| `actor_hint` | `varchar(255) null` |
| `task_id` | `varchar(128) null` |
| `justification` | `text null` |
| `status` | new `pgEnum approval_status ('pending','approved','denied','expired')`, `not null default 'pending'` |
| `expires_at` | `timestamptz not null` |
| `decided_by` | `uuid null references admin_users(id) on delete set null` — the human who decided |
| `decided_at` | `timestamptz null` |
| `consumed_at` | `timestamptz null` |
| `created_at` / `updated_at` | `timestamptz not null default now()`, `updated_at` with `$onUpdate` |

Indexes: `index("idx_approval_requests_tenant_status").on(tenantId, status, createdAt.desc())`, `index("idx_approval_requests_application_id").on(applicationId)`.

`decided_by` is an FK to `admin_users` rather than the free-text `decided_by` sketched in `Tasks.md`: the artboard's "Decided by" column needs the admin's **name**, and an FK gives it with a left join instead of parsing `user:<uuid>` strings. `status='expired'` and an API-key actor both leave it null; the DTO derives the label (see below).

Also in `0004`: `ALTER TYPE token_event_outcome ADD VALUE 'pending'` (edit `packages/db/src/schema/token-events.ts`, regenerate). PostgreSQL 16 permits `ADD VALUE` inside the migration transaction as long as the value is not used in the same transaction, which it is not.

### Shared package delta

`packages/shared/src/constants/oauth.ts` (append):

```ts
export const GRANT_TYPES = {
  CLIENT_CREDENTIALS: "client_credentials",
  APPROVAL: "urn:handsal:params:grant-type:approval",
} as const;
export const OAUTH_ERRORS = { /* … */ AUTHORIZATION_PENDING: "authorization_pending",
  ACCESS_DENIED: "access_denied", EXPIRED_TOKEN: "expired_token" } as const;
export const APPROVAL_STATUSES = { PENDING: "pending", APPROVED: "approved",
  DENIED: "denied", EXPIRED: "expired" } as const;
export const DEFAULTS = { /* … */ APPROVAL_TTL_SECONDS: 1800, APPROVAL_TOKEN_TTL_SECONDS: 300,
  APPROVAL_POLL_INTERVAL_SECONDS: 5, APPROVALS_PAGE_SIZE: 50 } as const;
export const TOKEN_EVENT_OUTCOMES = { /* … */ PENDING: "pending" } as const;
```

New `packages/shared/src/validation/approval.schema.ts` (export from `validation/index.ts`):

- `approvalGrantSchema = z.object({ approval_id: z.uuid() })` — form fields.
- `approvalRequestExtraSchema = z.object({ actor_hint: z.string().max(255).optional(), justification: z.string().max(2000).optional() })` — the optional form params on the *first* request.
- `approvalsQuerySchema = z.object({ status: z.enum(["pending","resolved"]).default("pending"), cursor: z.string().max(256).optional(), limit: z.coerce.number().int().min(1).max(100).default(50) })`.
- `approvalDtoSchema`: `{ id, applicationId, applicationName, clientId, audience, scopes: string[], actorHint, taskId, justification, status, expiresAt, createdAt, decidedAt, decidedBy: { kind: "user"|"rule"|"api-key", label: string } | null }`.
- `approvalCountsDtoSchema`: `{ pending, oldestPendingAt: string|null, approvedToday, deniedToday, medianWaitSeconds: number|null }`.

`token-events.schema.ts`: add `"pending"` to the `outcome` enum in both `tokenEventDtoSchema` and `tokenEventsQuerySchema` (required for `pnpm typecheck` to pass once the pg enum grows). `packages/shared/src/types/api.ts`: `ApprovalDto`, `ApprovalCountsDto`.

### API delta

**OAuth, first request** (no new route; a branch in `POST /t/:slug/oauth/token`). Response body is 400 with the standard OAuth envelope plus two fields:

```json
{ "error": "authorization_pending",
  "error_description": "Waiting for human approval of one or more requested scopes",
  "approval_id": "<uuid>", "interval": 5 }
```

Headers `Cache-Control: no-store`, `Pragma: no-cache`. Returned directly from the route handler, **not** thrown: `errorHandler` emits only `{error, error_description}`, and the pending path must record a `pending` token event rather than the `denied` one the catch block writes.

**OAuth, polling** — `grant_type=urn:handsal:params:grant-type:approval`, body `approval_id`, client auth as usual, `resource`/`scope` not accepted (they come from the row).

| Condition | Response |
|---|---|
| row `pending`, not expired | `400 authorization_pending` + `approval_id`, `interval: 5` |
| row `denied` | `400 {error:"access_denied"}` |
| row `expired`, or `expires_at <= now()` | `400 {error:"expired_token"}` |
| row `approved`, `consumed_at is null` | `200` normal token response, `expires_in: 300` |
| row `approved`, already consumed | `400 {error:"invalid_grant"}` |
| unknown id, other tenant, other application | `400 {error:"invalid_grant"}` — one answer, no existence oracle |

**Management** (new `apps/api/src/routes/management/approvals.ts`, mounted `managementRoutes.route("/tenants", approvalRoutes)`):

| Method / path | Role | Request | Response |
|---|---|---|---|
| `GET /api/tenants/:tenantId/approvals` | auditor | `approvalsQuerySchema` | `200 { items: ApprovalDto[], nextCursor, counts: ApprovalCountsDto }` |
| `POST /api/tenants/:tenantId/approvals/:approvalId/approve` | admin | — | `200 ApprovalDto` · `404 approval_not_found` · `409 approval_already_decided` · `409 approval_expired` |
| `POST /api/tenants/:tenantId/approvals/:approvalId/deny` | admin | — | same |

`requireTenantAccess("admin")` gives owner access and 403s auditors for free. Counts are embedded in the list response rather than a second endpoint: one route, one query hook, and the sidebar badge reuses it (`?status=pending&limit=1` → `counts.pending`). `status=pending` also requires `expires_at > now()` so a dead card never shows between expiry-job runs; `status=resolved` is `status in ('approved','denied','expired')`. Cursor is base64url `created_at|id` keyset on `(created_at desc, id desc)`, same shape as `token-event.service.ts:29` but with a uuid id.

`medianWaitSeconds` = `percentile_cont(0.5) within group (order by extract(epoch from (decided_at - created_at)))` over rows decided in the last 24 h; "today" means the last 24 h, matching the Tokens page and avoiding a tenant-timezone question.

### Service logic

New `apps/api/src/services/approval.service.ts`.

**A. `token.service.ts` restructure.** Replace the single-purpose `never` lookup at `apps/api/src/services/token.service.ts:54-74` with one query returning `{id, name, agentPolicy}` for `tokenScopes`, then extract the signing block (lines 76-122) into a private `signAndRecord(tenant, application, { resource, scopes, ttlSeconds, extraClaims?, eventFields? })`. Three callers will share it (client_credentials, approval redemption, 6.4 exchange); without the extraction the claims block gets copied three times.

Order inside `issueToken`, unchanged above the new step:

1. tenant paused → `invalid_request`
2. resource resolution → `invalid_target`
3. requested ⊆ granted → `invalid_scope`
4. 6.2 guardrails: `max_scopes_per_token`, `token_budget_per_hour`, `allowed_cidrs` → deny **before** step 5, so a request that would fail anyway never reaches the human queue
5. agent + any `never` scope → `invalid_scope`
6. **new:** agent + any `approval` scope → `createApprovalRequest(...)`, return the pending marker
7. `signAndRecord`

**B. `createApprovalRequest(tenant, application, { resource, audience, scopes, actorHint, taskId, justification }, ctx)`**

- Reuse an existing row first: `select` where `tenant_id`, `application_id`, `resource_id`, `status='pending'`, `expires_at > now()`, `scopes = $scopes` (array equality), `task_id is not distinct from $taskId`. Hit → return its id. This keeps one card per task in the queue when an agent re-sends the original request instead of polling, and costs one `SELECT` instead of a dedup rate limiter. Two concurrent first-requests can still create two rows; harmless, and cheaper than a partial unique index over an array column.
- Else insert with `expires_at = now() + interval '30 minutes'`, then `recordTokenEvent({ outcome: "pending", scopes, resourceId, audience, taskId, … })` inside this service, where the resolved scopes are known. The catch block in `routes/oauth/token.ts` must skip its `denied` event for this path.

**C. `redeemApproval(tenant, application, approvalId, ctx)`**

1. Atomic claim: `UPDATE approval_requests SET consumed_at = now() WHERE id = $1 AND tenant_id = $2 AND application_id = $3 AND status = 'approved' AND consumed_at IS NULL AND expires_at > now() RETURNING *`. One statement, so concurrent polls cannot both win and no transaction is needed.
2. 0 rows → re-read by `(id, tenant_id, application_id)` and map to `authorization_pending` / `access_denied` / `expired_token` / `invalid_grant` per the table above.
3. Re-check `getGrantedScopesForAudience`: the resource must still be `active` and every approved scope still granted, else `invalid_grant`. An admin can revoke a grant during the 30-minute window.
4. `signAndRecord(..., ttlSeconds: 300)`.
   Trade-off: if signing fails after step 1 the approval is burned and the agent must request again. Accepted — the alternative is a transaction held across an EC key operation.

**D. `decideApproval(tenantId, approvalId, decision, actor)`** — `UPDATE … SET status=$decision, decided_by=$userId, decided_at=now() WHERE id AND tenant_id AND status='pending' AND expires_at > now() RETURNING *`; 0 rows → re-read → `404 approval_not_found` or `409`. `decided_by` is null for an `ADMIN_API_KEY` actor; the DTO then reports `{kind:"api-key", label:"API key"}`.

**E. Expiry job** — `apps/api/src/jobs/approval-expiry.job.ts`, `intervalMs: 60_000`, `UPDATE approval_requests SET status='expired' WHERE status='pending' AND expires_at <= now()`; append to the `jobs` array in `apps/api/src/jobs/index.ts`. The job exists so expired rows reach the Resolved tab; the poll path checks `expires_at` itself and does not depend on it.

**F. Discovery** — `routes/oauth/discovery.ts`: append the approval URN to `grant_types_supported`.

### Web UI delta

- **New route** `apps/web/src/routes/t.$tenantId.approvals.tsx`. `validateSearch` → `{ tab?: "pending" | "resolved" }`, default `pending`. Let Vite regenerate `routeTree.gen.ts`; never hand-edit it.
- **New components** `ApprovalCard.tsx`, `ResolvedApprovalsTable.tsx`. Reuse `StatTile`, `Button`, `EmptyState`, `Table`.
- **Copy, verbatim from artboard 09:** H1 "Approvals"; sub "Agents asking for scopes marked "human approval". The token is issued only after someone here says yes."; tabs "Pending" / "Resolved"; right-aligned note "Approving once issues a single 5-minute token. Nothing is granted permanently from here."
- **Tiles (3):** "Waiting now" (accent value, sub "oldest {relative}"), "Approved today" (sub "{n} denied"), "Median wait" (value + small "min" unit, sub "requests expire after 30 min"). The 4th tile ("Auto-approve rules") and the header "Notify via Slack" button arrive in 6.5.
- **Card:** `{agentName}` (link to the app detail) · "wants" · scope chips (amber `#FEF3C7`/`#92400E`, mono) · "on" · `{audience}` mono; justification block labelled "Agent's justification"; meta row "On behalf of {actorHint}", "Task {taskId}", "Requested {when}", "Expires in {x}"; buttons "Approve once" (accent, primary) and "Deny" (outline), link "Inspect run" → `/t/$tenantId/tokens?applicationId=…`. Empty state: "Queue is clear" / "New requests for marked scopes will appear here." (6.5 restores the artboard's "…and in Slack").
- **Resolved table columns:** Time, Decision, Agent, Scope, On behalf of, Decided by (right-aligned). Badge palette: Approved / Auto-approved `#15803D` on `#ECFDF3`; Denied `#B91C1C` on `#FEF2F2`; Expired `#6B6B76` on `#F1F1F3`. `decidedBy === null` renders "—".
- **Sidebar** `apps/web/src/components/TenantSidebar.tsx`: new `NAV` entry between Tokens and Settings, label "Approvals", icon paths `M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3z` + `M9 12l2 2 4-4`, plus `badge: true`. Render the pill (`bg-[#EEF1FF] text-[#3730A3] text-[11px] font-semibold px-[7px] rounded-full`) only when `count > 0`.
- **`apps/web/src/lib/queries.ts`** — append a `// --- approvals (Task 6.3)` section at the end of the file, matching the `// --- token events (Task 4.4)` convention at line 119: `useApprovals(tenantId, status)` (infinite query, `refetchInterval: 10_000`), `useApprovalCounts(tenantId)` (`?status=pending&limit=1`, `refetchInterval: 30_000`, used by the sidebar), `useDecideApproval(tenantId)` (invalidates both keys).
- `TokenEventsTable.tsx`: a badge style for the new `pending` outcome.

### Tests

Integration, real Postgres, each agent on its own `TEST_DATABASE_URL` (db name must end in `_test`).

`apps/api/src/services/approval.service.test.ts`
- `creates a pending row and records a pending token event` — one row, `expires_at ≈ now()+30min`, one `token_events` row with `outcome='pending'` and the resolved scopes.
- `reuses the pending row for an identical repeated request` — second call returns the same id, still one row.
- `mixed auto and approval scopes go pending as a whole` — row `scopes` equals every requested scope.
- `never beats approval` — a request with both a `never` and an `approval` scope is `invalid_scope`, no row created.
- `redeem issues exactly one token` — first poll 200, second poll `invalid_grant`, exactly one `issued` token event.
- `redeemed token has TTL 300 and the approved scopes` — `expires_in === 300`, verified payload `scope`.
- `grant revoked during the window → invalid_grant`.
- `expired row → expired_token` (set `expires_at` in the past).
- `denied row → access_denied`.

`apps/api/src/routes/oauth/token.test.ts` (append)
- `approval_id from another tenant → invalid_grant`.
- `another application polling someone else's approval → invalid_grant`.
- `pending response carries approval_id and interval` — body has both, status 400, `Cache-Control: no-store`.

`apps/api/src/routes/management/approvals.test.ts`
- `approve twice → 409` (`approval_already_decided`).
- `auditor approve → 403`; `auditor list → 200`.
- `non-member → 404 on list and approve`.
- `approval of another tenant's id → 404`.
- `pending list excludes rows past expires_at`; `resolved list includes expired`.
- `counts match the seeded rows` (pending, approvedToday, deniedToday).
- `cursor returns the next page without overlap`.

`apps/api/src/jobs/approval-expiry.job.test.ts` — `marks only overdue pending rows expired`.

### Task split

| Slice | Agent | Files owned |
|---|---|---|
| 6.3a schema + migration | Opus `developer` | `packages/db/src/schema/approval-requests.ts`, `schema/token-events.ts`, `schema/index.ts`, `drizzle/0004_*.sql`, `packages/db/src/schema.test.ts` |
| 6.3b shared | Sonnet `developer` | `packages/shared/src/validation/approval.schema.ts` (+test), `validation/index.ts`, `constants/oauth.ts`, `constants/defaults.ts`, `validation/token-events.schema.ts`, `types/api.ts` |
| 6.3c service + oauth grant | Opus `developer` | `services/approval.service.ts` (+test), `services/token.service.ts`, `routes/oauth/token.ts` (+test), `routes/oauth/discovery.ts`, `jobs/approval-expiry.job.ts`, `jobs/index.ts` |
| 6.3d management routes | Opus `developer` | `routes/management/approvals.ts` (+test), `routes/management/index.ts` |
| 6.3e web | Sonnet `developer` | `routes/t.$tenantId.approvals.tsx`, `components/ApprovalCard.tsx`, `components/ResolvedApprovalsTable.tsx`, `components/TenantSidebar.tsx`, `components/TokenEventsTable.tsx`, `lib/queries.ts` (append-only), `lib/types.ts` |

6.3a and 6.3b run in parallel. 6.3c and 6.3d then run in parallel (6.3d only reads the service). 6.3e starts once 6.3b lands and stubs nothing else. Conflict points: `routes/management/index.ts` (append one import + one `.route()` line at the end of the mount list), `lib/queries.ts` and `jobs/index.ts` (append only), `routeTree.gen.ts` (regenerated, never edited).

---

## 6.4 — Token exchange (RFC 8693)

### Decision summary

- `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` on the existing token endpoint. Only applications with `kind='agent'` and a non-empty `may_act_for` may use it; everyone else gets `unauthorized_client`.
- Accepted subject tokens: Handsal access tokens of the **same tenant**, and JWTs from **one** external IdP configured per tenant. `actor_token` / `actor_token_type` are **out of scope** and rejected explicitly with `invalid_request`.
- `resource` stays required (the product-wide audience rule). The issued token's `sub` is the subject's `sub`; `act.sub` is the agent's `client_id`, nested when the subject already carries `act`.
- Scope is computed per the agent's `delegation_scope_mode`: `intersection` (default) or `agent_only`.
- TTL follows the existing precedence (`application ?? resource ?? tenant`). No special rule; an agent configured at 300 s reproduces the artboard's "ES256 · 300 s".
- An exchange that resolves to an `approval` scope is **refused** with `invalid_scope`, not queued. Approving minutes later would mint a delegated token whose subject credential can no longer be verified, which would silently defeat revocation of the subject token.
- **The artboard's claims preview is RFC-inverted.** `Agent.dc.html` shows `"sub": "svc_agent_44f1"` with `"act": {"sub": "user_9f2d"}`. RFC 8693 §4.1 makes `act` the *acting* party, so the implementation and the preview UI must both show `sub` = the subject and `act.sub` = the agent.

### Schema delta

Migration `0005_<name>.sql`. Edit `packages/db/src/schema/applications.ts`:

- ``mayActFor: text("may_act_for").array().notNull().default(sql`'{}'::text[]`)`` — allowed members `users | tenant | services`, validated by Zod. `text[]` rather than an enum array because `users` (external identities) and `services`/`tenant` (internal clients) are orthogonal, and Drizzle enum arrays are awkward to query.
- `delegationScopeMode: delegationScopeMode("delegation_scope_mode").notNull().default("intersection")`, new `pgEnum delegation_scope_mode ('intersection','agent_only')`. `intersection` is the narrower default.

`packages/db/src/schema/tenants.ts`: `externalIdp: jsonb("external_idp")`, nullable, shape `{ issuer: string, jwksUri: string, audience: string }`. One configured issuer per tenant, not a `trusted_issuers` table: no new table, no CRUD routes, no join. `shortcut: one external issuer per tenant; promote to a trusted_issuers table when a tenant needs two`.

`packages/db/src/schema/token-events.ts`: `actor_sub` **already exists** (added by 6.6 in migration 0002, nullable, written nowhere until now); 6.4 is the only writer, from the subject token's `sub`. No schema change here. Without it the delegation leaves no trace once the JWT expires, which is an audit gap in a security product; 6.6's "agent · for <actor>" column also reads it. Exchanged tokens keep `outcome='issued'` — **no new enum value** — and are identified by `actor_sub is not null`.

6.4 regenerates its migration after rebasing onto the landed 6.3.

### Shared package delta

```ts
export const GRANT_TYPES = { /* … */ TOKEN_EXCHANGE: "urn:ietf:params:oauth:grant-type:token-exchange" };
export const TOKEN_TYPE_URNS = {
  ACCESS_TOKEN: "urn:ietf:params:oauth:token-type:access_token",
  JWT: "urn:ietf:params:oauth:token-type:jwt",
} as const;
export const MAY_ACT_FOR = { USERS: "users", TENANT: "tenant", SERVICES: "services" } as const;
export const DELEGATION_SCOPE_MODES = { INTERSECTION: "intersection", AGENT_ONLY: "agent_only" } as const;
```

`validation/oauth.schema.ts`: `tokenExchangeSchema = z.object({ subject_token: z.string().min(1).max(8192), subject_token_type: z.enum([TOKEN_TYPE_URNS.ACCESS_TOKEN, TOKEN_TYPE_URNS.JWT]), resource: z.string().min(1).max(512), scope: z.string().optional(), task_id: z.string().max(128).optional() })`.

`validation/application.schema.ts`: `applicationUpdateSchema` gains `mayActFor: z.array(z.enum(["users","tenant","services"])).max(3).optional()` and `delegationScopeMode: z.enum(["intersection","agent_only"]).optional()`; `applicationDtoSchema` gains both fields.

`validation/tenant.schema.ts`: `externalIdpSchema = z.object({ issuer: z.url(), jwksUri: z.url(), audience: z.string().min(1).max(512) })`; `tenantUpdateSchema` gains `externalIdp: externalIdpSchema.nullable().optional()`; `tenantDtoSchema` gains `externalIdp: externalIdpSchema.nullable()`.

### API delta

**Request** (form-encoded, client auth as usual): `grant_type`, `subject_token`, `subject_token_type`, `resource`, optional `scope`, optional `task_id`. `actor_token` or `actor_token_type` present → `400 invalid_request` "actor_token is not supported".

**Response** `200`:

```json
{ "access_token": "…", "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer", "expires_in": 300, "scope": "tools:tickets.read tools:tickets.create" }
```

| Error | Status | When |
|---|---|---|
| `invalid_request` | 400 | missing/unsupported `subject_token_type`, `actor_token` present |
| `unauthorized_client` | 400 | `kind !== 'agent'`, or `may_act_for` empty, or the subject's class is not in `may_act_for` |
| `invalid_grant` | 400 | subject token fails verification, is expired, revoked, `iat < not_before`, belongs to another tenant, or comes from an unconfigured issuer |
| `invalid_target` | 400 | `resource` unknown in the tenant or not granted to the agent |
| `invalid_scope` | 400 | requested ⊄ computed set, computed set empty, intersection mode with no scopes on the subject, or an `approval` scope is involved |

Management: no new routes. `mayActFor`, `delegationScopeMode` ride on `PATCH /api/tenants/:tenantId/applications/:appId`; `externalIdp` on `PATCH /api/tenants/:tenantId`. `routes/oauth/discovery.ts` appends the exchange URN to `grant_types_supported`.

### Service logic

New `apps/api/src/services/token-exchange.service.ts`, called from `routes/oauth/token.ts` after client auth (the branch added next to 6.3's).

1. `application.kind === "agent"` and `mayActFor.length > 0`, else `unauthorized_client`.
2. **Classify and verify the subject.** First try Handsal: `introspectToken(tenant, subject_token)` from `apps/api/src/services/introspection.service.ts:82`. It already covers the tenant JWKS including retiring keys, revocation, both `tokens_not_before` marks, disabled applications and paused tenants. `active === true` → class is `services` when `client_kind === 'service'`, and `tenant` otherwise; require `mayActFor` to contain that class (`tenant` also admits `services`). Otherwise fall back to the external IdP: `tenant.externalIdp` must be set, and `jwtVerify(token, getRemoteJwks(jwksUri), { issuer, audience })` must pass → class `users`. Neither → `invalid_grant`.
   `getRemoteJwks` is a module-level `Map<string, ReturnType<typeof createRemoteJWKSet>>` keyed by `jwksUri`; jose's remote set does its own caching and cooldown, so no new dependency and no cache code (jose 6.2 is already in `apps/api/package.json`).
3. Resolve the target: `getGrantedScopesForAudience(tenant.id, application.id, resource)`; null or not `active` → `invalid_target`.
4. **Compute scopes.**
   - `agent_only`: `base = agentGranted`.
   - `intersection`: `subjectScopes` from the subject's `scope` claim (space-split) or `scp` (array) — accept both, since external IdPs differ; neither present → `invalid_scope`. `base = agentGranted ∩ subjectScopes`; empty → `invalid_scope`.
   - Explicit `scope` param must be a subset of `base`, else `invalid_scope`; omitted → `base`.
5. Guardrails from 6.2 (`max_scopes_per_token`, `token_budget_per_hour`, `allowed_cidrs`) apply unchanged; reuse the same helper `issueToken` calls.
6. Any resulting scope with `agent_policy='approval'` → `invalid_scope` "scope requires human approval; request it with the approval grant". `never` → `invalid_scope` as today.
7. **Claims.** `act = subjectAct ? { sub: agentClientId, act: subjectAct } : { sub: agentClientId }` (most recent actor outermost, RFC 8693 §4.1). `sub = subject.sub`. `client_id`, `client_kind`, `tenant`, `aud`, `jti`, `iat`, `exp` unchanged — so `introspectToken` and `revokeToken`, which key off `client_id`, keep working on exchanged tokens.
8. `signAndRecord(..., extraClaims: { act, task_id }, eventFields: { actorSub: subject.sub })` — the helper 6.3c extracts.

### Web UI delta

`apps/web/src/routes/t.$tenantId.applications.$appId.tsx` — append a **Delegation** section below 6.2's Guardrails, agent kind only. 6.4 runs after 6.2; expect to rebase this file.

- Section copy from artboard 08: "Delegation" / "Let the agent act on behalf of a user or another service via token exchange (RFC 8693). The token carries both identities."
- "May act for" — three **checkboxes**, not the artboard's radios, because `may_act_for` is an array: "Users from the configured identity provider" (`users`), "Any client in this tenant" (`tenant`), "Service clients only" (`services`). The artboard's app-specific labels ("Users of the Support app") are mockup data.
- "Resulting scopes" — two radios: "Intersection of user's and agent's scopes" (`intersection`), "Agent's scopes only" (`agent_only`).
- "Token claims preview" with the "ES256 · {ttl} s" chip — a static JSON block computed client-side from the loaded application (client id, granted scope names, mode). No API call. Render `sub` as a placeholder subject (`user_…`) and `act: { sub: <clientId> }`, i.e. the corrected shape, not the artboard's.
- `lib/queries.ts`: extend the existing `useUpdateApplication` payload type; no new hook.
- `externalIdp` is **API-only** in 6.4 (`PATCH /api/tenants/:tenantId`) plus a short `docs/integration.md` section. No Settings UI; artboard 07 does not show the field.

### Tests

`apps/api/src/services/token-exchange.service.test.ts`
- `exchanges a Handsal service token and nests nothing` — `act === { sub: agentClientId }`, `sub === subject.sub`.
- `nests act when the subject already carries one` — `act === { sub: agent, act: { sub: firstAgent } }`.
- `revoked subject token → invalid_grant`.
- `subject token from another tenant → invalid_grant`.
- `subject token issued before tokens_not_before → invalid_grant`.
- `intersection mode narrows to the overlap`; `intersection with no overlap → invalid_scope`; `intersection with a scopeless subject → invalid_scope`.
- `agent_only ignores the subject's scopes`.
- `accepts scp as an array from an external IdP` (local JWKS stub served by a Hono app, `externalIdp.jwksUri` pointed at it).
- `external subject rejected when may_act_for lacks users → unauthorized_client`.
- `non-agent application → unauthorized_client`.
- `foreign resource → invalid_target`; `approval scope → invalid_scope`.
- `records actor_sub on the token event`.

`apps/api/src/routes/oauth/token.test.ts` — `actor_token present → invalid_request`; `unknown subject_token_type → invalid_request`; `response carries issued_token_type`.

### Task split

| Slice | Agent | Files owned |
|---|---|---|
| 6.4a schema + shared | Sonnet `developer` | `packages/db/src/schema/{applications,tenants,token-events,index}.ts`, `drizzle/0005_*.sql`, `packages/shared/src/{constants/oauth.ts,validation/{oauth,application,tenant}.schema.ts,types/api.ts}` |
| 6.4b exchange service + route | Opus `developer` | `services/token-exchange.service.ts` (+test), `routes/oauth/token.ts` (+test), `routes/oauth/discovery.ts`, `services/token.service.ts` |
| 6.4c management passthrough | Sonnet `developer` | `services/application.service.ts`, `services/tenant.service.ts` (DTO + update fields), their tests |
| 6.4d web delegation section | Sonnet `developer` | `routes/t.$tenantId.applications.$appId.tsx`, `lib/queries.ts` (append) |

6.4a first (everything types off it), then 6.4b ∥ 6.4c ∥ 6.4d. `routes/oauth/token.ts` and `services/token.service.ts` are owned by 6.4b alone and must be rebased onto 6.3's landed version before editing.

---

## 6.5 — Approval notifications + auto-approve rules

### Decision summary

- `approval_rules` lets a tenant auto-approve matching requests. A matching rule creates the row already `approved` with `decided_by_rule_id` set; the agent **still polls once**, with `interval: 0` in the pending response.
- That keeps one issuance site, one consumption site and one client contract: every approval-scope request is pending-then-poll whether a human or a rule decided. Issuing inside the original request would duplicate the token issuance and the single-use bookkeeping, and the one-token invariant would then live in two places. `interval: 0` tells a compliant client to poll immediately, so the latency cost is a round trip, not 5 s.
- Condition language, all-of (AND) semantics, `{}` matches always: `{ "application_ids"?: uuid[], "task_id_prefix"?: string, "max_scopes"?: int }`. Evaluated in JS against the in-memory candidate, not in SQL.
- Notifications: `tenants.approval_webhook_url` + optional secret, fired async with one retry when a row is created `pending`. Rule-approved rows fire nothing.
- Rules are **API-only** in 6.5 plus a `docs/agents.md` section. Artboard 09 shows a rules count tile and a `#rules` anchor but no rules editor, and the brief prefers API-only. Webhook configuration is likewise API-only; the artboard's "Notify via Slack" button is a label, not a form. Flagged gap: a self-hosted admin cannot configure either from the UI until a follow-up task adds a Settings section.
- Out of scope: per-rule amount/condition DSL beyond the three keys, rule ordering/priority (first match wins by `created_at`), webhook delivery log, Slack interactive buttons.

### Schema delta

Migration `0006_<name>.sql`. New `packages/db/src/schema/approval-rules.ts`:

| Column | Type / rule |
|---|---|
| `id` | `uuid pk default gen_random_uuid()` |
| `tenant_id` | `uuid not null references tenants(id) on delete cascade` |
| `scope_id` | `uuid not null`; composite FK `(tenant_id, scope_id) → scopes(tenant_id, id) on delete cascade` |
| `condition` | `jsonb not null default '{}'::jsonb` |
| `action` | new `pgEnum approval_rule_action ('auto_approve')`, `not null default 'auto_approve'` |
| `created_by` | `uuid null references admin_users(id) on delete set null` |
| `created_at` / `updated_at` | as elsewhere |

Index: `index("idx_approval_rules_tenant_scope").on(tenantId, scopeId)`.

`packages/db/src/schema/approval-requests.ts`: add `decidedByRuleId: uuid("decided_by_rule_id")` with `references(() => approvalRules.id, { onDelete: "set null" })`. A rule decision sets it; a human decision sets `decided_by`; an expiry sets neither.

`packages/db/src/schema/tenants.ts`: `approvalWebhookUrl: varchar("approval_webhook_url", { length: 2048 })`, `approvalWebhookSecretEnc: text("approval_webhook_secret_enc")`, both nullable. The secret is an HMAC key, so it cannot be hashed; store it with the existing `encryptPrivateKey` / `decryptPrivateKey` (`apps/api/src/utils/crypto.ts`, AES-256-GCM over a string) rather than in plaintext, and never return it — the DTO exposes `approvalWebhookSecretSet: boolean`.

### Shared package delta

New `packages/shared/src/validation/approval-rule.schema.ts`:

- `approvalConditionSchema = z.object({ application_ids: z.array(z.uuid()).max(50).optional(), task_id_prefix: z.string().min(1).max(128).optional(), max_scopes: z.number().int().min(1).max(50).optional() }).strict()`.
- `approvalRuleCreateSchema = z.object({ scopeId: z.uuid(), condition: approvalConditionSchema.default({}) })`.
- `approvalRuleDtoSchema = { id, scopeId, scopeName, resourceName, condition, action: "auto_approve", createdBy: string|null, createdAt }`.
- `tenantUpdateSchema` gains `approvalWebhookUrl: z.url().max(2048).nullable().optional()` and `approvalWebhookSecret: z.string().min(16).max(255).nullable().optional()`. URL must be `https://` in production; allow `http://` only when the API's `NODE_ENV !== "production"` (refine in the API route, which has `env`). This is admin-configured outbound request destination control, the minimum SSRF guard worth keeping.
- `approvalDtoSchema.decidedBy.kind` gains `"rule"`; `approvalCountsDtoSchema` gains `rules: number`.

### API delta

| Method / path | Role | Request | Response |
|---|---|---|---|
| `GET /api/tenants/:tenantId/approval-rules` | auditor | — | `200 { items: ApprovalRuleDto[] }` |
| `POST /api/tenants/:tenantId/approval-rules` | admin | `approvalRuleCreateSchema` | `201 ApprovalRuleDto` · `400 invalid_scope_ids` when the scope is not in the tenant · `409 approval_rule_exists` on a duplicate `(scope_id, condition)` |
| `DELETE /api/tenants/:tenantId/approval-rules/:ruleId` | admin | — | `204` · `404 approval_rule_not_found` |

No PATCH: delete and recreate. New file `apps/api/src/routes/management/approval-rules.ts`, appended to the mount list in `routes/management/index.ts`. `GET …/approvals` gains `counts.rules`.

Webhook delivery, `POST <approval_webhook_url>`:

```
Content-Type: application/json
X-Handsal-Signature: sha256=<hex hmac-sha256 of the exact request body, keyed by the secret>
X-Handsal-Event: approval.pending

{"type":"approval.pending","approval":{"id","tenantSlug","applicationName","clientId",
 "audience","scopes":[…],"actorHint","taskId","justification","expiresAt","createdAt"}}
```

**Slack:** when the URL host ends in `hooks.slack.com`, send `{"text": "…"}` instead. A generic JSON body posted to a Slack incoming webhook is rejected with `invalid_payload`, so one payload genuinely cannot serve both; one hostname branch choosing the body is the smallest thing that works. The signature header is computed over whichever body is sent (Slack ignores it), so there is no second branch.

### Service logic

New `apps/api/src/services/approval-rule.service.ts`:

```ts
export function conditionMatches(condition: ApprovalCondition, candidate: {
  applicationId: string; taskId: string | null; scopeCount: number;
}): boolean {
  if (condition.application_ids && !condition.application_ids.includes(candidate.applicationId)) return false;
  if (condition.task_id_prefix && !candidate.taskId?.startsWith(condition.task_id_prefix)) return false;
  if (condition.max_scopes !== undefined && candidate.scopeCount > condition.max_scopes) return false;
  return true;
}
```

`findMatchingRule(tenantId, approvalScopeIds, candidate)` — select the tenant's rules whose `scope_id` is in `approvalScopeIds`, ordered by `created_at asc`, and return the first whose condition matches. A rule attached to **one** of the approval scopes auto-approves the whole request; `max_scopes` is the lever for narrowing that, which is exactly what the artboard's "refunds < 20 EUR"-style rules imply.

Hook into 6.3's `createApprovalRequest`, step B, immediately before the insert:

1. `const rule = await findMatchingRule(...)`.
2. Insert with `status: rule ? "approved" : "pending"`, `decidedByRuleId: rule?.id ?? null`, `decidedAt: rule ? new Date() : null`.
3. `recordTokenEvent({ outcome: "pending", … })` either way, so the Tokens page shows the request.
4. No rule → `void notifyApprovalPending(tenant, row)`.
5. Return `{ approvalId, interval: rule ? 0 : 5 }`; the route puts `interval` in the pending body.

New `apps/api/src/services/approval-webhook.service.ts` — `notifyApprovalPending` resolves nothing and never throws:

- No `approval_webhook_url` → return.
- Build the body, sign with `createHmac("sha256", secret)` when a secret is set (header omitted otherwise), `fetch(url, { method: "POST", signal: AbortSignal.timeout(5000) })` — Node 24 built-ins, no dependency.
- Retry **once** after 2 s on a network error or a 5xx. Never retry 4xx. Log the final failure at `warn`.
- Fired without `await` from the request path, so a slow webhook never delays the token response. Trade-off to document: a process exit between the response and the delivery loses the notification. Acceptable for a notification; the queue in the UI is the source of truth.

The DTO mapper gains: `decidedByRuleId !== null` yields `{ kind: "rule", label: "rule: <scopeName>" }`.

### Web UI delta

Minimal, inside the 6.3 page.

- 4th tile on `t.$tenantId.approvals.tsx`: "Auto-approve rules", value `counts.rules`, sub link to the docs anchor. The artboard's sub text "e.g. refunds under 20 EUR" is sample data; use "Configured via the API".
- Resolved table: "Decided by" renders `rule: <scope>` for rule decisions, and the Decision badge reads "Auto-approved" with the green palette when `decidedBy.kind === "rule"`.
- Empty state copy becomes the artboard's full line: "New requests for marked scopes will appear here and in Slack."
- No rules editor, no webhook form, no "Notify via Slack" button. One new `docs/agents.md` section shows the three endpoints and a `curl` for each, plus the `PATCH /api/tenants/:id` body for the webhook.
- `lib/queries.ts`: no new hook; `counts.rules` rides on the existing approvals query.

### Tests

`apps/api/src/services/approval-rule.service.test.ts` (unit, no DB)
- `empty condition matches anything`.
- `application_ids filters by application`; `task_id_prefix matches only the prefix`; `max_scopes rejects a wider request`.
- `all keys are ANDed` — one failing key fails the match.
- `a null task_id never matches a task_id_prefix rule`.

`apps/api/src/services/approval.service.test.ts` (append, integration)
- `a matching rule creates an approved row with decided_by_rule_id and interval 0`.
- `the rule-approved row still issues exactly once` — poll 200, second poll `invalid_grant`.
- `a non-matching rule leaves the row pending and interval 5`.
- `deleting the rule leaves decided_by_rule_id null and the row approved` (`on delete set null`).
- `no webhook is sent for a rule-approved row`.

`apps/api/src/services/approval-webhook.service.test.ts`
- `signs the exact body` — a local Hono stub server recomputes the HMAC over the raw body it received and the test asserts it equals the `X-Handsal-Signature` value.
- `omits the signature header when no secret is configured`.
- `sends a Slack text payload to hooks.slack.com` (stub server bound with a rewritten host, or the hostname predicate unit-tested directly).
- `retries once on 500 and gives up` — stub counts two requests.
- `does not retry a 400` — stub counts one request.
- `a webhook failure does not fail the approval request` — approval row exists after the stub refuses the connection.

`apps/api/src/routes/management/approval-rules.test.ts`
- `auditor create → 403`; `auditor list → 200`.
- `scope from another tenant → 400 invalid_scope_ids`.
- `rule of another tenant → 404 on delete`.
- `duplicate (scope, condition) → 409`.
- `http webhook url rejected when NODE_ENV=production`.

### Task split

6.5 runs after 6.3 has landed; it touches 6.3's service and page.

| Slice | Agent | Files owned |
|---|---|---|
| 6.5a schema + shared | Sonnet `developer` | `packages/db/src/schema/{approval-rules,approval-requests,tenants,index}.ts`, `drizzle/0006_*.sql`, `packages/shared/src/validation/{approval-rule,approval,tenant}.schema.ts`, `validation/index.ts`, `types/api.ts` |
| 6.5b rule evaluation + approval hook | Opus `developer` | `services/approval-rule.service.ts` (+test), `services/approval.service.ts` (+test) |
| 6.5c webhook | Opus `developer` | `services/approval-webhook.service.ts` (+test), `services/tenant.service.ts` (webhook fields + encryption), `routes/management/tenants.ts` |
| 6.5d rules routes | Sonnet `developer` | `routes/management/approval-rules.ts` (+test), `routes/management/index.ts` |
| 6.5e web + docs | Sonnet `developer` | `routes/t.$tenantId.approvals.tsx`, `components/ResolvedApprovalsTable.tsx`, `docs/agents.md` (rules + webhook section) |

6.5a first. Then 6.5b ∥ 6.5c ∥ 6.5d ∥ 6.5e. 6.5b owns `approval.service.ts` alone; 6.5c owns `tenant.service.ts` alone. Verification for every slice: `pnpm check && pnpm typecheck && pnpm test` from the repo root with Postgres up and `pnpm db:migrate` applied, each agent on its own `_test` database.

---

## Cross-task notes

- **Shared mutable files.** `apps/api/src/routes/oauth/token.ts` and `services/token.service.ts` are touched by both 6.3 and 6.4; 6.3 lands first and 6.4 rebases. `routes/management/index.ts`, `jobs/index.ts`, `packages/{db/src/schema,shared/src/validation}/index.ts` and `apps/web/src/lib/queries.ts` are append-only for every slice. `apps/web/src/routeTree.gen.ts` is generated.
- **Discovery metadata** gains one `grant_types_supported` entry in 6.3 and one in 6.4. Without both the published metadata lies about the server.
- **Tenant isolation.** Every new query filters by `tenant_id` from the URL or the resolved tenant: `approval_requests` and `approval_rules` reads, the atomic redemption claim, the decide update, and the rule lookup. The composite FKs make a cross-tenant `scope_id` or `application_id` unrepresentable at the database level, the same guarantee `application_grants` already relies on.
- **No new dependencies.** jose 6.2 covers remote JWKS for 6.4; `node:crypto` covers the HMAC; `AbortSignal.timeout` covers the webhook timeout.
- **Two risks for the reviewer.** Artboard 08's claims preview has `sub` and `act` swapped relative to RFC 8693, so shipping it as drawn would publish a non-standard delegation claim. And 6.5 as specified leaves self-hosters no UI for rules or the webhook, a deliberate cut that likely needs a follow-up Settings task.

---

## Implementation deviations

Where the shipped code differs from this note (the code is the reference; see [api.md](api.md) and [integration.md](integration.md)):

- An `nbf` failure of a client assertion is reported with reason `assertion_not_yet_valid` (the note folded it into `assertion_expired`).
- The assertion lifetime check includes the 60 s clock tolerance.
- Migrations are numbered 0002 to 0006: 0002 is the 6.1/6.2/6.6 schema, 0003 approvals, 0004 6.4, 0005 6.5, 0006 review hardening.
- `redeemApproval` lives in `services/token.service.ts`, not in `approval.service.ts`.
- A pending poll records no token event; only the first request (`pending`) and the final redemption (`issued`) are logged.
- Auto-approve needs a matching rule for every approval scope in the request; one rule never covers another scope.
- A rule-approved row still goes through one poll, and that response carries `interval: 0`.
- Redemption re-runs the CIDR, scope ceiling, budget and `agent_policy` checks, not only the grant check.
- `approval_requests` has a pending cap per application (20, `access_denied` reason `approval_queue_full`) and a 30-day retention job (`approval-retention`, hourly, 1000 rows per tick); the expiry job also works in 1000-row batches.
- Poll requests with `resource`, `scope` or `task_id` are `invalid_request`; CIDR and budget run before the claim, so a refused poll does not consume the approval; a demoted or deleted scope is `invalid_grant` with reason `policy_changed`.
- Denied and expired poll events carry the row's audience and scopes; the issued event has reason `approval`.
- Reusing an existing row matches scopes, `task_id`, `actor_hint` and `justification`, and also reuses an approved-but-unredeemed row.
- `decidedBy.label` is snapshotted at decision time (`decided_by_label`), so deleted users and rules keep their name.
- A Handsal subject token's `aud` must equal the exchange `resource`; issued tokens carry `sub_kind`, from which `mayActFor` is classified (`users` for `user`, `services`/`tenant` for `service`, `tenant` for `agent`); an external IdP's `act` is never propagated; `act` nesting is capped at 3 (`act_chain_too_deep`).
- External IdP tokens need `exp`, are verified with 5 s tolerance and the algorithms RS256/PS256/ES256/ES384/EdDSA; JWKS fetches do not follow redirects and the cache holds 100 entries.
- `approvalWebhookUrl` and `externalIdp.jwksUri` go through an outbound URL guard (https and no internal hosts in production; checks the URL, not the resolved address).
- Rules: a `task_id_prefix`-only condition is `invalid_rule_condition`; a rule on a scope whose `agent_policy` is not `approval` is `scope_not_approval`.
- The admin UI ships a webhook settings form (the note assumed API-only).
- Auto-approve rules are API-only; there is no UI.
