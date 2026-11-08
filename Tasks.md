# Handsal — Implementation Plan (Tasks.md)

> **For agentic workers:** REQUIRED SUB-SKILL: `superpowers:subagent-driven-development` (one fresh `developer` agent per task, `code-reviewer` after each behaviour-changing task, `verifier` on the combined result). Each task below is a self-contained brief: copy it verbatim into the agent prompt together with the **Global Constraints** and **Conventions** sections. Steps use `- [ ]` for tracking.

**Status (2026-11-06):** Phases 0–6 implemented and merged to `main`: all 23 MVP tasks plus Phase 6 (6.1–6.6, design note `docs/agents.md`, migrations 0002–0006); code reviews for Phases 1–4 and 6.1–6.5 applied. Remaining work is the backlog below.

**Goal:** An open-source, self-hostable, multi-tenant machine-to-machine OAuth 2.0 authorization server (client-credentials grant, ES256 JWTs, introspection, revocation, JWKS, per-tenant issuers) with an admin UI, shipped as **one Docker image** plus a production `docker-compose` with PostgreSQL.

**Architecture:** pnpm + Turborepo monorepo. `apps/api` is a Hono (Node 24) server that exposes the OAuth endpoints under `/t/:slug/…`, a session-cookie management REST API under `/api/…`, and serves the built React SPA from `/`. `packages/db` is Drizzle ORM + PostgreSQL 16 with migrations run at startup. `packages/shared` holds Zod schemas, constants and types shared by api and web. `apps/web` is React 19 + TanStack Router/Query + Tailwind. Everything is scoped by `tenant_id`; each tenant has its own signing keys and issuer URL.

**Tech Stack:** TypeScript 5.9 (strict, ESM), Hono 4, `@hono/node-server`, jose 6, drizzle-orm 0.45 + pg 8, argon2, zod 4, pino, React 19, TanStack Router/Query 5, Tailwind 3, Vite 6, Vitest 4, Biome 2, Turbo 2, Docker (node:24-bookworm-slim).

**Spec:** the product decisions in this file.

**MVP scope:** everything on artboards 01–07 **except** anything agent-specific (AI-agent kind, agent policy UI, guardrails, approvals, delegation, SSO, forgot-password, p95 latency, CSV export, "Introspect a token" admin tool). Artboards 08 (Agent detail) and 09 (Approvals) are **post-MVP** (Phase 6) — the MVP schema must not block them. Only machine-to-machine flows; no end-user login flows, no authorization-code grant.

---

## Product decisions (the parts the artboards leave open)

| Topic | Decision |
|---|---|
| Name / scope | `handsal`, packages `@handsal/api`, `@handsal/web`, `@handsal/db`, `@handsal/shared`. Open source under **Apache License 2.0** (`LICENSE`). The "Open source · MIT" line on artboard 01 is wrong — omit it from the UI. |
| Tenant issuer | Path-based: `iss = ${PUBLIC_URL}/t/${tenant.slug}`. All OAuth endpoints live under `/t/:slug`. Custom domains per tenant are post-MVP. |
| Endpoints (per tenant) | `POST /t/:slug/oauth/token`, `POST /t/:slug/oauth/introspect` (RFC 7662), `POST /t/:slug/oauth/revoke` (RFC 7009), `GET /t/:slug/.well-known/openid-configuration`, `GET /t/:slug/.well-known/oauth-authorization-server` (RFC 8414, same body), `GET /t/:slug/.well-known/jwks.json`. |
| Signing | ES256 (P-256) per tenant, `kid = k_<YYYY-MM-DD>_<4 hex>`. Private keys AES-256-GCM encrypted at rest with `KEY_ENCRYPTION_SECRET`. Key states `active → retiring → retired`; JWKS serves active + retiring. |
| Client auth | `client_secret_basic` and `client_secret_post` in MVP; `private_key_jwt` is an enum value + post-MVP task. The registered method is enforced (a basic client sending the secret in the body gets `invalid_client`). |
| Client IDs / secrets | `client_id = app_<20 chars base32 lowercase>`; secret = `hs_<48 chars base62>`, shown once, Argon2id hashed. Rotation keeps the previous hash valid until `previous_secret_expires_at` (default 24 h). |
| Audience | `resource` parameter (RFC 8707) is **required** on every token request and must match one `resources.audience` of the tenant for which the app has ≥1 granted scope; otherwise `invalid_target`. One audience per token, always. |
| Scopes | Requested `scope` ⊆ granted scopes on that resource; missing `scope` ⇒ all granted scopes on that resource. Anything else ⇒ `invalid_scope`. |
| TTL precedence | `application.token_ttl_seconds ?? resource.token_ttl_seconds ?? tenant.default_token_ttl_seconds` (tenant default 3600). Allowed values anywhere: 60–86400. |
| JWT claims | `iss, sub (=client_id), client_id, aud (=audience string), scope (space-separated), tenant (=slug), client_kind ("service"\|"agent"), jti (UUIDv7-ish ULID or UUID), iat, exp`. Header `alg=ES256, kid, typ=at+jwt`. |
| Revocation | `revoked_tokens(jti, tenant_id, expires_at)` + `tokens_not_before` timestamp on tenants and applications ("Revoke all"). Introspection returns `active:false` for revoked, `iat < not_before`, disabled app, or paused tenant. Document that JWT-verifying resource servers only see revocation via introspection. |
| Token log | `token_events` row for every token request (issued/denied) and every revoke; retention `TOKEN_EVENTS_RETENTION_DAYS` (30). Powers artboard 06. |
| Admin auth | Email + password (Argon2id), HMAC-signed stateless cookie session, `SameSite=Strict`, `X-CSRF-Token` header required on mutating `/api` calls. Optional `BOOTSTRAP_ADMIN_EMAIL/PASSWORD` creates the first super-admin on startup when `admin_users` is empty. |
| Roles | `admin_users.is_super_admin` sees every tenant. `tenant_members.role ∈ owner \| admin \| auditor`: auditor = read-only; admin = everything except members, delete/pause tenant; owner = everything. |
| Rate limits | In-memory dual layer (per IP + per client_id) on token/introspect/revoke. Admin login 5 / 15 min per IP. Redis store is post-MVP. |
| Observability | pino JSON to stdout, `LOG_LEVEL`. `GET /health` (process up), `GET /ready` (DB `select 1`). No vendor SDKs. |
| Deployment | One image (`Dockerfile`): API serves `apps/web/dist` from `./public`. `docker-compose.prod.yml` = handsal + postgres. Migrations run at process start. CI: GitHub Actions → GHCR. |
| Agent-readiness (MVP) | `applications.kind` enum has `service \| agent` but the MVP management API only accepts `service`. `scopes.agent_policy` enum (`auto \| approval \| never`) exists, defaults `auto`, hidden in the UI. Token service already rejects `never` scopes when `client_kind === "agent"` (one `if`). Nothing else agent-related ships in MVP. |

### Data model (MVP) — `packages/db/src/schema/*.ts`

All tables: `id uuid pk default gen_random_uuid()`, `created_at/updated_at timestamptz` (except `revoked_tokens`, `token_events`, join tables). Every tenant-owned table has `tenant_id uuid not null references tenants(id) on delete cascade` plus `unique(tenant_id, id)` so child FKs can enforce same-tenant linkage.

| Table | Columns beyond the defaults |
|---|---|
| `tenants` | `name varchar(255)`, `slug varchar(63) unique` (`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`), `status enum('active','paused') default 'active'`, `default_token_ttl_seconds int default 3600`, `introspection_enabled bool default true`, `key_rotation_days int null` (null = manual), `tokens_not_before timestamptz null` |
| `admin_users` | `email varchar(255) unique`, `password_hash varchar(512)`, `name varchar(255)`, `is_super_admin bool default false`, `is_active bool default true`, `last_login_at timestamptz null` |
| `tenant_members` | `tenant_id`, `admin_user_id fk admin_users on delete cascade`, `role enum('owner','admin','auditor')`, pk `(tenant_id, admin_user_id)` |
| `applications` | `tenant_id`, `name varchar(255)`, `description text null`, `kind enum('service','agent') default 'service'`, `client_id varchar(32) unique`, `client_secret_hash varchar(512) null`, `previous_secret_hash varchar(512) null`, `previous_secret_expires_at timestamptz null`, `secret_rotated_at timestamptz null`, `token_endpoint_auth_method enum('client_secret_basic','client_secret_post','private_key_jwt') default 'client_secret_basic'`, `token_ttl_seconds int null`, `status enum('active','disabled') default 'active'`, `tokens_not_before timestamptz null`, `last_token_at timestamptz null`, `created_by uuid null fk admin_users on delete set null`; `unique(tenant_id, name)`; index `tenant_id` |
| `resources` | `tenant_id`, `name varchar(255)`, `kind enum('api','mcp') default 'api'`, `audience varchar(512)`, `token_ttl_seconds int null`, `status enum('active','disabled') default 'active'`; `unique(tenant_id, audience)`, `unique(tenant_id, name)` |
| `scopes` | `tenant_id`, `resource_id fk (tenant_id, resource_id) → resources(tenant_id, id) on delete cascade`, `name varchar(128)` (`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`), `description text null`, `agent_policy enum('auto','approval','never') default 'auto'`; `unique(resource_id, name)` |
| `application_grants` | `tenant_id`, `application_id`, `scope_id`; composite FKs on `(tenant_id, …)` to both parents; pk `(application_id, scope_id)`. Resource access = ≥1 grant on a scope of that resource. |
| `signing_keys` | `tenant_id`, `kid varchar(64) unique`, `algorithm varchar(10) default 'ES256'`, `public_key_pem text`, `private_key_enc text`, `status enum('active','retiring','retired') default 'active'`, `retires_at timestamptz null`; partial unique index: one `active` per tenant |
| `revoked_tokens` | `jti varchar(64) pk`, `tenant_id`, `expires_at timestamptz`; index `expires_at` |
| `token_events` | `id bigserial pk`, `tenant_id`, `application_id uuid null` (no FK — keep history after delete), `application_client_id varchar(32) null`, `resource_id uuid null`, `audience varchar(512) null`, `outcome enum('issued','denied','revoked')`, `reason varchar(64) null` (OAuth error code or `client_disabled`, `tenant_paused`, `unknown_client`, `bad_secret`, `rate_limited`), `scopes text[] default '{}'`, `jti varchar(64) null`, `expires_at timestamptz null`, `source_ip varchar(45) null`, `created_at timestamptz default now()`; index `(tenant_id, created_at desc)`, index `jti` |

### Management API surface (MVP) — all JSON, Zod-validated, `/api` prefix

```
POST   /api/auth/login            {email,password} → 200 {user} + Set-Cookie     (rate-limited 5/15min/IP)
POST   /api/auth/logout
GET    /api/auth/me               → {user, tenants:[{id,name,slug,role}]}
GET    /api/tenants               (super-admin: all; else: member of)      → [{…, appCount, resourceCount, tokens24h}]
POST   /api/tenants               {name,slug}  (super-admin or any admin user; creator becomes owner)
GET    /api/tenants/:tenantId     → tenant + issuer + stats
PATCH  /api/tenants/:tenantId     {name?, defaultTokenTtlSeconds?, introspectionEnabled?, keyRotationDays?}   (admin+)
POST   /api/tenants/:tenantId/pause | /resume | /revoke-all-tokens   (owner)
DELETE /api/tenants/:tenantId     (owner)
GET/POST          /api/tenants/:tenantId/applications          POST {name, description?, tokenEndpointAuthMethod?, tokenTtlSeconds?} → 201 {application, clientSecret}
GET/PATCH/DELETE  /api/tenants/:tenantId/applications/:appId   PATCH {name?, description?, tokenEndpointAuthMethod?, tokenTtlSeconds?}
POST              /api/tenants/:tenantId/applications/:appId/rotate-secret   {graceSeconds?=86400} → {clientSecret, previousSecretExpiresAt}
POST              /api/tenants/:tenantId/applications/:appId/disable | /enable | /revoke-all-tokens
PUT               /api/tenants/:tenantId/applications/:appId/grants   {scopeIds: uuid[]} (replace set) → {grants:[{resource, scopes}]}
GET               /api/tenants/:tenantId/applications/:appId/token-events?limit=10
GET/POST          /api/tenants/:tenantId/resources              POST {name, kind?, audience, tokenTtlSeconds?}
GET/PATCH/DELETE  /api/tenants/:tenantId/resources/:resourceId  (GET includes scopes[] with grantedAppCount, and applications[] with access)
GET/POST          /api/tenants/:tenantId/resources/:resourceId/scopes          POST {name, description?}
PATCH/DELETE      /api/tenants/:tenantId/resources/:resourceId/scopes/:scopeId
GET               /api/tenants/:tenantId/signing-keys
POST              /api/tenants/:tenantId/signing-keys/rotate    (admin+)
GET/POST          /api/tenants/:tenantId/members                POST {email, name?, role} → existing user is linked; new user is created and {temporaryPassword} returned once   (owner)
PATCH/DELETE      /api/tenants/:tenantId/members/:adminUserId   PATCH {role}   (owner; cannot remove the last owner)
GET               /api/tenants/:tenantId/token-events?outcome=&applicationId=&q=&since=&limit=50&cursor=
GET               /api/tenants/:tenantId/token-events/stats     → {issued24h, issuedPrev24h, denied24h, requests24h, activeApps24h, totalApps}
```

Error envelope for `/api`: `{ error: string_code, error_description: string, details?: ZodFlattened }`. OAuth endpoints use RFC 6749 §5.2 bodies (`{error, error_description}`) with `Cache-Control: no-store`.

---

## Global Constraints

- Node `>=24`, pnpm `9.15.0` (`packageManager` pinned), TypeScript strict, ESM only (`"type": "module"`, `.js` extensions in relative imports inside `apps/api` and `packages/*`).
- Biome is the only linter/formatter (`pnpm check`). No eslint/prettier.
- Every DB query on a tenant-owned table filters by `tenant_id` taken from the URL/session, never from the body.
- Secrets (client secrets, admin passwords) are Argon2id-hashed; comparison via `argon2.verify`; never logged. Signing private keys never leave the process unencrypted; `.env` never holds key material.
- `KEY_ENCRYPTION_SECRET`: exactly 64 hex chars; in `NODE_ENV=production` reject the `.env.example` placeholder and repeated-block strings. `PUBLIC_URL` must be `https://` in production.
- Tests: Vitest. Pure logic = unit tests. Anything touching the DB = integration tests against the real PostgreSQL from `docker-compose.yml` (`DATABASE_URL` from env; each test file truncates the tables it uses in `beforeEach`). No mocking of Drizzle.
- Verification before "done": `pnpm check && pnpm typecheck && pnpm test` green from repo root (postgres running, `pnpm db:migrate` applied).
- No vendor-specific code or wording. The product is generic.
- Git: each writing agent works in its own worktree; **never** `git stash`, `git reset`, `git checkout <path>`, `git add -A`. Compare with `git show HEAD:<file>` instead. Commit only when asked.

## Conventions (copy into every agent brief)

- Layout: `apps/api/src/{index.ts,env.ts,app.ts,server.ts,middleware/,routes/oauth/,routes/management/,services/,jobs/,utils/,test/}`; `packages/db/src/{schema/,client.ts,migrate.ts,seed.ts,index.ts}`; `packages/shared/src/{constants/,validation/,types/,index.ts}`; `apps/web/src/{main.tsx,router.tsx,routes/,components/,lib/api.ts,lib/queries.ts}`.
- Hono routes are thin: parse + validate with a schema from `@handsal/shared`, call a `services/*.service.ts` function, return. Services take `tenantId` as the first argument.
- Errors: throw `OAuthError(code, status, description)` (port `middleware/error-handler.ts`) in OAuth routes; throw `ApiError(status, code, description)` in management routes; one `app.onError` handler maps both.
- Env is read **only** in `apps/api/src/env.ts` (Zod-parsed at import, `process.exit(1)` on failure). `index.ts` imports `./env.js` first, then dynamically imports `./server.js` so env validation runs before the server module loads.
- IDs in URLs are UUIDs; `client_id` is a separate opaque string.
- Timestamps are `timestamptz`; the API returns ISO strings; the web formats relative times.
- Tests live next to the code as `*.test.ts`; integration tests use `apps/api/src/test/{setup.ts,helpers.ts,factories.ts}` (`createTenant()`, `createApplication()`, `createResourceWithScopes()`, `grant()`, `loginAs()`, `tokenRequest()`).
- Web: TanStack Router file-based routes, TanStack Query for all server state, Tailwind utility classes, no component library. Visual target: Inter, Space Grotesk and JetBrains Mono, accent `#3B5BDB`, neutral greys. Semantic HTML (`<button>`, `<a href>`, `<label for>`), 44px targets.

## Review Focus

Inputs the spec implies but no artboard shows; each has a test pinned to the owning task:

1. A token request whose `resource` belongs to **another tenant** (same slug path, foreign audience) must fail with `invalid_target`, never leak the resource's existence. → Task 2.3
2. A rotated secret: old secret works until `previous_secret_expires_at`, fails one second after; new secret works immediately. → Task 2.2
3. A retiring signing key still verifies in introspection and appears in JWKS until `retires_at`; tokens are never **signed** with it. → Task 2.1
4. Removing the last `owner` of a tenant, or an auditor calling any mutating route, must be refused (403), including sessions of super-admins who are not members (super-admins are allowed). → Task 3.2
5. A paused tenant: `/oauth/token` returns `400 {error:"invalid_request", error_description:"tenant paused"}`, introspection of its tokens returns `active:false`, JWKS still serves keys (resource servers must keep verifying old tokens until expiry). → Tasks 2.3, 2.4, 2.5

---

## Agent routing legend

- **Opus** = `developer` with `model: opus` (auth, crypto, token logic, migrations, multi-tenant authz).
- **Sonnet** = `developer` default (boilerplate, UI from an exact spec, CI, docs).
- After every Opus task: `code-reviewer` (Opus). After each phase: `verifier`.
- Tasks inside a phase marked ∥ are independent and must be launched in **one message**, each in its own worktree.

---

## Phase 0 — Scaffold (status: root config DONE, packages TODO)

Done already: `package.json`, `pnpm-workspace.yaml`, `turbo.json`, `biome.json`, `tsconfig.base.json`, `vitest.config.ts`, `.npmrc`, `.gitignore`, `.dockerignore`, `renovate.json`, `Dockerfile`, `docker-compose.yml`, `docker-compose.prod.yml`, `.env.example`, `.github/workflows/{ci,docker}.yml`.

### Task 0.1 — Workspace packages skeleton  (Sonnet)

**Files:** create `packages/shared/{package.json,tsconfig.json,src/index.ts}`, `packages/db/{package.json,tsconfig.json,drizzle.config.ts,src/index.ts}`, `apps/api/{package.json,tsconfig.json,vitest.config.ts,src/index.ts}`, `apps/web/{package.json,tsconfig.json,vite.config.ts,index.html,src/main.tsx,tailwind.config.ts,postcss.config.js,src/globals.css}`.

**Spec:** each package has scripts `dev`, `build`, `typecheck`, `test`, `lint`, `format:check` (db also `generate`, `migrate`, `seed`). `apps/web/vite.config.ts` proxies `/api`, `/t`, `/health`, `/ready` to `http://localhost:3000`; no `allowedHosts`. `apps/api/vitest.config.ts` uses `globals` and `setupFiles: ./src/test/setup.ts`. `src/index.ts` files may be placeholders that export nothing, but every package must build.

- [ ] Create the files; run `pnpm install` (generates `pnpm-lock.yaml`).
- [ ] Verify: `pnpm typecheck && pnpm check && pnpm build` pass; `docker build -t handsal:dev .` succeeds (the Dockerfile already references these paths).
- [ ] Done when CI config in `.github/workflows/ci.yml` would run green except `db:migrate`/`test` (no migrations yet).

---

## Phase 1 — Foundation  (1.1 ∥ 1.2 ∥ 1.3 after 0.1)

### Task 1.1 — `@handsal/shared`: constants, Zod schemas, types  (Sonnet)

**Files:** `packages/shared/src/constants/{oauth.ts,defaults.ts,index.ts}`, `packages/shared/src/validation/{tenant.schema.ts,application.schema.ts,resource.schema.ts,scope.schema.ts,member.schema.ts,oauth.schema.ts,auth.schema.ts,token-events.schema.ts,index.ts}`, `packages/shared/src/types/{api.ts,index.ts}`, tests `*.schema.test.ts`.

**Produces (exact names):**
- `GRANT_TYPES = { CLIENT_CREDENTIALS: "client_credentials" }`, `TOKEN_TYPES.BEARER`, `OAUTH_ERRORS = { INVALID_REQUEST, INVALID_CLIENT, INVALID_GRANT, UNAUTHORIZED_CLIENT, UNSUPPORTED_GRANT_TYPE, INVALID_SCOPE, INVALID_TARGET, SERVER_ERROR, TEMPORARILY_UNAVAILABLE }` (snake_case values), `TOKEN_ENDPOINT_AUTH_METHODS`, `APPLICATION_KINDS`, `RESOURCE_KINDS`, `AGENT_POLICIES`, `TENANT_ROLES`, `KEY_STATUSES`, `TOKEN_EVENT_OUTCOMES` as `as const` objects + derived union types.
- `DEFAULTS = { TOKEN_TTL_SECONDS: 3600, TTL_MIN: 60, TTL_MAX: 86400, SECRET_GRACE_SECONDS: 86400, TOKEN_EVENTS_RETENTION_DAYS: 30, TOKEN_EVENTS_PAGE_SIZE: 50 }`.
- Regexes: `SLUG_REGEX`, `SCOPE_NAME_REGEX`, `CLIENT_ID_REGEX = /^app_[a-z2-7]{20}$/`.
- Zod: `tenantCreateSchema {name 1..255, slug SLUG_REGEX}`, `tenantUpdateSchema`, `applicationCreateSchema {name, description?, tokenEndpointAuthMethod? (enum minus private_key_jwt in MVP — use `.refine` with message "private_key_jwt is not available yet"), tokenTtlSeconds? int TTL_MIN..TTL_MAX}`, `applicationUpdateSchema`, `rotateSecretSchema {graceSeconds int 0..604800 default 86400}`, `grantsReplaceSchema {scopeIds: uuid[] max 500}`, `resourceCreateSchema {name, kind?, audience url-or-urn 1..512, tokenTtlSeconds?}`, `resourceUpdateSchema`, `scopeCreateSchema {name SCOPE_NAME_REGEX, description? ≤1000}`, `scopeUpdateSchema`, `memberCreateSchema {email, name? , role}`, `memberUpdateSchema {role}`, `loginSchema {email, password 8..256}`, `tokenRequestSchema {grant_type, scope?, resource, client_id?, client_secret?}` (form fields are strings), `introspectRequestSchema {token, token_type_hint?}`, `revokeRequestSchema {token, token_type_hint?}`, `tokenEventsQuerySchema {outcome?, applicationId?, q?, since?, limit coerce 1..200 default 50, cursor?}`.
- Types: `ApiError { error: string; error_description: string; details?: unknown }`, response DTOs `TenantDto, ApplicationDto, ResourceDto, ScopeDto, SigningKeyDto, MemberDto, TokenEventDto, TokenStatsDto` as `z.infer` of response schemas.

- [ ] Tests per schema: valid sample passes; one failing sample per rule (bad slug, TTL 59, TTL 86401, `private_key_jwt` refused, scope name with space, >500 scopeIds).
- [ ] Verify: `pnpm --filter @handsal/shared test && pnpm typecheck`.

### Task 1.2 — `@handsal/db`: schema, migration 0000, client, migrate, seed  (Opus)

**Files:** `packages/db/src/schema/{tenants,admin-users,tenant-members,applications,resources,scopes,application-grants,signing-keys,revoked-tokens,token-events,index}.ts`, `packages/db/src/relations.ts`, `packages/db/src/client.ts`, `packages/db/src/migrate.ts`, `packages/db/src/seed.ts`, `packages/db/drizzle/0000_*.sql` (generated), `packages/db/src/index.ts`.

**Spec:** exactly the **Data model** table above, with pg enums named `tenant_status, tenant_role, application_kind, token_endpoint_auth_method, application_status, resource_kind, resource_status, agent_policy, signing_key_status, token_event_outcome`. `client.ts` and `migrate.ts` use a `pool` with `max 20` and `pool.on("error")` that logs and does not crash. `index.ts` exports `db, pool, runMigrations, schema tables, relations`. `seed.ts` (`tsx`, uses `DATABASE_URL`) creates: super-admin `admin@handsal.local / handsal-dev-password`, tenant `acme-payments`, resources `Payments API (https://api.acme.io/payments: payments:read, payments:write, payments:refund)`, `Invoices API (…/invoices: invoices:read, invoices:write, invoices:void)`, application `billing-service` granted `payments:read, invoices:write`; prints the client_id + secret once and writes nothing else to disk.

- [ ] Write schema; `pnpm db:generate` → inspect SQL for the partial unique index on `signing_keys (tenant_id) where status='active'` (add via `uniqueIndex(...).where(sql\`status = 'active'\`)`), all composite FKs, cascade rules.
- [ ] `pnpm db:migrate` on the dev compose Postgres succeeds twice (idempotent).
- [ ] Integration test `packages/db/src/schema.test.ts` (own vitest project): inserting a `scopes` row whose `resource_id` belongs to another tenant fails with FK violation; two `active` keys for one tenant fail; deleting a tenant cascades to applications, resources, scopes, grants, signing_keys, revoked_tokens, token_events.
- [ ] Add `packages/db` to root `vitest.config.ts` projects. Verify `pnpm test`.

### Task 1.3 — `@handsal/api` core: env, app, logging, errors, rate-limit, health, bootstrap  (Opus)

**Files:** `apps/api/src/{env.ts,env.test.ts,index.ts,app.ts,app.test.ts,server.ts}`, `apps/api/src/middleware/{error-handler.ts,error-handler.test.ts,request-logger.ts,rate-limit.ts,rate-limit.test.ts,security-headers.ts}`, `apps/api/src/utils/{logger.ts,client-ip.ts,client-ip.test.ts,store.ts,security-logger.ts}`, `apps/api/src/test/{setup.ts,helpers.ts}`.

**Spec:** `env.ts` schema: `NODE_ENV (development|test|production) default development`, `DATABASE_URL`, `PUBLIC_URL url`, `KEY_ENCRYPTION_SECRET 64 hex`, `BOOTSTRAP_ADMIN_EMAIL? email`, `BOOTSTRAP_ADMIN_PASSWORD? min 12`, `PORT default 3000`, `LOG_LEVEL default info`, `CORS_ORIGINS default http://localhost:5173`, `TRUST_PROXY`, `TRUST_PROXY_HOP_COUNT`, `ENABLE_ADMIN_PANEL default "true"`, `RATE_LIMIT_TOKEN_IP_MAX default 600`, `RATE_LIMIT_TOKEN_CLIENT_MAX default 600`, `TOKEN_EVENTS_RETENTION_DAYS default 30`; production refinements from the Global Constraints. `app.ts`: request-id, pino request logger, security headers (API CSP `default-src 'none'` for `/api`, `/t`, `/health`, `/ready`; SPA CSP otherwise), CORS on `/api/*` only, `bodyLimit` 16 KB on `/t/*`, 512 KB on `/api/*`, `GET /health → {status:"ok", version}`, `GET /ready → 200 {status:"ok"} | 503 {status:"db_unavailable"}`, mount points `app.route("/t/:slug", oauthRoutes)` and `app.route("/api", managementRoutes)` (both may be empty `new Hono()` placeholders in this task), static SPA serving when `ENABLE_ADMIN_PANEL=true` and `NODE_ENV=production`, `app.onError(errorHandler)`. `error-handler.ts`: `class OAuthError(code, status, description)`, `class ApiError(status, code, description, details?)`, Zod errors → 400 `validation_error`, unknown → 500 `server_error` logged with requestId. `server.ts`: `runMigrations()` → `bootstrapAdmin()` (Task 3.1 provides; stub here) → `startJobs()` (stub) → `serve`; graceful shutdown on SIGTERM and SIGINT. `rate-limit.ts`: `rateLimit({ keyFn, max, windowMs, store? })` with `MemoryStore` default, `Retry-After` header, 429 OAuth body on `/t`, API body on `/api`.

- [ ] Tests: `env.test.ts` (prod rejects placeholder secret, http PUBLIC_URL), `app.test.ts` (`/health` 200, `/ready` 503 when pool rejects, headers present, unknown route 404 JSON), `rate-limit.test.ts` (max+1 request → 429 with Retry-After), `error-handler.test.ts` (OAuthError body shape + `Cache-Control: no-store`).
- [ ] Verify `pnpm --filter @handsal/api test && pnpm typecheck && pnpm check`.

---

## Phase 2 — OAuth core  (2.1 ∥ 2.2 after Phase 1; 2.3 after 2.1+2.2; 2.4 ∥ 2.5 after 2.3)

### Task 2.1 — Crypto, signing keys, JWKS, rotation job  (Opus)

**Files:** `apps/api/src/utils/{crypto.ts,crypto.test.ts,jwt.ts,jwt.test.ts,key-management.ts,key-management.test.ts}`, `apps/api/src/services/{signing-key.service.ts,signing-key.service.test.ts}`, `apps/api/src/jobs/{key-rotation.job.ts,index.ts}`.

**Produces:**
- `hashSecret(secret): Promise<string>`, `verifySecret(secret, hash): Promise<boolean>` (Argon2id, timing-safe; port incl. `ServiceOverloadError`), `generateClientId(): string` (`app_` + 20 base32), `generateClientSecret(): string` (`hs_` + 48 base62), `encryptPrivateKey(pem, hex): string`, `decryptPrivateKey(enc, hex): string` (AES-256-GCM, `iv:tag:ciphertext` base64), `deriveKey(masterHex, purpose, 32): Buffer` (HKDF).
- `generateEs256KeyPair(): { publicKeyPem, privateKeyPem }`, `makeKid(date = new Date()): string` → `k_YYYY-MM-DD_xxxx`.
- `signAccessToken(privateKeyPem, kid, claims): Promise<string>` (jose `SignJWT`, `alg ES256`, `typ at+jwt`), `verifyAccessToken(token, jwks: JSONWebKeySet, { issuer, audience? }): Promise<JWTPayload>`, `decodeHeader(token): { kid?, alg? }`.
- `ensureActiveKey(tenantId): Promise<SigningKey>` (creates if none), `getActiveKey(tenantId)`, `getJwks(tenantId): Promise<JSONWebKeySet>` (active + retiring, public only, `use: "sig"`, `alg: "ES256"`, `kid`), `rotateKey(tenantId, { graceSeconds }): Promise<SigningKey>` (new active; old → retiring with `retires_at = now + graceSeconds`; default grace = max TTL in tenant across tenant default, resources, applications), `retireExpiredKeys(): Promise<number>`, `autoRotateDueKeys(): Promise<number>` (tenants with `key_rotation_days` whose active key is older than that), `listKeys(tenantId)`.
- Job: `startJobs()` runs `retireExpiredKeys` + `autoRotateDueKeys` hourly (`setInterval(...).unref()`), exported `stopJobs()`.

- [ ] Unit tests: encrypt/decrypt roundtrip + tamper detection; kid format; sign → verify roundtrip; verify rejects wrong issuer, expired, RS256 token.
- [ ] Integration tests: `ensureActiveKey` idempotent; `rotateKey` leaves exactly one active and one retiring; `getJwks` has both kids; after `retires_at` passes `retireExpiredKeys` removes it from JWKS; a token signed with the retiring kid still verifies via JWKS (Review Focus 3); `rotateKey` never signs with retiring (assert `getActiveKey().kid === newKid`).
- [ ] Verify suite green.

### Task 2.2 — Applications, grants & client authentication  (Opus)

**Files:** `apps/api/src/services/{application.service.ts,application.service.test.ts,grant.service.ts,grant.service.test.ts,client-auth.service.ts,client-auth.service.test.ts}`, `apps/api/src/routes/oauth/helpers.ts` (+test), `apps/api/src/test/factories.ts`.

**Produces:**
- `createApplication(tenantId, input, createdBy?): Promise<{ application, clientSecret }>`, `listApplications(tenantId, { q?, status? })` (with `resourceCount`, `scopeNames`, `lastTokenAt`), `getApplication(tenantId, appId)`, `updateApplication`, `deleteApplication`, `setApplicationStatus(tenantId, appId, "active"|"disabled")`, `rotateSecret(tenantId, appId, graceSeconds): Promise<{ clientSecret, previousSecretExpiresAt }>`, `revokeAllApplicationTokens(tenantId, appId)` (sets `tokens_not_before = now()`).
- `replaceGrants(tenantId, appId, scopeIds): Promise<GrantView[]>` (validates every scope belongs to tenant; else `ApiError 400 invalid_scope_ids`), `getGrants(tenantId, appId): Promise<GrantView[]>` where `GrantView = { resource: {id,name,audience,kind}, scopes: {id,name}[] }`, `getGrantedScopesForAudience(tenantId, appId, audience): Promise<{ resource, scopeNames: string[] } | null>`.
- `authenticateClient(tenant, { clientId, clientSecret, viaBasic: boolean }, sourceIp): Promise<{ application }>` — rules: unknown client_id → `invalid_client` 401 (still run a dummy argon2 verify to equalize timing); method mismatch (`viaBasic` vs `token_endpoint_auth_method`) → `invalid_client`; secret matches current hash → ok; matches `previous_secret_hash` and `now < previous_secret_expires_at` → ok; disabled app → `invalid_client` with `reason=client_disabled`; every failure returns the `reason` code for the token event. 401 responses carry `WWW-Authenticate: Basic realm="handsal"`.
- `parseBasicAuth(header): { clientId, clientSecret } | null` (percent-decoding per RFC 6749 §2.3.1), `isFormUrlEncoded(contentType)`.
- Factories: `createTenant(over?)`, `createApplication(tenantId, over?)` returns secret, `createResourceWithScopes(tenantId, audience, scopeNames)`, `grant(appId, scopeIds)`, `truncateAll()`.

- [ ] Tests: create returns `app_…` id and `hs_…` secret and hash verifies; `rotateSecret` grace semantics (Review Focus 2: old works at `expires − 1s`, fails at `expires + 1s`, new works); method mismatch rejected; disabled rejected with reason; grants replace is atomic (transaction) and rejects foreign-tenant scope ids; unique `(tenant_id, name)` violation → `ApiError 409 application_exists`.

### Task 2.3 — Token endpoint + token service + token events  (Opus)

**Files:** `apps/api/src/services/{token.service.ts,token.service.test.ts,token-event.service.ts,token-event.service.test.ts,tenant.service.ts (lookup by slug only here; CRUD in 3.2)}`, `apps/api/src/routes/oauth/{index.ts,token.ts,token.test.ts}`, `apps/api/src/middleware/tenant-resolver.ts`.

**Produces:**
- `tenantResolver` middleware: loads tenant by `:slug` into `c.var.tenant`; unknown slug → 404 `{error:"invalid_request", error_description:"unknown tenant"}`.
- `issueToken(tenant, application, { audience, requestedScopes?: string[] }, ctx: { sourceIp }): Promise<{ access_token, token_type:"Bearer", expires_in, scope }>` — paused tenant → `invalid_request` "tenant paused"; resolve resource via `getGrantedScopesForAudience` → null or resource disabled → `invalid_target` 400; scope subset check → `invalid_scope`; `application.kind === "agent"` and any requested scope has `agent_policy === "never"` → `invalid_scope`; TTL precedence rule; claims per the table; sign with `getActiveKey`; `recordTokenEvent({... outcome:"issued"})` and `update applications set last_token_at` (both awaited inside the same request; a failure to record is logged, not surfaced).
- `recordTokenEvent(event): Promise<void>`, `listTokenEvents(tenantId, query): Promise<{ items, nextCursor }>` (cursor = `created_at,id` keyset), `getTokenStats(tenantId): Promise<TokenStatsDto>`, `purgeOldTokenEvents(retentionDays): Promise<number>` (register in `jobs/index.ts`, daily).
- Route `POST /t/:slug/oauth/token`: `rateLimit(ip, RATE_LIMIT_TOKEN_IP_MAX/min)` + `rateLimit(clientIdKey, RATE_LIMIT_TOKEN_CLIENT_MAX/min)`; require `application/x-www-form-urlencoded`; `grant_type` must be `client_credentials` else `unsupported_grant_type`; credentials via Basic or body; on **any** failure after the tenant is resolved record a `denied` event with `reason` (client id if known); response headers `Cache-Control: no-store`, `Pragma: no-cache`.

- [ ] Tests (integration, via `app.request`): happy path returns a JWT whose payload has all claims and whose header `kid` is the tenant's active key; verifies against `/t/:slug/.well-known/jwks.json` output of `getJwks`; missing `resource` → `invalid_target`; foreign-tenant audience → `invalid_target` and no scopes leak (Review Focus 1); scope outside grant → `invalid_scope`; `scope` omitted → all granted scopes on that audience, in grant order; TTL precedence (app 900 wins over resource 1800 over tenant 3600); paused tenant → 400 "tenant paused" (Review Focus 5); wrong secret → 401 + `WWW-Authenticate`; each failure path inserts one `token_events` row with the expected `reason`; JSON body → 400 `invalid_request`; per-client 429 after `RATE_LIMIT_TOKEN_CLIENT_MAX`.

### Task 2.4 — Introspection + revocation  (Opus)

**Files:** `apps/api/src/services/{introspection.service.ts,revocation.service.ts}` (+tests), `apps/api/src/routes/oauth/{introspect.ts,revoke.ts}` (+tests), `apps/api/src/jobs/revoked-cleanup.job.ts`.

**Produces:**
- `introspectToken(tenant, token): Promise<IntrospectionResponse>` — verify against tenant JWKS (active + retiring) with `issuer = ${PUBLIC_URL}/t/${slug}`; inactive when: invalid/expired, `jti` in `revoked_tokens`, `iat < tenant.tokens_not_before`, `iat < application.tokens_not_before`, application disabled or deleted, tenant paused. Active response: `{ active:true, scope, client_id, token_type:"Bearer", exp, iat, sub, aud, iss, jti, tenant, client_kind }`.
- `revokeToken(tenant, callerApplication, token): Promise<void>` — decode without verifying signature first to read `jti/exp/client_id`; verify; if `client_id !== caller.client_id` → silently 200 (RFC 7009 §2.2); else insert `revoked_tokens` (ignore duplicate) and record `token_events outcome:"revoked"`.
- `revokeAllTenantTokens(tenantId)` (sets `tenants.tokens_not_before`), `purgeExpiredRevocations(): Promise<number>` (hourly job).
- Routes: both require client authentication (`authenticateClient`, form-encoded, rate limits introspect 1200 IP / 600 client, revoke 200 / 100). `POST /t/:slug/oauth/introspect` returns 200 always for authenticated callers (`{active:false}` on any token problem); when `tenant.introspection_enabled === false` → 404 `{error:"invalid_request", error_description:"introspection disabled"}`. `POST /t/:slug/oauth/revoke` → 200 empty body.

- [ ] Migration `0001_*`: add index `idx_revoked_tokens_tenant_id` on `revoked_tokens(tenant_id)` (tenant delete and `revokeAllTenantTokens` cleanup otherwise seq-scan). Edit the schema file, `pnpm db:generate`, never hand-edit SQL.
- [ ] Tests: issued token → active with all fields; after `revokeToken` → inactive; token from app A revoked by app B → still active, 200; after `revokeAllApplicationTokens` tokens issued before are inactive and tokens issued after are active; tenant `revoke-all` same; disabled app → inactive; paused tenant → inactive (Review Focus 5); token signed by a *retiring* key → active; garbage token → `{active:false}`; introspection disabled → 404; unauthenticated → 401.

### Task 2.5 — Discovery + JWKS routes  (Sonnet)

**Files:** `apps/api/src/routes/oauth/{discovery.ts,jwks.ts}` (+tests), `apps/api/src/routes/oauth/index.ts` (wire all five routes).

**Spec:** `GET /t/:slug/.well-known/openid-configuration` and `GET /t/:slug/.well-known/oauth-authorization-server` return `{ issuer, token_endpoint, introspection_endpoint (omit when disabled), revocation_endpoint, jwks_uri, grant_types_supported:["client_credentials"], token_endpoint_auth_methods_supported:["client_secret_basic","client_secret_post"], introspection_endpoint_auth_methods_supported: same, revocation_endpoint_auth_methods_supported: same, response_types_supported: [], id_token_signing_alg_values_supported: ["ES256"], token_endpoint_auth_signing_alg_values_supported: ["ES256"] }` with `Cache-Control: public, max-age=300`. `GET /t/:slug/.well-known/jwks.json` → `getJwks(tenant.id)` with `Cache-Control: public, max-age=300`. JWKS of a paused tenant still returns keys (Review Focus 5). Unknown slug → 404.

- [ ] Tests: URLs are built from `PUBLIC_URL` + slug; disabled introspection omits the field; JWKS has no private members (`d` absent); paused tenant JWKS 200.

---

## Phase 3 — Management API  (3.1 first; then 3.2 ∥ 3.3 ∥ 3.4 ∥ 3.5)

### Task 3.1 — Admin auth: login, session cookie, CSRF, bootstrap, role guards  (Opus)

**Files:** `apps/api/src/services/{admin-user.service.ts,admin-user.service.test.ts,bootstrap.ts}`, `apps/api/src/middleware/{admin-auth.ts,admin-auth.test.ts,tenant-access.ts,tenant-access.test.ts}`, `apps/api/src/routes/management/{index.ts,auth.ts,auth.test.ts}`, `apps/api/src/test/helpers.ts` (`loginAs(app, email, password): Promise<{cookie, csrf}>`).

**Spec:** HMAC-signed session cookie `handsal_session`, key = `deriveKey(KEY_ENCRYPTION_SECRET, "admin-session")`, 12 h TTL, `HttpOnly; Secure (prod); SameSite=Strict; Path=/`; CSRF token = HMAC of session id returned in the login body and required as `X-CSRF-Token` on `POST/PUT/PATCH/DELETE /api/*`. `adminAuth` middleware accepts the session cookie only. `requireTenantAccess(minRole: "auditor"|"admin"|"owner")` middleware for `/api/tenants/:tenantId/*`: super-admin passes; otherwise look up `tenant_members`; 404 when the tenant does not exist or the user is not a member (do not reveal existence), 403 when role is below `minRole`. `bootstrapAdmin()` creates the super-admin from `BOOTSTRAP_ADMIN_*` only when `admin_users` is empty, logs email (never the password). Login rate limit 5 / 15 min per IP; failed login returns 401 `invalid_credentials` regardless of which part was wrong; `last_login_at` updated.

- [ ] Tests: login/logout/me cycle; wrong password 401; tampered cookie 401; mutating call without CSRF header 403 `csrf_required`; `requireTenantAccess("admin")` → auditor 403, admin 200, non-member 404, super-admin 200 (Review Focus 4); bootstrap creates once and is a no-op when a user exists; 6th login attempt in window 429.

### Task 3.2 — Tenants + members routes  (Opus)

**Files:** `apps/api/src/services/{tenant.service.ts,member.service.ts}` (+tests), `apps/api/src/routes/management/{tenants.ts,members.ts}` (+tests).

**Spec:** the **Management API surface** rows for `/api/tenants…` and `…/members…`. `createTenant` runs in one transaction: insert tenant → `ensureActiveKey` → add creator as `owner`. `GET /api/tenants` enriches with `appCount, resourceCount, tokens24h` (one grouped query, not N+1). `GET /api/tenants/:id` adds `issuer`, `discoveryUrl`, `jwksUrl`, `stats` (`getTokenStats`). `DELETE` requires owner and body `{confirmSlug}` equal to the slug. `pause`/`resume` toggle status; `revoke-all-tokens` → `revokeAllTenantTokens`. Members: `POST` with an unknown email creates an `admin_users` row with a generated 24-char temporary password returned once (`{member, temporaryPassword}`); `PATCH`/`DELETE` refuse to demote/remove the last `owner` (409 `last_owner`); a member cannot change their own role.

- [ ] Tests cover every rule above plus: auditor can `GET` but every mutation → 403; non-member → 404 on every route; delete cascades (count rows after).

### Task 3.3 — Applications + grants routes  (Opus)

**Files:** `apps/api/src/routes/management/{applications.ts,grants.ts}` (+tests).

**Spec:** the `…/applications…` rows. Uses Task 2.2 services only. `POST` returns the secret exactly once; `kind` is not accepted from the body in MVP (always `service`). `PUT …/grants` returns the `GrantView[]`. `GET …/applications/:appId` returns `{ application, grants: GrantView[], issuer, tokenEndpoint, recentTokens: last 5 token_events for the app }`. `GET …/applications` supports `?q=` (name or client_id ILIKE) and `?status=active|disabled|needs_attention` (`needs_attention` = disabled OR `previous_secret_expires_at > now()`).

- [ ] Tests: CRUD happy paths; `kind:"agent"` in body ignored/400; rotate-secret response shape; grants with a foreign-tenant scope id → 400; auditor 403 on mutations; filters.

### Task 3.4 — Resources + scopes routes  (Opus)

**Files:** `apps/api/src/services/{resource.service.ts,scope.service.ts}` (+tests), `apps/api/src/routes/management/{resources.ts,scopes.ts}` (+tests).

**Spec:** the `…/resources…` rows. `GET …/resources` list includes `scopeCount`, `appCount` (distinct apps with ≥1 grant), `tokens24h`. `GET …/resources/:id` includes `scopes[]` each with `grantedAppCount`, and `applications[]` `{id,name,clientId}` with access. Deleting a resource cascades scopes + grants (DB does it; test it). `audience` unique per tenant → 409 `audience_exists`. `agent_policy` is accepted on scope create/update (schema allows it) but defaults `auto`; the UI will not expose it in MVP.

- [ ] Tests: CRUD; duplicate audience 409; duplicate scope name within resource 409 but same name on another resource OK; cascade on delete; tenant isolation (resource id of tenant B under tenant A → 404).

### Task 3.5 — Signing keys + token events routes  (Sonnet)

**Files:** `apps/api/src/routes/management/{signing-keys.ts,token-events.ts}` (+tests).

**Spec:** `GET …/signing-keys` → `listKeys` as `SigningKeyDto { kid, algorithm, status, createdAt, retiresAt }` (never PEMs). `POST …/signing-keys/rotate` (admin+) → `rotateKey(tenantId, {})` → 201 new key DTO. `GET …/token-events` → `listTokenEvents` with `tokenEventsQuerySchema`; `q` matches `application_client_id`, application name (join) or `jti` prefix. `GET …/token-events/stats` → `getTokenStats`. `GET …/applications/:appId/token-events?limit=` lives here too (filter by app).

- [ ] Tests: no PEM in any response (`expect(JSON.stringify(body)).not.toContain("PRIVATE")`), rotate requires admin, pagination cursor returns the next page without overlap, stats numbers match seeded events.

---

## Phase 4 — Web admin UI  (4.1 first; then 4.2 ∥ 4.3 ∥ 4.4 ∥ 4.5)

Visual spec: Inter, Space Grotesk and JetBrains Mono, accent `#3B5BDB`, and the layout and copy already in the admin UI. Replace sample data with API data. Drop everything listed under **MVP scope** exclusions. Shared pieces from 4.1 are the only allowed cross-task dependency.

### Task 4.1 — App shell, auth, Tenants page  (Sonnet)

**Files:** `apps/web/src/{main.tsx,router.tsx}`, `apps/web/src/lib/{api.ts,queries.ts,auth.ts,format.ts}`, `apps/web/src/components/{AppShell.tsx,TenantSidebar.tsx,TopBar.tsx,Button.tsx,Input.tsx,Badge.tsx,Table.tsx,Dialog.tsx,SecretReveal.tsx,EmptyState.tsx,Toast.tsx}`, routes `routes/{__root.tsx,login.tsx,index.tsx (redirect),tenants.tsx,t.$tenantId.tsx (layout with sidebar)}`.

**Spec:** `api.ts` = `fetch` wrapper: JSON, `credentials:"include"`, injects `X-CSRF-Token` from `auth.ts` memory store, maps error envelope to `ApiRequestError`. Route guard: unauthenticated → `/login`. **Login** (artboard 01): left brand panel with the static token-exchange snippet (`POST /t/{slug}/oauth/token`), right form; no SSO button, no forgot-password link, no "MIT" line; footer keeps "handsal — Old Norse: a deal sealed by a handshake · RFC 6749 · 7662 · 8414 · v0.1.0". **Tenants** (artboard 02): cards grid with Apps / Resources / Tokens-24h, status badge, search filter (client side), "New tenant" dialog (name + slug with auto-slugify + inline validation). Sidebar (artboards 03–07 left column): tenant switcher, nav Applications / Resources / Tokens / Settings (**no Approvals**), issuer box with slug-derived issuer + "JWKS healthy" dot (green when `GET jwks` 200), current user + role.

- [ ] Verify: `pnpm --filter @handsal/web typecheck && pnpm build`; manual run against seeded API: login → tenants → create tenant → sidebar shows issuer.

### Task 4.2 — Applications list + Application detail  (Sonnet)

**Files:** routes `t.$tenantId.applications.tsx`, `t.$tenantId.applications.$appId.tsx`, components `ApplicationForm.tsx`, `GrantsMatrix.tsx`, `CurlSnippet.tsx`.

**Spec:** artboards 03 and 04. List: search (server `q`), filter group **All / Active / Needs attention** (no "AI agents"), table columns Application, Client ID, Resources, Scopes (chips + `+n`), Status, Last token, open chevron; Type column omitted. "New application" dialog → shows the secret once in a `SecretReveal` with copy button and the warning "You won't see this again". Detail: header with status + Disable/Enable + Delete (confirm by name); Credentials card (client id copy, secret masked placeholder, **Rotate secret** dialog with grace select 0 / 1 h / 24 h / 7 d, shows new secret once, "previous secret valid until …"); Authentication method radio (basic / post; `private_key_jwt` shown disabled with "coming soon"); Access token lifetime select (15 min / 1 h / 8 h / inherit); Access section = `GrantsMatrix` (resource groups with scope checkboxes, granted/total, Discard / Save → `PUT grants`); right column: "Get a token" curl using the real issuer, client id and granted scopes; Token profile (grant, format `JWT · ES256`, issuer, introspection on/off, rate limit); Recent tokens (last 5 events, link "View all" → Tokens page filtered by app).

- [ ] Verify build + manual: create app → rotate → grants save → curl snippet matches real request that returns 200 against the dev API.

### Task 4.3 — Resources & scopes  (Sonnet)

**Files:** route `t.$tenantId.resources.tsx`, components `ResourceList.tsx`, `ResourceDetail.tsx`, `ScopeTable.tsx`, `ResourceForm.tsx`, `ScopeForm.tsx`.

**Spec:** artboard 05 master-detail. Left: resource cards (name, MCP/API badge, audience, scope count, app count), "New resource" dialog (name, kind, audience, TTL). Right: selected resource header (Edit / Delete with confirm), facts row (Token lifetime, Signing `ES256`, Tokens/24h), Scopes table with columns Scope, Description, Granted to (n apps) — **no Agent policy column** — row actions edit/delete, "Add scope" dialog; "Applications with access" chips linking to app detail. Selection persisted in the URL search param `?resource=`.

### Task 4.4 — Token activity  (Sonnet)

**Files:** route `t.$tenantId.tokens.tsx`, components `StatTile.tsx`, `TokenEventsTable.tsx`.

**Spec:** artboard 06. Stat tiles: Tokens issued (24h, delta vs previous 24h), Denied requests (count + % of requests), Active clients (`activeApps24h / totalApps`); omit p95 latency, Export, Introspect-a-token. Search box (server `q`), filter **All / Issued / Needs attention** (`needs_attention` = denied + revoked), "Live · updates every 5 s" = `refetchInterval: 5000` while the tab is visible. Columns Time, Outcome, Client, Audience, Scopes, Token ID (prefix 12 chars + copy), Expires (relative; for denied show the `reason` humanised: `invalid_scope` → "outside granted scopes", `client_disabled` → "client disabled", etc.). "Load more" via cursor. Supports `?applicationId=` from the app detail link.

### Task 4.5 — Tenant settings  (Sonnet)

**Files:** route `t.$tenantId.settings.tsx`, components `SettingsNav.tsx`, `SigningKeysTable.tsx`, `MembersTable.tsx`, `DangerZone.tsx`.

**Spec:** artboard 07, sections with anchor nav: **General** (name editable, slug read-only, issuer URL read-only with copy, note about discovery + JWKS paths); **Signing keys** (table kid / alg / status / created / retires, "Rotate key" with confirm, "Automatic rotation" toggle bound to `keyRotationDays` 90 ⇄ null); **Token defaults** (lifetime select 15 min / 1 h / 8 h / 24 h; token format shows `JWT (self-contained)` selected and `Opaque` disabled "coming soon"; toggle "Token introspection endpoint"; omit "Require explicit audience" (always on) and "Issue refresh tokens"); **Members** (table, Invite dialog email + role; shows temporary password once when a new user was created; role change / remove with last-owner guard surfaced as an error toast; auditors see read-only); **Danger zone** (Revoke all tokens, Pause/Resume, Delete tenant with slug confirmation) — owner only, hidden for others.

---

## Phase 5 — Ship  (5.1 ∥ 5.2 ∥ 5.3 after Phase 4; 5.4 after 5.1)

### Task 5.1 — Single-image build + production compose smoke  (Sonnet)

- [ ] `docker build -t handsal:local .` from a clean clone succeeds; image runs with `.env.example` values + `POSTGRES_PASSWORD` via `docker compose -f docker-compose.prod.yml up` (use `build: .`), `GET /health` 200, `GET /ready` 200, SPA served at `/`, migrations applied, bootstrap admin created from `BOOTSTRAP_ADMIN_*`.
- [ ] `runMigrations()` takes a Postgres advisory lock (`pg_advisory_lock(<constant>)`) so two replicas starting together do not race on `CREATE TYPE`; and `server.ts` starts the HTTP listener (with `/ready` returning 503 `migrating`) **before** running migrations so orchestrators do not kill the container mid-DDL.
- [ ] Add `HEALTHCHECK` to the Dockerfile (`node -e "fetch('http://localhost:3000/health').then(r=>process.exit(r.ok?0:1))"`), run as non-root `node` user, image size noted in `docs/deployment.md`.

### Task 5.2 — CI hardening  (Sonnet)

- [ ] `.github/workflows/ci.yml` runs green on a PR (postgres service already configured). Pin action versions to SHAs (Renovate keeps them). `docker.yml` builds on `main` and `v*` tags → `ghcr.io/${{ github.repository }}`. `docker-compose.prod.yml` pulls `ghcr.io/wfalowski/handsal:latest`.

### Task 5.3 — Docs: README, deployment, integration guide  (Sonnet, then `pl-copywriter` is NOT needed — docs are English)

- [ ] `README.md`: what Handsal is (M2M OAuth 2.0, tenants, ES256, introspection, single image), 5-minute quickstart with `docker-compose.prod.yml`, dev setup, env reference (table from `.env.example`), endpoint table, Apache-2.0 note.
- [ ] `docs/deployment.md`: reverse proxy + `TRUST_PROXY`, secrets generation, backups (pg_dump), upgrading (migrations on start), key rotation semantics, revocation caveat for JWT-verifying resource servers.
- [ ] `docs/integration.md`: how a service obtains a token (curl + Node + Python snippets), how a resource server verifies (`jose` `createRemoteJWKSet` with the tenant JWKS URL, check `iss`, `aud`, `scope`), when to use introspection.
- [ ] `CLAUDE.md` already exists — update commands/architecture if anything moved.

### Task 5.4 — End-to-end smoke script  (Sonnet)

- [ ] `scripts/smoke.sh` (bash + curl + jq) against a running instance: login as a super-admin → create tenant → resource + scope → application + grant → `POST /t/:slug/oauth/token` → decode and check `aud`/`scope` → introspect active → revoke → introspect inactive → discovery URLs resolve → exit 0. Wire into CI after `docker compose up` as a final job.

---

## Phase 6 — Post-MVP: AI agents (artboards 08–09) — DONE (status: all six tasks merged; deviations listed in `docs/agents.md` → Implementation deviations; auto-approve rules are API-only, no UI)

Each task gets its own migration (`00NN_*.sql`) and a short design note in `docs/agents.md` before implementation (`deep-reasoner` writes the note; `developer` Opus implements).

- **6.1 `private_key_jwt` (RFC 7523)** — table `application_keys (id, tenant_id, application_id, kid, alg 'ES256', public_key_pem/jwk, fingerprint_sha256, status active|retiring, retires_at)`; token endpoint accepts `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` + `client_assertion` (`iss=sub=client_id`, `aud=token endpoint`, `exp ≤ 5 min`, `jti` replay cache); management routes + "Registered public keys" UI from artboard 08. Enables `token_endpoint_auth_method = private_key_jwt`.
- **6.2 Agent application kind + guardrails** — allow `kind:"agent"`; columns on `applications`: `agent_runtime varchar`, `operator_email`, `allowed_cidrs text[]`, `max_scopes_per_token int`, `token_budget_per_hour int`; TTL options 1/5/15 min for agents; token service enforces: scope count ≤ max, hourly budget (count `token_events` issued in the last hour), source IP ∈ `allowed_cidrs`; "AI agents" filter + Type column on artboard 03; Agent detail page sections Credentials / Runtime binding / Guardrails / Scope ceiling (artboard 08).
- **6.3 Scope ceiling with human approval** — `scopes.agent_policy = approval` enforced: token request from an agent for such a scope creates `approval_requests (id, tenant_id, application_id, resource_id, scopes, actor_hint, task_id, justification, status pending|approved|denied|expired, expires_at = now()+30 min, decided_by, decided_at)` and returns `400 {error:"authorization_pending", approval_id, interval}` (device-flow-style); client polls `POST /oauth/token` with `grant_type=urn:handsal:params:grant-type:approval` + `approval_id`; approval issues **one** 5-minute token; routes + **Approvals** page (artboard 09: pending / resolved tabs, approve once / deny, counters) + sidebar badge; `token_events` outcome `pending`.
- **6.4 Token exchange (RFC 8693)** — `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with `subject_token` (a Handsal token or a configured external IdP JWT), `act` claim, `task_id` passthrough, per-agent delegation settings (`may_act_for: users|tenant|services[]`, `scope_mode: intersection|agent_only`); claims preview in Agent detail.
- **6.5 Approvals notifications + auto-approve rules** — Slack/webhook on new pending request; `approval_rules (scope_id, condition jsonb, action auto_approve)`; "Decided by: rule" in the resolved table.
- **6.6 Agent activity** — "Recent tasks" grouping of token events by `task_id`; Tokens page "agent · for <actor>" column.

### Non-agent backlog (unscheduled)

Opaque tokens (introspection-only format) · custom issuer domains per tenant · admin SSO (OIDC) · password reset · Redis store for rate limits (multi-replica) · CSV export of token events · "Introspect a token" admin tool · p95 latency tile · audit log of admin actions · enterprise license + feature flags.
approval-rules editor in the admin UI · unique index on `approval_rules (tenant_id, scope_id, condition)` · redeem guardrails: pending cap is check-then-insert (can overshoot under concurrency) · admin password reset / "reset temporary password" route (re-inviting an existing user returns no password) · `CREATE INDEX CONCURRENTLY` migrations once tables grow · `unsupported_token_type` for unknown `token_type_hint` on revoke

---

## Self-review log

- Spec coverage: artboards 01–07 → Phases 1–5 (exclusions listed under MVP scope); 08–09 → Phase 6. User requirements: Hono ✓, single Docker image + prod compose with PostgreSQL ✓ (Phase 0 files, Task 5.1), reusable/generic ✓ (Global Constraints), MVP without agents but agent-ready ✓ (kind/agent_policy columns, Phase 6 plan), M2M only ✓, open source under Apache-2.0 ✓.
- Type consistency: `GrantView`, `getGrantedScopesForAudience`, `recordTokenEvent`, `rotateKey`, `getJwks`, `authenticateClient`, `requireTenantAccess` are named identically in every task that uses them.
- Review Focus items 1–5 each have a test in the task they point to.
