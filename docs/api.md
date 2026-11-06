# API reference

Two surfaces: the OAuth endpoints under `/t/:slug` (for services and resource servers) and the management API under `/api` (for the admin UI and automation). `<issuer>` below is `<PUBLIC_URL>/t/<slug>`.

## OAuth endpoints

All bodies are `application/x-www-form-urlencoded` (anything else is `400 invalid_request`) and at most 16 KiB (`413 invalid_request`). Responses carry `Cache-Control: no-store`. Errors are `{"error": "<code>", "error_description": "<text>"}`.

Client authentication (token, introspect, revoke): `Authorization: Basic base64(urlencode(client_id):urlencode(client_secret))` for applications registered as `client_secret_basic`, or `client_id` + `client_secret` in the body for `client_secret_post`. The registered method is enforced; sending both is `400 invalid_request`. `client_id` has the form `app_` plus 20 characters, the secret `hs_` plus 48.

| Method | Path | Auth | Body | Success | Errors |
|---|---|---|---|---|---|
| POST | `<issuer>/oauth/token` | client | `grant_type=client_credentials` (required), `resource` (required, one audience), `scope` (space-separated, optional) | 200 `{access_token, token_type:"Bearer", expires_in, scope}` | see below |
| POST | `<issuer>/oauth/introspect` | client (any application of the tenant) | `token` (required), `token_type_hint` (ignored) | 200 active: `{active:true, scope, client_id, token_type, exp, iat, sub, aud, iss, jti, tenant, client_kind}`; otherwise `{active:false}` | `invalid_client` 401, `invalid_request` 400, `invalid_request` 404 `introspection disabled`, 429 |
| POST | `<issuer>/oauth/revoke` | client (the token's own application) | `token` (required), `token_type_hint` (ignored) | 200, empty body, also for unknown or foreign tokens | `invalid_client` 401, `invalid_request` 400, 429 |
| GET | `<issuer>/.well-known/openid-configuration` | none | none | 200 discovery document (`Cache-Control: public, max-age=300`) | `invalid_request` 404 `unknown tenant` |
| GET | `<issuer>/.well-known/oauth-authorization-server` | none | none | same document | same |
| GET | `<issuer>/.well-known/jwks.json` | none | none | 200 `{keys:[{kty:"EC", crv:"P-256", x, y, kid, use:"sig", alg:"ES256"}]}`: active key first, then retiring keys; served for paused tenants | `invalid_request` 404 `unknown tenant` |

Token endpoint errors (HTTP status, `error`, cause):

| Status | `error` | Cause |
|---|---|---|
| 400 | `invalid_request` | Wrong content type, missing `grant_type`, client auth by two methods, malformed parameters, tenant paused (`tenant paused`) |
| 400 | `unsupported_grant_type` | `grant_type` is not `client_credentials` |
| 401 | `invalid_client` | Unknown client, wrong or expired secret, wrong auth method, disabled application, missing credentials. Includes `WWW-Authenticate: Basic realm="handsal"`. The reason is only in logs and the token log |
| 400 | `invalid_target` | `resource` missing, unknown, disabled, belongs to another tenant, or the application has no granted scope on it |
| 400 | `invalid_scope` | A requested scope is not granted on that resource (also: scope with `agent_policy=never` requested by an `agent` application) |
| 404 | `invalid_request` | Unknown tenant slug |
| 429 | `too_many_requests` | Rate limit; `Retry-After` header in seconds, plus `X-RateLimit-Limit` and `X-RateLimit-Remaining` |
| 500 | `server_error` | Unexpected error |

Rate limits (per minute, per IP and per `client_id`): token 6000 / 600, introspect 1200 / 600, revoke 200 / 100; configurable (see README).

Access token: JWT, header `{alg:"ES256", kid, typ:"at+jwt"}`, claims `iss` (`<issuer>`), `sub` and `client_id` (the application's client ID), `aud` (the `resource`), `scope`, `tenant` (slug), `client_kind`, `jti` (UUID), `iat`, `exp`. TTL is `application.tokenTtlSeconds ?? resource.tokenTtlSeconds ?? tenant.defaultTokenTtlSeconds` (default 3600; 60 to 86400 everywhere).

## Instance endpoints

| Method | Path | Auth | Success | Errors |
|---|---|---|---|---|
| GET | `/health` | none | 200 `{status:"ok", version}` | |
| GET | `/ready` | none | 200 `{status:"ok"}` | 503 `{status:"db_unavailable"}` |

## Management API (`/api`)

Available unless `ENABLE_ADMIN_PANEL=false` (then `404 {"error":"not_found"}`). JSON in and out; bodies up to 512 KiB (`413 payload_too_large`). Timestamps are ISO 8601 strings, IDs are UUIDs. Errors: `{"error": "<code>", "error_description": "<text>", "details"?: ...}`.

### Authentication

- Session: `POST /api/auth/login` sets the `handsal_session` cookie (`HttpOnly`, `SameSite=Strict`, `Secure` in production, 12 h) and returns `{user:{id,email,name,isSuperAdmin}, csrfToken}`. Send the token as `X-CSRF-Token` on every `POST`, `PUT`, `PATCH` and `DELETE`; without it the call fails with `403 csrf_required`.
- API key: `Authorization: Bearer <ADMIN_API_KEY>`. Acts as a super-admin; no CSRF header needed. Use it for scripts.
- Roles per tenant: `auditor` (read), `admin` (everything except members, pause/resume, revoke-all-tenant, delete tenant), `owner` (everything). Super-admins and the API key count as `owner` everywhere. A tenant that does not exist or that you are not a member of is `404 tenant_not_found`; a role that is too low is `403 forbidden`.

Common errors on every route: `401 unauthenticated`, `403 csrf_required`, `400 validation_error` (`details` holds the flattened Zod errors), `404 tenant_not_found`, `403 forbidden`.

| Method | Path | Min role | Body / query | Success | Specific errors |
|---|---|---|---|---|---|
| POST | `/api/auth/login` | none | `{email, password}` | 200 (above) | 401 `invalid_credentials`, 429 `rate_limited` (5 per 15 min per IP) |
| POST | `/api/auth/logout` | none | none | 204 | |
| GET | `/api/auth/me` | any | none | `{user, tenants:[{id,name,slug,role}]}` | |

### Tenants

| Method | Path | Min role | Body / query | Success | Specific errors |
|---|---|---|---|---|---|
| GET | `/api/tenants` | any | none | 200 `[{...tenant, appCount, resourceCount, tokens24h, role}]` | |
| POST | `/api/tenants` | any user | `{name, slug}` (`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`) | 201 tenant; creator becomes `owner`; first signing key is created | 409 `slug_exists` |
| GET | `/api/tenants/:tenantId` | auditor | none | 200 tenant + `discoveryUrl`, `jwksUrl`, `stats`, `role` | |
| PATCH | `/api/tenants/:tenantId` | admin | `{name?, defaultTokenTtlSeconds? (60-86400), introspectionEnabled?, keyRotationDays? (1-3650 or null)}` | 200 tenant | |
| POST | `/api/tenants/:tenantId/pause` | owner | none | 200 tenant (`status:"paused"`): token requests fail, introspection returns inactive, JWKS still served | |
| POST | `/api/tenants/:tenantId/resume` | owner | none | 200 tenant | |
| POST | `/api/tenants/:tenantId/revoke-all-tokens` | owner | none | 200 tenant (`tokensNotBefore` = now) | |
| DELETE | `/api/tenants/:tenantId` | owner | `{confirmSlug}` | 204; removes all tenant data | 400 `confirm_slug_mismatch` |

Tenant: `{id, name, slug, status:"active"|"paused", defaultTokenTtlSeconds, introspectionEnabled, keyRotationDays, tokensNotBefore, issuer, createdAt, updatedAt}`.

### Applications

Application: `{id, name, description, kind:"service", clientId, tokenEndpointAuthMethod, tokenTtlSeconds, status:"active"|"disabled", secretRotatedAt, previousSecretExpiresAt, tokensNotBefore, lastTokenAt, createdAt, updatedAt}`. `kind` and `private_key_jwt` are not accepted yet (`400 validation_error`; unknown body keys are rejected on create).

| Method | Path | Min role | Body / query | Success | Specific errors |
|---|---|---|---|---|---|
| GET | `.../applications` | auditor | `?q=&status=active\|disabled\|needs_attention` | 200 `{items:[{...application, resourceCount, scopeNames}]}` | |
| POST | `.../applications` | admin | `{name, description?, tokenEndpointAuthMethod? ("client_secret_basic" default \| "client_secret_post"), tokenTtlSeconds?}` | 201 `{application, clientSecret}`; the secret is shown once | 409 `application_exists` |
| GET | `.../applications/:appId` | auditor | none | 200 `{application, grants, issuer, tokenEndpoint, recentTokens}` | 404 `application_not_found` |
| PATCH | `.../applications/:appId` | admin | `{name?, description?, tokenEndpointAuthMethod?, tokenTtlSeconds? (or null)}` | 200 application | 404, 409 `application_exists` |
| DELETE | `.../applications/:appId` | admin | none | 204 | 404 |
| POST | `.../applications/:appId/rotate-secret` | admin | `{graceSeconds?}` (0-604800, default 86400) | 200 `{clientSecret, previousSecretExpiresAt}`; the old secret works until then (`null` when 0) | 404 |
| POST | `.../applications/:appId/disable` / `enable` | admin | none | 200 application | 404 |
| POST | `.../applications/:appId/revoke-all-tokens` | admin | none | 200 application (`tokensNotBefore` = now) | 404 |
| GET | `.../applications/:appId/grants` | auditor | none | 200 `{grants:[{resource, scopes:[{id,name}]}]}` | 404 |
| PUT | `.../applications/:appId/grants` | admin | `{scopeIds: uuid[]}` (replaces the whole set, max 500) | 200 `{grants}` | 400 `invalid_scope_ids`, 404 |
| GET | `.../applications/:appId/token-events` | auditor | `?limit=` (1-200, default 50) | 200 `{items}` | 404 |

`...` is `/api/tenants/:tenantId`. "Revoke all" invalidates tokens issued before the call (visible in introspection); it does not change the client secret.

### Resources and scopes

Resource: `{id, name, kind:"api"|"mcp", audience, tokenTtlSeconds, status, createdAt, updatedAt}`. The audience is a URL or a URN and is the exact string clients pass as `resource`. Scope: `{id, resourceId, name, description, agentPolicy, createdAt, updatedAt}`; the name matches `^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$`. `agentPolicy` (`auto`, `approval`, `never`) is stored but only `never` has an effect today (agents cannot get such a scope).

| Method | Path | Min role | Body | Success | Specific errors |
|---|---|---|---|---|---|
| GET | `.../resources` | auditor | none | 200 `[{...resource, scopeCount, appCount, tokens24h}]` | |
| POST | `.../resources` | admin | `{name, audience, kind?, tokenTtlSeconds?}` | 201 resource | 409 `audience_exists`, 409 `resource_name_exists` |
| GET | `.../resources/:resourceId` | auditor | none | 200 `{...resource, scopes:[{...scope, grantedAppCount}], applications:[{id,name,clientId}]}` | 404 `resource_not_found` |
| PATCH | `.../resources/:resourceId` | admin | `{name?, kind?, audience?, tokenTtlSeconds? (or null)}` | 200 resource | 404, 409 |
| DELETE | `.../resources/:resourceId` | admin | none | 204 (scopes and grants cascade) | 404 |
| GET | `.../resources/:resourceId/scopes` | auditor | none | 200 `[scope]` | 404 |
| POST | `.../resources/:resourceId/scopes` | admin | `{name, description?, agentPolicy?}` | 201 scope | 404 `resource_not_found`, 409 `scope_exists` |
| PATCH | `.../resources/:resourceId/scopes/:scopeId` | admin | `{name?, description?, agentPolicy?}` | 200 scope | 404 `scope_not_found`, 409 `scope_exists` |
| DELETE | `.../resources/:resourceId/scopes/:scopeId` | admin | none | 204 | 404 `scope_not_found` |

### Signing keys

| Method | Path | Min role | Success |
|---|---|---|---|
| GET | `.../signing-keys` | auditor | 200 `{items:[{id, kid, algorithm, status:"active"\|"retiring"\|"retired", retiresAt, createdAt}]}`, newest first; no key material |
| POST | `.../signing-keys/rotate` | admin | 201 the new active key; the previous one becomes `retiring` (see [deployment](deployment.md#signing-key-rotation)) |

### Members

Member: `{adminUserId, email, name, role, isActive, lastLoginAt, createdAt}`.

| Method | Path | Min role | Body | Success | Specific errors |
|---|---|---|---|---|---|
| GET | `.../members` | auditor | none | 200 `[member]` | |
| POST | `.../members` | owner | `{email, name?, role}` | 201 `{member, temporaryPassword?}`: an existing user is linked; a new user is created and the temporary password is returned once | 409 `already_member` |
| PATCH | `.../members/:adminUserId` | owner | `{role}` | 200 member | 404 `member_not_found`, 400 `cannot_modify_self`, 409 `last_owner` |
| DELETE | `.../members/:adminUserId` | owner | none | 204 | 404, 400 `cannot_modify_self`, 409 `last_owner` |

### Token log

Event: `{id, applicationId, applicationClientId, resourceId, audience, outcome:"issued"|"denied"|"revoked", reason, scopes, jti, expiresAt, sourceIp, createdAt}`. `reason` on denied events is the OAuth error code or one of `unknown_client`, `auth_method_mismatch`, `bad_secret`, `client_disabled`, `tenant_paused`. Events are purged after `TOKEN_EVENTS_RETENTION_DAYS`.

| Method | Path | Min role | Query | Success | Specific errors |
|---|---|---|---|---|---|
| GET | `.../token-events` | auditor | `outcome`, `applicationId`, `q` (client ID or `jti` prefix), `since` (ISO), `limit` (1-200, default 50), `cursor` | 200 `{items, nextCursor}` | 400 `invalid_cursor` |
| GET | `.../token-events/stats` | auditor | none | 200 `{issued24h, issuedPrev24h, denied24h, requests24h, activeApps24h, totalApps}` | |
