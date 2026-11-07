# Handsal

Handsal is a self-hostable, multi-tenant machine-to-machine OAuth 2.0 authorization server. Services and AI agents authenticate with the client-credentials grant and receive short-lived ES256-signed JWT access tokens that resource servers verify offline against a public JWKS, or online through token introspection. Each tenant has its own issuer (`<PUBLIC_URL>/t/<slug>`), signing keys, applications (clients), resources (audiences) and scopes, plus revocation and a token log. The server ships as one Docker image plus PostgreSQL, with an admin UI and a management REST API.

This repository is a pnpm monorepo with three parts:

- **Platform** — [`apps/api`](apps/api) is the server, [`apps/web`](apps/web) is the admin UI, and [`packages/db`](packages/db) and [`packages/shared`](packages/shared) sit behind them. This is what the Docker image contains.
- **Landing** — [`apps/site`](apps/site) is the public site, including `/docs`. It is static, deployed on its own, and not part of the image. `pnpm site` serves it locally.
- **SDK** — [`packages/sdk`](packages/sdk) (`@handsal/sdk`) checks a bearer token in a Hono, Express, or Next.js app. See [docs/sdk.md](docs/sdk.md).

The longer guides are markdown in [`docs/`](docs/).

## Features (MVP)

- OAuth 2.0 `client_credentials` grant; `client_secret_basic` and `client_secret_post` (the method registered for the application is enforced).
- Multi-tenant: per-tenant issuer, signing keys, applications, resources, scopes, members and roles (`owner`, `admin`, `auditor`).
- Required `resource` parameter (RFC 8707): every token has exactly one audience; scopes are granted per application and per resource.
- ES256 JWTs with per-tenant keys; key rotation (manual or every N days) with a grace period; JWKS and discovery documents (RFC 8414 / OIDC).
- Token introspection (RFC 7662) and revocation (RFC 7009); "revoke all" per application and per tenant.
- Client secret rotation with an overlap window (default 24 h).
- `private_key_jwt` client authentication (RFC 7523, ES256 / P-256 public keys per application, key rotation with a grace period), see the [integration guide](docs/integration.md#5-authenticating-with-private_key_jwt).
- AI-agent applications (`kind: agent`) with guardrails (allowed source CIDRs, scope ceiling per token, hourly token budget) and per-task activity in the token log, see [AI agent applications](docs/integration.md#6-ai-agent-applications).
- Human approval for agent scopes (`agent_policy = approval`): the agent polls with `authorization_pending` until an admin approves or denies, see [Human approval](docs/integration.md#7-human-approval-for-agent-scopes).
- Auto-approve rules for known-safe requests and a per-tenant approval webhook (HMAC-signed, Slack-compatible).
- Token exchange (RFC 8693) with the `act` claim for delegation: agents act for users (external IdP) or services, see [Delegation](docs/integration.md#8-delegation-token-exchange).
- Admin UI (tenants, applications, resources and scopes, token log, settings) and a management API (session cookie).
- Token log with configurable retention, security events as structured JSON logs, in-memory rate limits.
- Headless mode (`ENABLE_ADMIN_PANEL=false`) for a pure issuer.

## Quickstart (5 minutes)

Requirements: Docker with Compose and a public `https://` URL (or a TLS-terminating proxy in front of port 3000). In production mode Handsal refuses an `http://` `PUBLIC_URL`, and the admin session cookie is `Secure`, so a plain-HTTP trial is not possible; for a local try-out use [Development](#development).

```bash
git clone <this repository> handsal && cd handsal
cp .env.example .env

# Generate two secrets
openssl rand -hex 32   # KEY_ENCRYPTION_SECRET (exactly 64 hex chars)
openssl rand -hex 32   # POSTGRES_PASSWORD
```

Edit `.env` (set or replace these lines):

```bash
PUBLIC_URL=https://auth.example.com
KEY_ENCRYPTION_SECRET=<64 hex chars>
POSTGRES_PASSWORD=<generated>
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=<at least 12 chars>
CORS_ORIGINS=https://auth.example.com   # must not contain "localhost" in production
TRUST_PROXY=true                         # when behind a reverse proxy
```

Start it. The compose file pulls `ghcr.io/wfalowski/handsal:latest`. To build from this checkout instead, change that service to `build: .`.

```bash
docker compose -f docker-compose.prod.yml up -d
curl -s http://localhost:3000/ready      # {"status":"ok"} once migrations are done
```

Open `https://auth.example.com`, sign in with the bootstrap admin, then:

1. **Tenants > New tenant**: name `Acme`, slug `acme`. The issuer is `https://auth.example.com/t/acme`.
2. **Resources > New resource**: name `Orders API`, audience `https://api.acme.example/orders`. Add scopes `orders:read` and `orders:write`.
3. **Applications > New application**: name `billing-service`. Copy the client secret now; it is shown once.
4. Open the application, **Access**, and grant `orders:read` (and optionally `orders:write`) on `Orders API`.

Request a token:

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  --data-urlencode "resource=https://api.acme.example/orders" \
  --data-urlencode "scope=orders:read" \
  https://auth.example.com/t/acme/oauth/token
# {"access_token":"eyJ...","token_type":"Bearer","expires_in":3600,"scope":"orders:read"}
```

Verify it with introspection (any application of the tenant can call it):

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" -d "token=$ACCESS_TOKEN" \
  https://auth.example.com/t/acme/oauth/introspect
# {"active":true,"scope":"orders:read","client_id":"app_...","aud":"https://api.acme.example/orders",...}
```

Next: [docs/integration.md](docs/integration.md) (client and resource-server code), [docs/deployment.md](docs/deployment.md), [docs/api.md](docs/api.md).

## Development

Requirements: Node 24, pnpm 9, Docker.

```bash
docker compose up -d      # PostgreSQL on localhost:5434
cp .env.example .env      # defaults work for development
pnpm install
pnpm db:migrate
pnpm dev                  # API on :3000, admin UI on :5173
```

- `pnpm test` runs Vitest. API and DB tests need PostgreSQL and use `TEST_DATABASE_URL` (default `postgresql://handsal:handsal_dev@localhost:5434/handsal_test`; the database name must end in `_test`). Run `pnpm db:migrate` against it first.
- `pnpm smoke` runs `scripts/smoke.sh` against a running instance (`SMOKE_ADMIN_EMAIL` and `SMOKE_ADMIN_PASSWORD` of a super-admin; see `scripts/README.md`).
- Also: `pnpm check` (Biome), `pnpm typecheck`, `pnpm build`, `pnpm db:generate`, `pnpm db:seed`.
- `pnpm site` runs the marketing page (`apps/site`) on port 4321. It is a static Astro site, deployed separately from the Docker image. See [Landing](docs/deployment.md#landing). The same site serves `/docs` from the markdown in `docs/`.
- `@handsal/sdk` (`packages/sdk`) verifies access tokens in a Hono, Express, or Next.js API. See [docs/sdk.md](docs/sdk.md).

## Environment reference

Env is read only in `apps/api/src/env.ts`; the process exits at startup on invalid values. `.env.example` is the template. `POSTGRES_PASSWORD` is read by `docker-compose.prod.yml`, not by the app.

| Variable | Required | Default | Notes | Production rule |
|---|---|---|---|---|
| `DATABASE_URL` | yes | none | PostgreSQL connection string. Overridden by `docker-compose.prod.yml`. | |
| `PUBLIC_URL` | yes | none | Base URL of this instance; issuer is `${PUBLIC_URL}/t/<slug>`. Trailing slash removed. | Must be `https://` |
| `KEY_ENCRYPTION_SECRET` | yes | none | 64 hex chars. Encrypts signing keys at rest and derives the admin session and CSRF keys. | Placeholder and repeated-block values rejected |
| `BOOTSTRAP_ADMIN_EMAIL` | no | unset | Creates the first super-admin when `admin_users` is empty. Set together with the password. | Both or neither |
| `BOOTSTRAP_ADMIN_PASSWORD` | no | unset | Min 12 chars. | `change-me` rejected |
| `NODE_ENV` | no | `development` | `development`, `test`, `production`. Set by `docker-compose.prod.yml`. | |
| `PORT` | no | `3000` | HTTP port. | |
| `LOG_LEVEL` | no | `info` | `fatal`, `error`, `warn`, `info`, `debug`, `trace`, `silent`. | |
| `CORS_ORIGINS` | no | `http://localhost:5173` | Comma-separated origins allowed on `/api/*`. Dev only; the UI is same-origin in production. | Must not contain `localhost`, so set it explicitly |
| `TRUST_PROXY` | no | `false` | `true` behind a reverse proxy. `X-Forwarded-For` is used only when the TCP peer is loopback, private, link-local or CGNAT. | Startup warning if not `true` |
| `TRUST_PROXY_HOP_COUNT` | no | `1` | Trusted proxy hops, counted from the right of `X-Forwarded-For`. | |
| `ENABLE_ADMIN_PANEL` | no | `true` | `false` disables the admin UI and `/api` (headless issuer). | |
| `RATE_LIMIT_TOKEN_IP_MAX` | no | `600` | Requests per minute per IP on `/oauth/token`. | |
| `RATE_LIMIT_TOKEN_CLIENT_MAX` | no | `600` | Per minute per `client_id` on `/oauth/token`. | |
| `RATE_LIMIT_INTROSPECT_IP_MAX` | no | `1200` | Per minute per IP on `/oauth/introspect`. | |
| `RATE_LIMIT_INTROSPECT_CLIENT_MAX` | no | `600` | Per minute per `client_id` on `/oauth/introspect`. | |
| `RATE_LIMIT_REVOKE_IP_MAX` | no | `200` | Per minute per IP on `/oauth/revoke`. | |
| `RATE_LIMIT_REVOKE_CLIENT_MAX` | no | `100` | Per minute per `client_id` on `/oauth/revoke`. | |
| `TOKEN_EVENTS_RETENTION_DAYS` | no | `30` | Token log retention; purged daily. | |
| `TEST_DATABASE_URL` | tests only | `...:5434/handsal_test` | Test database; name must end in `_test`. | |

## Endpoints

Per tenant, under the issuer `https://<host>/t/<slug>`:

| Method | Path | Purpose |
|---|---|---|
| POST | `/oauth/token` | Client-credentials token request |
| POST | `/oauth/introspect` | RFC 7662 introspection |
| POST | `/oauth/revoke` | RFC 7009 revocation |
| GET | `/.well-known/openid-configuration` | Discovery document |
| GET | `/.well-known/oauth-authorization-server` | Same document (RFC 8414) |
| GET | `/.well-known/jwks.json` | Public signing keys |

Instance level: `GET /health` (process is up, returns the version), `GET /ready` (database reachable, else 503), `/api/*` management API (admin session), `/` admin UI. Full reference: [docs/api.md](docs/api.md).

## Examples

- [examples/mcp-agent](examples/mcp-agent/README.md): an MCP server (stdio) that lets an AI agent call Handsal-protected APIs with `private_key_jwt` and human approval, without the model ever seeing a token.

## Security model

- Client secrets (`hs_` + 48 base62 chars) and admin passwords are hashed with Argon2id; secrets are shown once. Authentication failures cost one Argon2 verification even for unknown clients and return the same `invalid_client` for every reason.
- Each tenant has its own ES256 key pair. Private keys are stored AES-256-GCM encrypted with `KEY_ENCRYPTION_SECRET`, so a database dump alone does not yield signing keys. Keep the secret out of database backups.
- Every query on tenant data is scoped by `tenant_id` taken from the URL or session. A `resource` of another tenant is indistinguishable from an unknown one (`invalid_target`).
- Rate limits are in-memory and per process: per IP and per `client_id` on the OAuth endpoints (defaults above), 5 login attempts per 15 minutes per IP on the admin login. Run a single replica, or also limit at the proxy.
- Admin sessions are HMAC-signed `SameSite=Strict` cookies (12 h) with a CSRF header on mutating calls. Logging out bumps `session_version`, so a copied cookie stops working.
- Revocation: introspection reports a revoked token, a "revoke all" mark, a disabled application or a paused tenant as `active:false`. A resource server that only verifies the JWT locally (signature, `iss`, `aud`, `exp`) never sees any of that; the token stays valid there until it expires. Use short TTLs, and call introspection for operations where immediate revocation matters. See [docs/integration.md](docs/integration.md).

## Project status and license

Handsal is licensed under the [Apache License, Version 2.0](LICENSE).

An enterprise edition with additional features may follow later, as its own package under a separate commercial license.

## Contributing

Open an issue before sending a change.
Before submitting, run `pnpm check && pnpm typecheck && pnpm test`.
