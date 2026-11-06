# Handsal — open-source multi-tenant M2M OAuth 2.0 server (client credentials, ES256 JWTs)

Self-hostable authorization server for services (and later AI agents) talking to each other. Each tenant has its own issuer `${PUBLIC_URL}/t/<slug>`, signing keys, applications (clients), resources (audiences) and scopes. Ships as one Docker image + PostgreSQL.

**Work is driven by `Tasks.md`** — read it first; it holds product decisions, the data model, the API surface, conventions, and per-task agent briefs. Design spec lives in `docs/design/*.dc.html`.

## Commands
- `docker compose up -d` — local PostgreSQL (`postgresql://handsal:handsal_dev@localhost:5434/handsal`)
- `pnpm dev` — API `:3000` + web `:5173` (turbo, watch)
- `pnpm build` / `pnpm typecheck` / `pnpm check` (Biome lint+format) / `pnpm check:fix`
- `pnpm test` — vitest (`apps/api`, `packages/shared`, `packages/db`); API/db tests need Postgres + `pnpm db:migrate`
- `pnpm db:generate` / `pnpm db:migrate` / `pnpm db:seed`
- `docker build -t handsal .` ; `docker compose -f docker-compose.prod.yml up -d`

## Architecture
- `apps/api` — Hono (Node 24). `src/routes/oauth/*` mounted at `/t/:slug` (token, introspect, revoke, discovery, jwks); `src/routes/management/*` at `/api` (session cookie or `ADMIN_API_KEY`); `src/services/*` business logic (first arg is always `tenantId`); `src/jobs/*` interval jobs (key rotation/retirement, revoked-token purge, token-event retention); `src/utils/*` crypto/jwt/keys; serves `apps/web/dist` from `./public` in production.
- `apps/web` — React 19 + TanStack Router/Query + Tailwind admin UI.
- `packages/db` — Drizzle schema + migrations (`drizzle/*.sql`, run at startup), seed.
- `packages/shared` — Zod schemas, constants, DTO types shared by api + web.

## Conventions
- Biome only. TS strict, ESM, `.js` extensions in relative imports (api, packages).
- Env is read only in `apps/api/src/env.ts`; `index.ts` imports it before anything else.
- Every query on a tenant-owned table filters by `tenant_id` from URL/session, never from the body.
- Secrets Argon2id-hashed; signing private keys AES-256-GCM encrypted with `KEY_ENCRYPTION_SECRET`; nothing secret in `.env.example` that passes in production.
- Schema changes: edit `packages/db/src/schema`, `pnpm db:generate`, never hand-edit SQL.
- Integration tests hit the real Postgres; no Drizzle mocks.
- No vendor-specific code. This is a generic open-source product. No LICENSE yet (intentional).
