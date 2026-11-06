# Deployment

Handsal runs as one container (API, admin UI and background jobs in a single Node process) next to PostgreSQL 16. `docker-compose.prod.yml` wires both. The variables are described in the [README](../README.md#environment-reference).

## Image

<!-- written by Task 5.1 -->

## Secrets

Generate every secret per environment; never reuse the values from `.env.example`.

```bash
openssl rand -hex 32   # KEY_ENCRYPTION_SECRET (exactly 64 hex chars)
openssl rand -hex 32   # POSTGRES_PASSWORD
openssl rand -hex 32   # ADMIN_API_KEY (optional, 64 chars; production needs at least 48)
```

In production the process refuses to start when `KEY_ENCRYPTION_SECRET` is the `.env.example` placeholder or a repeated pattern, when `PUBLIC_URL` is not `https://`, when `CORS_ORIGINS` contains `localhost`, or when `BOOTSTRAP_ADMIN_PASSWORD` is `change-me`. `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` (min 12 chars) only take effect when the `admin_users` table is empty; changing them later does nothing. Remove them from `.env` after the first start if you prefer.

### Rotating secrets

- `ADMIN_API_KEY`: change it and restart. Nothing else depends on it.
- Client secrets: rotate per application in the UI or with `POST .../rotate-secret`; the old secret keeps working for `graceSeconds` (default 24 h).
- `KEY_ENCRYPTION_SECRET`: it encrypts the signing private keys and derives the admin session and CSRF keys. Changing it signs every admin user out and makes all stored signing keys undecryptable, so token issuance fails (HTTP 500) until the keys are replaced. There is no re-encryption tool. Procedure:
  1. Take a database backup (see below) and stop the `handsal` container.
  2. Retire the old keys: `docker compose -f docker-compose.prod.yml exec postgres psql -U handsal -d handsal -c "UPDATE signing_keys SET status = 'retired';"`
  3. Set the new `KEY_ENCRYPTION_SECRET` in `.env` and start the container. Each tenant gets a fresh active key on its next token request or JWKS fetch.
  4. Every token issued before the change fails verification (the old public keys are no longer in the JWKS); services obtain new tokens on their next request. Plan the change for a quiet moment, and keep the old secret until you have confirmed that everything works, because without it the old backup cannot be used to restore tokens.

## Reverse proxy and TLS

Handsal speaks plain HTTP on `PORT` (3000). Terminate TLS in a proxy and forward to it. Publish the container port on loopback only (`"127.0.0.1:3000:3000"` in the compose file's `ports`) so that clients cannot bypass the proxy.

Caddy (adds `X-Forwarded-For` itself):

```
auth.example.com {
    reverse_proxy 127.0.0.1:3000
}
```

nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:3000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Set `TRUST_PROXY=true` and `TRUST_PROXY_HOP_COUNT` to the number of proxies in front of Handsal (1 for a single proxy, 2 for a CDN plus a proxy). The client IP is the entry that many positions from the right of `X-Forwarded-For`; entries further left are client-controlled and ignored. Without `TRUST_PROXY=true`, all requests share the proxy's address: per-IP rate limits collapse into one bucket and token events and security logs record the proxy IP. A startup warning reminds you in production. A request body above 16 KiB on `/t/*` is rejected with 413.

Point your orchestrator at `GET /health` (process is up) and `GET /ready` (executes `select 1`; 503 `db_unavailable` otherwise).

## Database

Handsal needs PostgreSQL 16 and creates its schema itself. Tenant data, hashed client secrets, encrypted signing keys and the token log all live in this one database.

Backup (custom format, restorable selectively):

```bash
docker compose -f docker-compose.prod.yml exec -T postgres \
  pg_dump -U handsal -d handsal -Fc > handsal-$(date +%F).dump
```

Restore into an empty database (stop `handsal` first):

```bash
docker compose -f docker-compose.prod.yml exec -T postgres \
  pg_restore -U handsal -d handsal --clean --if-exists --no-owner < handsal-2026-01-01.dump
```

A dump holds signing keys only in encrypted form. Store `KEY_ENCRYPTION_SECRET` separately from the dumps (a password manager or secret store): the dump is useless for issuing tokens without it, and anyone holding both can mint tokens. The token log is the only fast-growing table; `TOKEN_EVENTS_RETENTION_DAYS` (default 30) bounds it. Test restores regularly.

## Upgrading

```bash
docker compose -f docker-compose.prod.yml pull
docker compose -f docker-compose.prod.yml up -d
```

Migrations are forward-only and run at process start, before the server accepts traffic. Back up first; a migration cannot be rolled back by starting an older image. During the restart the instance is unavailable for a few seconds, and in-memory rate-limit counters reset. Services that cache tokens keep working, since resource servers verify against a cached JWKS. For several replicas, upgrade one first and wait for `/ready` before starting the others, so that two new-version processes do not run the same migration concurrently. Zero-downtime upgrades are only safe for releases whose migrations are backward compatible with the previous version; check the release notes.

Rate limits are per process (in memory), so with N replicas the effective limit is N times the configured value.

## Signing key rotation

Each tenant has exactly one `active` key. New tokens are always signed with it, never with a retiring key.

| State | Signs new tokens | In JWKS | Verifies tokens (introspection) |
|---|---|---|---|
| `active` | yes | yes | yes |
| `retiring` | no | yes, until `retires_at` | yes, until `retires_at` |
| `retired` | no | no | no |

Rotation (UI "Rotate key", `POST /api/tenants/:tenantId/signing-keys/rotate`, or automatic) turns the active key into `retiring`, sets `retires_at = now + the longest token TTL configurable in the tenant` (tenant default, every resource and application override, at least 60 s), and creates a new active key. Every token the old key signed has expired by then. An hourly job flips expired `retiring` keys to `retired`.

Automatic rotation: set `keyRotationDays` (1 to 3650) on the tenant, via the UI or `PATCH /api/tenants/:tenantId`; `null` means manual only. The same hourly job rotates a tenant whose active key is older than that.

Resource servers must fetch keys from the JWKS by `kid` and tolerate new keys appearing: the JWKS is served with `Cache-Control: public, max-age=300`, and clients such as `jose` refetch when they see an unknown `kid`. Do not pin a key. The JWKS keeps working for a paused tenant so tokens issued earlier stay verifiable.

## Revocation caveat

Revoking a token (`/oauth/revoke`), "revoke all" (application or tenant), disabling an application and pausing a tenant take effect in introspection immediately. A resource server that validates the JWT locally never calls Handsal again, so it keeps accepting such a token until `exp`. To limit exposure, use short TTLs (`60` to `86400` s, set per tenant, resource or application) and call `/oauth/introspect` for sensitive operations. After a suspected leak: rotate the client secret with `graceSeconds: 0`, run "revoke all" on the application, and, if the signing key is suspect, rotate it and retire the old key at once in the database (`UPDATE signing_keys SET status = 'retired' WHERE tenant_id = '<id>' AND status = 'retiring';`).

## Headless mode

`ENABLE_ADMIN_PANEL=false` serves only the OAuth endpoints, `/health` and `/ready`; the admin UI is not served and `/api/*` answers `404 {"error":"not_found"}`. Create tenants, resources and applications first with the panel enabled, either before switching or in a second, private instance that uses the same database and the same `KEY_ENCRYPTION_SECRET`. A common layout is a public headless issuer plus an internal admin instance.

## Observability

- Logs are pino JSON on stdout (`LOG_LEVEL`, default `info`); each request is logged, and an `X-Request-Id` header is accepted or generated and echoed back.
- Security events carry `"security": true`, `"module": "security"`, an `event` name and a `severity` (`LOW` logs as info, `MEDIUM`/`HIGH` as warn, `CRITICAL` as fatal). Events: `client_auth_failure`, `admin_login_failure`, `admin_login_success`, `admin_logout`, `admin_auth_failure`, `rate_limit_exceeded`, `invalid_scope_request`, `malformed_request`, `unsupported_grant_type`. Failure logs include `reason` (`unknown_client`, `auth_method_mismatch`, `bad_secret`, `client_disabled`) that is never returned to the caller. Alert on bursts of `client_auth_failure` and `rate_limit_exceeded`.
- The token log (UI "Tokens", `GET /api/tenants/:tenantId/token-events`) records issued, denied and revoked events with reason, scopes, `jti` and source IP.
- Background jobs (key rotation and retirement hourly, revoked-token purge hourly, token-log retention daily) run in-process and log failures as `Job failed`.
- Shutdown on `SIGTERM` is graceful (10 s limit).
