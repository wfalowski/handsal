# scripts

`smoke.sh` is an end-to-end smoke test for a running Handsal instance. It needs only `bash`, `curl`, `jq` and `base64`.
It creates a throwaway tenant (`smoke-<6 hex>`) via the management API, then checks the OAuth flow:
discovery, JWKS, `client_credentials` token (claims decoded), introspection, revocation, and the negative cases.
The tenant is deleted on exit, also on failure. Exit code 0 means every assertion passed.

Local: run `pnpm dev`. `pnpm db:seed` creates a super-admin `admin@handsal.local` / `handsal-dev-password`. Then
`SMOKE_ADMIN_EMAIL=admin@handsal.local SMOKE_ADMIN_PASSWORD=handsal-dev-password pnpm smoke`
(`HANDSAL_URL` defaults to `http://localhost:3000`).
Production compose: `docker compose -f docker-compose.prod.yml up -d`, then
`HANDSAL_URL=http://localhost:3000 SMOKE_ADMIN_EMAIL=<email> SMOKE_ADMIN_PASSWORD=<password> pnpm smoke`.
