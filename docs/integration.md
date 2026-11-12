---
title: Integration
description: Request a token, verify it, and use private keys, agents, and delegation.
---

# Integration guide

Two roles are involved. A **service** (client) obtains an access token from Handsal and sends it to a **resource server**, which verifies it. In the examples:

- Issuer: `https://auth.example.com/t/acme` (`<PUBLIC_URL>/t/<tenant-slug>`; shown in the UI and in the discovery document).
- Resource (audience): `https://api.acme.example/orders`, with scopes `orders:read` and `orders:write`.
- The application has been granted those scopes on that resource; `CLIENT_ID` is `app_...`, `CLIENT_SECRET` is `hs_...`.

## 1. Service: obtaining a token

`POST <issuer>/oauth/token`, `application/x-www-form-urlencoded`, with:

| Parameter | Required | Notes |
|---|---|---|
| `grant_type` | yes | `client_credentials` |
| `resource` | yes | The audience of the API you are calling. Exactly one. Must be a resource your application has at least one granted scope on. |
| `scope` | no | Space-separated subset of the scopes granted on that resource. Omitted: all granted scopes on that resource. |
| client credentials | yes | HTTP Basic (`client_secret_basic`, the default) or `client_id` + `client_secret` in the body (`client_secret_post`), or a signed assertion (`private_key_jwt`, see [section 5](#5-authenticating-with-private_key_jwt)). Use the method registered for the application; the others are rejected with `invalid_client`. Never send two methods at once. |

Response: `{"access_token":"<jwt>","token_type":"Bearer","expires_in":3600,"scope":"orders:read"}` with `Cache-Control: no-store`.

### curl

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  --data-urlencode "resource=https://api.acme.example/orders" \
  --data-urlencode "scope=orders:read orders:write" \
  https://auth.example.com/t/acme/oauth/token
```

### Node (`@handsal/sdk`)

The client caches the token until 30 seconds before `exp` and shares one request across concurrent calls. Use `authentication: "client_secret_post"` when the application is registered that way.

```ts
import { createHandsalClient } from "@handsal/sdk";

const orders = createHandsalClient({
  issuer: "https://auth.example.com/t/acme",
  clientId: process.env.CLIENT_ID ?? "",
  clientSecret: process.env.CLIENT_SECRET ?? "",
  resource: "https://api.acme.example/orders",
  scope: "orders:read orders:write",
});

const authorization = await orders.authorization();
```

### Python (requests)

```python
import os, time, requests

ISSUER = "https://auth.example.com/t/acme"
_cache = {"token": None, "expires_at": 0.0}

def get_token() -> str:
    if _cache["token"] and time.time() < _cache["expires_at"] - 30:
        return _cache["token"]
    r = requests.post(
        f"{ISSUER}/oauth/token",
        auth=(os.environ["CLIENT_ID"], os.environ["CLIENT_SECRET"]),
        data={
            "grant_type": "client_credentials",
            "resource": "https://api.acme.example/orders",
            "scope": "orders:read",
        },
        timeout=10,
    )
    body = r.json()
    if not r.ok:
        raise RuntimeError(f"{r.status_code} {body.get('error')}: {body.get('error_description')}")
    _cache.update(token=body["access_token"], expires_at=time.time() + body["expires_in"])
    return _cache["token"]
```

### Caching and errors

Request a token once and reuse it until shortly before `expires_in` elapses (30 s margin above); one token per (resource, scope set). Do not request a token per call: the token endpoint is rate limited and every request is Argon2-verified. Cache per process; the token is a bearer credential, so keep it out of logs.

| Response | Meaning | What to do |
|---|---|---|
| 401 `invalid_client` | Unknown client, wrong or expired secret, application disabled, or credentials sent by the wrong method. The message is always the same. | Do not retry in a loop. Check the secret and that the method matches the application's setting (Basic vs body); after a rotation, switch to the new secret before the grace period ends. |
| 400 `invalid_scope` | A requested scope is not granted to the application on that resource. | Fix the request or grant the scope in the UI. |
| 400 `invalid_target` | `resource` is missing, unknown, disabled, or the application has no granted scope on it. | Check the audience string (exact match, including trailing slash) and the grants. |
| 400 `invalid_request` | Malformed request, mixed client auth methods, wrong `Content-Type`, or `tenant paused`. | Fix the request; for a paused tenant wait for the owner to resume it. |
| 400 `unsupported_grant_type` | Only `client_credentials` exists. | |
| 429 `too_many_requests` | Rate limit hit, or an agent's hourly token budget (see [section 6](#6-ai-agent-applications)). | Wait for the `Retry-After` header (seconds) and retry with backoff; cache tokens. |
| 5xx | Server or database trouble. | Retry with exponential backoff and jitter. |

## 2. Resource server: verifying a token locally

Fetch the tenant's public keys from `<issuer>/.well-known/jwks.json` and verify every incoming `Authorization: Bearer` token:

- signature with `ES256` only (reject any other `alg`, in particular `none`);
- `iss` equals the issuer, including the tenant slug;
- `aud` equals **your own** audience string (the `resource` value); a token for another API of the same tenant must be rejected;
- `exp` has not passed (libraries do this);
- the `scope` claim (space-separated string) contains what the endpoint needs.

Tokens carry the header `typ: at+jwt` and the claims `iss`, `sub` and `client_id` (both the application's client ID), `aud`, `scope`, `tenant` (slug), `client_kind` (`service` or `agent`), `jti`, `iat`, `exp`. Agent tokens may also carry `task_id` (see [AI agent applications](#6-ai-agent-applications)).

### Node (jose)

```js
import { createRemoteJWKSet, jwtVerify } from "jose";

const ISSUER = "https://auth.example.com/t/acme";
const AUDIENCE = "https://api.acme.example/orders";
// Caches keys, refetches on an unknown kid, so key rotation needs no restart.
const jwks = createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`));

export async function verify(token, requiredScope) {
  const { payload } = await jwtVerify(token, jwks, {
    issuer: ISSUER,
    audience: AUDIENCE,
    algorithms: ["ES256"],
    typ: "at+jwt",
  });
  const scopes = String(payload.scope ?? "").split(" ");
  if (requiredScope && !scopes.includes(requiredScope)) {
    throw new Error("insufficient_scope");
  }
  return payload; // payload.client_id identifies the calling application
}
```

### Hono middleware

```ts
import { createMiddleware } from "hono/factory";
import { HTTPException } from "hono/http-exception";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

const ISSUER = "https://auth.example.com/t/acme";
const jwks = createRemoteJWKSet(new URL(`${ISSUER}/.well-known/jwks.json`));

export const requireScope = (scope: string) =>
  createMiddleware<{ Variables: { token: JWTPayload } }>(async (c, next) => {
    const header = c.req.header("Authorization");
    if (!header?.startsWith("Bearer ")) {
      throw new HTTPException(401, { res: new Response(null, { status: 401, headers: { "WWW-Authenticate": "Bearer" } }) });
    }
    try {
      const { payload } = await jwtVerify(header.slice(7), jwks, {
        issuer: ISSUER,
        audience: "https://api.acme.example/orders",
        algorithms: ["ES256"],
        typ: "at+jwt",
      });
      if (!String(payload.scope ?? "").split(" ").includes(scope)) {
        throw new HTTPException(403, { message: "insufficient_scope" });
      }
      c.set("token", payload);
    } catch (err) {
      if (err instanceof HTTPException) throw err;
      throw new HTTPException(401, { message: "invalid_token" });
    }
    await next();
  });

// app.get("/orders", requireScope("orders:read"), (c) => c.json([]));
```

### Python (PyJWT)

```python
# pip install "pyjwt[crypto]"
import jwt
from jwt import PyJWKClient

ISSUER = "https://auth.example.com/t/acme"
AUDIENCE = "https://api.acme.example/orders"
jwks_client = PyJWKClient(f"{ISSUER}/.well-known/jwks.json", cache_keys=True)

def verify(token: str, required_scope: str | None = None) -> dict:
    key = jwks_client.get_signing_key_from_jwt(token)  # picks the key by kid
    claims = jwt.decode(
        token,
        key.key,
        algorithms=["ES256"],
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"require": ["exp", "iss", "aud"]},
    )
    if required_scope and required_scope not in claims.get("scope", "").split():
        raise PermissionError("insufficient_scope")
    return claims
```

Respond `401` for a missing or invalid token and `403` for a valid token without the scope.

`@handsal/sdk` (`packages/sdk`) does this check for Hono, Express, and Next.js. See [sdk.md](sdk.md).

## 3. Introspection: when local verification is not enough

A JWT verified locally stays acceptable until `exp`, even after the token was revoked, the application was disabled, "revoke all" was used, or the tenant was paused. For operations where that window is unacceptable (payments, deletions, admin actions), ask Handsal: `POST <issuer>/oauth/introspect` with the token, authenticated as any application of the same tenant (Basic or body, per its registered method). Your resource server therefore needs its own application and secret.

```bash
curl -s -u "$RS_CLIENT_ID:$RS_CLIENT_SECRET" -d "token=$ACCESS_TOKEN" \
  https://auth.example.com/t/acme/oauth/introspect
```

Active token:

```json
{"active":true,"scope":"orders:read","client_id":"app_x7k2...","token_type":"Bearer","exp":1767225600,"iat":1767222000,"sub":"app_x7k2...","aud":"https://api.acme.example/orders","iss":"https://auth.example.com/t/acme","jti":"0b1c...","tenant":"acme","client_kind":"service"}
```

Anything else (invalid, expired, revoked, issued before a "revoke all", disabled application, paused tenant, another tenant's token) returns exactly `{"active":false}` with HTTP 200. Introspection does not check `aud` for you: compare the returned `aud` with your audience, and check `scope`. If the endpoint answers anything other than 200 (401, 429, 5xx, or 404 when introspection is disabled for the tenant), treat the token as not verified (fail closed). Introspection is rate limited (1200 per minute per IP and 600 per client by default); verify locally first and introspect only where it matters, optionally caching a positive answer for a few seconds.

The token's owner can revoke it with `POST <issuer>/oauth/revoke` (`token=<jwt>`, same client authentication). The answer is always 200 with an empty body, also for unknown tokens and tokens that belong to another application.

## 4. Discovery

`GET <issuer>/.well-known/openid-configuration` (identical to `/.well-known/oauth-authorization-server`, cacheable for 5 minutes) lets clients avoid hard-coded URLs:

```json
{
  "issuer": "https://auth.example.com/t/acme",
  "token_endpoint": "https://auth.example.com/t/acme/oauth/token",
  "introspection_endpoint": "https://auth.example.com/t/acme/oauth/introspect",
  "revocation_endpoint": "https://auth.example.com/t/acme/oauth/revoke",
  "jwks_uri": "https://auth.example.com/t/acme/.well-known/jwks.json",
  "grant_types_supported": ["client_credentials"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "private_key_jwt"],
  "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
  "id_token_signing_alg_values_supported": ["ES256"]
}
```

`introspection_endpoint` is omitted when introspection is disabled for the tenant. The document does not list the tenant's scopes. Read `token_endpoint` and `jwks_uri` from this document at startup instead of building the paths by hand; validate that `issuer` equals the value you configured.

## 5. Authenticating with private_key_jwt

Instead of a shared secret, the application proves its identity with a short-lived JWT signed by a private key that only the client holds (RFC 7523). Handsal stores only the public key. Only ES256 / P-256 keys are supported.

1. **Generate a key pair** (keep `key.pem` in your secret store):

   ```bash
   openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out key.pem
   openssl pkey -in key.pem -pubout -out pub.pem   # SPKI PEM: "-----BEGIN PUBLIC KEY-----"
   ```

2. **Register the public key**, in the UI (application detail) or through the management API (`admin` role; the `kid` is your choice, up to 128 characters of `A-Za-z0-9._:-`, unique per application). Management calls send the `handsal_session` cookie and `X-CSRF-Token` returned by `POST /api/auth/login`.

   ```bash
   curl -s -X POST -H "Cookie: handsal_session=$SESSION" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
     -d "$(jq -n --arg pem "$(cat pub.pem)" '{kid:"key-2026-11", publicKeyPem:$pem}')" \
     https://auth.example.com/api/tenants/$TENANT_ID/applications/$APP_ID/keys
   ```

   Anything other than a P-256 SPKI public key (a private key, a certificate, an RSA key) is `400 invalid_public_key`; a duplicate `kid` or key is `409 application_key_exists`.

3. **Switch the authentication method** to `private_key_jwt` (`PATCH .../applications/$APP_ID` with `{"tokenEndpointAuthMethod":"private_key_jwt"}`, or in the UI). The application needs at least one `active` key, otherwise the call fails with `409 no_application_key`; for the same reason an application cannot be created with this method. From then on, Basic and body secrets are rejected for this application (`invalid_client`).

4. **Build a new assertion for every token request:**

   | Part | Value |
   |---|---|
   | header | `alg=ES256`, `kid=<registered kid>` |
   | `iss`, `sub` | the application's `client_id` |
   | `aud` | the tenant's token endpoint URL, exactly: `https://auth.example.com/t/acme/oauth/token`. Use this value for introspect and revoke too. |
   | `exp` | required, at most 300 s after now (60 s clock tolerance applies) |
   | `iat` | optional; not more than 60 s in the future |
   | `jti` | required, unique per assertion (a UUID) |

5. **Send it** to `/oauth/token` with `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion=<jwt>`. Send both parameters together. `client_id` is optional; when sent it must equal the assertion's `iss`. Do not combine the assertion with Basic or `client_secret` (`400 invalid_request`). The same two parameters authenticate `/oauth/introspect` and `/oauth/revoke`.

Node (jose), producing the assertion:

```js
// sign.mjs: `node sign.mjs` prints the assertion
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { importPKCS8, SignJWT } from "jose";

const { CLIENT_ID, KID, TOKEN_ENDPOINT } = process.env; // https://auth.example.com/t/acme/oauth/token
const key = await importPKCS8(readFileSync("key.pem", "utf8"), "ES256");
console.log(
  await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: KID })
    .setIssuer(CLIENT_ID)
    .setSubject(CLIENT_ID)
    .setAudience(TOKEN_ENDPOINT)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(randomUUID())
    .sign(key),
);
```

```bash
export CLIENT_ID=app_x7k2... KID=key-2026-11 TOKEN_ENDPOINT=https://auth.example.com/t/acme/oauth/token
curl -s "$TOKEN_ENDPOINT" \
  -d grant_type=client_credentials \
  -d resource=https://api.acme.example/orders \
  -d scope=orders:read \
  -d client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer \
  --data-urlencode "client_assertion=$(node sign.mjs)"
```

Every authentication failure is `401 invalid_client` with the same message. The reason (`bad_assertion`, `unknown_assertion_key`, `assertion_expired`, `assertion_replayed`, `unknown_client`, `auth_method_mismatch`, `client_disabled`) is only in the token log and the server logs. `bad_assertion` covers a wrong `alg`, signature, `iss`, `sub` or `aud`, a missing `jti` or `exp`, and a lifetime above 300 s; check `aud` first, it must match the server's `PUBLIC_URL`.

**Key rotation.** Register the new key (it is `active` at once; several active keys are allowed), start signing with its `kid`, then retire the old one: `POST .../keys/$KEY_ID/retire` with `{"graceSeconds":86400}` (0 to 604800, default 86400). A `retiring` key keeps verifying assertions until the grace period ends; `DELETE .../keys/$KEY_ID` removes a key immediately. Handsal does not stop you from retiring the last active key: the client is locked out when its grace period ends.

**Limitation.** Replay protection for `jti` is per process (in memory). With several replicas, a captured assertion can be replayed once per replica until it expires, at most about 6 minutes. Keep lifetimes short; see [deployment](deployment.md#several-replicas).

## 6. AI agent applications

An application of `kind: "agent"` represents an AI agent or other automated actor. It uses the same token endpoint and any of the three authentication methods (`private_key_jwt` is the better fit). The kind is chosen at creation and cannot be changed; its tokens carry `client_kind: "agent"`.

**Task grouping.** The optional form parameter `task_id` (1 to 128 characters of `A-Za-z0-9._:-`) names the job the agent is working on. It becomes the `task_id` claim of the access token and groups the token events, which the admin UI and `GET .../token-events?taskId=` show per task. A value that does not match the format is `400 invalid_request`.


**Guardrails** are fields of the agent application (UI, or `allowedCidrs`, `maxScopesPerToken`, `tokenBudgetPerHour` plus the informational `agentRuntime` and `operatorEmail` in the [management API](api.md#applications)). They are checked on every token request after authentication:

| Guardrail | Rule | Response | Token event `reason` |
|---|---|---|---|
| Allowed CIDRs | The source IP must be inside one of the IPv4/IPv6 CIDRs (up to 20). An empty list means unrestricted. | `400 unauthorized_client`, `Source address is not allowed` | `cidr_denied` |
| Max scopes per token | At most N scopes (1 to 50) in one token. With `scope` omitted, all granted scopes on the resource count, so an agent with a wide grant must request scopes explicitly. | `400 invalid_scope`, `Too many scopes requested for one token` | `scope_ceiling` |
| Token budget per hour | At most N tokens (1 to 100000) issued in the trailing hour. | `429 too_many_requests`, `Hourly token budget exhausted`, with `Retry-After` | `budget_exhausted` |

`Retry-After` is the number of seconds until the oldest counted token leaves the window (1 to 3600). The budget response has no `X-RateLimit-*` headers, unlike the rate limiter; handle both 429s by waiting for `Retry-After`. The budget is read just before issuing, so concurrent requests can overshoot it slightly. The CIDR check uses the client IP Handsal derives from the connection or `X-Forwarded-For`; behind a proxy see [deployment](deployment.md#reverse-proxies-and-agent-cidr-rules).

**Scope policy.** A scope with `agent_policy=never` cannot be in an agent's token. Requesting it, or omitting `scope` while it is granted, returns `400 invalid_scope` (`Requested scope is not available to agents`). Other policies do not change this path.

## 7. Human approval for agent scopes

A scope with `agent_policy = approval` is one an `agent` application may only use after a person said yes. Set the policy on the scope (UI, or `agentPolicy` in the [management API](api.md#resources-and-scopes)) and grant the scope to the agent as usual. Services are not affected; `never` scopes stay unavailable to agents.

**1. Request.** The agent asks for the scope exactly as for any token. Optional `actor_hint` (who the agent works for) and `justification` (why) are shown to the approver:

```bash
curl -s https://auth.example.com/t/acme/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=client_credentials \
  -d resource=https://api.acme.example/orders \
  -d scope=orders:refund \
  -d task_id=refund-4411 \
  -d actor_hint="jane@acme.example" \
  --data-urlencode "justification=Customer asked for a refund of order 4411"
```

No token is issued. The answer is `400`:

```json
{"error":"authorization_pending","error_description":"Waiting for human approval of one or more requested scopes","approval_id":"6f1c2c1e-6c1b-4a54-9d0e-3f6f6a0c9b11","interval":5}
```

A request that mixes `auto` and `approval` scopes waits as a whole. Repeating the same request returns the same `approval_id` instead of a second card.

**2. Poll.** With the `approval_id`, no more often than every `interval` seconds, using the same client authentication. The poll takes no `resource`, `scope` or `task_id` (`400 invalid_request`):

```bash
curl -s https://auth.example.com/t/acme/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=urn:handsal:params:grant-type:approval \
  -d approval_id=6f1c2c1e-6c1b-4a54-9d0e-3f6f6a0c9b11
```

`authorization_pending` means keep waiting. `access_denied` means a person denied it; `expired_token` means nobody decided within 30 minutes. Stop in both cases and start a new request if the agent still needs the access. `invalid_grant` means the id is unknown, was already redeemed, or the grant changed meanwhile. On approval the answer is a normal `200` token response for the approved audience and scopes. It lives 300 seconds and an approval can be redeemed only once, so a new action needs a new request. Redemption checks the agent's guardrails (CIDR, scope ceiling, hourly budget) again.

**What the approver sees.** The tenant's Approvals page lists pending requests as cards: application and client ID, audience, the scopes, `actor_hint`, `task_id`, `justification` and the time left until expiry, with Approve and Deny buttons; above them the counts (pending, oldest, approved and denied in the last 24 h, median wait); below, the history of resolved requests with who or which rule decided. `admin` and `owner` can decide, `auditor` can only read. The same is available over the API (`GET .../approvals`, `POST .../approvals/:id/approve|deny`).

### Auto-approve rules

A rule lets a known-safe pattern skip the human. It is tied to one `approval` scope and has an optional condition (all keys ANDed): `application_ids`, `task_id_prefix`, `max_scopes`. `task_id` is asserted by the agent and is not an authorization boundary: a rule keyed on `task_id_prefix` alone is rejected, so pair it with `application_ids` (`400 invalid_rule_condition`). A rule can only be created on a scope whose `agent_policy` is `approval` (`400 scope_not_approval`). A request is auto-approved only when every `approval` scope in it is covered by a matching rule. Rules are managed through the API only:

```bash
curl -s -X POST -H "Cookie: handsal_session=$SESSION" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"scopeId":"'$SCOPE_ID'","condition":{"application_ids":["'$APP_ID'"],"task_id_prefix":"refund-","max_scopes":2}}' \
  https://auth.example.com/api/tenants/$TENANT_ID/approval-rules
```

The agent flow does not change: the first request still answers `authorization_pending`, but with `interval: 0`, and the first poll returns the token. Auto-approved requests send no webhook and show in the history as decided by the rule. Delete a rule with `DELETE .../approval-rules/$RULE_ID`.

### Webhook notifications

Set `approvalWebhookUrl` (https; `http` is accepted outside production) and optionally `approvalWebhookSecret` (16 to 255 characters) on the tenant, in Settings or with `PATCH /api/tenants/$TENANT_ID`. Every new pending approval is POSTed there once, without blocking the agent. Delivery has a 5 s timeout, one retry after 2 s on a network error or `5xx`, none on `4xx`, and redirects are not followed. It is a notification, not a queue: the Approvals page is the source of truth.

Headers: `Content-Type: application/json`, `X-Handsal-Event: approval.pending` and, when a secret is set, `X-Handsal-Signature: sha256=<hex>`, the HMAC-SHA256 of the raw body keyed with the secret. Body:

```json
{
  "type": "approval.pending",
  "approval": {
    "id": "6f1c2c1e-6c1b-4a54-9d0e-3f6f6a0c9b11", "applicationId": "...", "applicationName": "Refund bot",
    "clientId": "app_x7k2...", "audience": "https://api.acme.example/orders", "scopes": ["orders:refund"],
    "actorHint": "jane@acme.example", "taskId": "refund-4411", "justification": "Customer asked for a refund of order 4411",
    "status": "pending", "expiresAt": "2026-11-06T12:30:00.000Z", "createdAt": "2026-11-06T12:00:00.000Z",
    "decidedAt": null, "decidedBy": null
  },
  "tenant": { "id": "...", "slug": "acme" },
  "links": { "approvals": "https://auth.example.com/t/<tenantId>/approvals" }
}
```

Verify the signature over the raw bytes, before parsing the JSON:

```js
import { createHmac, timingSafeEqual } from "node:crypto";

function verify(rawBody, header, secret) {
  const expected = Buffer.from(`sha256=${createHmac("sha256", secret).update(rawBody).digest("hex")}`);
  const got = Buffer.from(header ?? "");
  return got.length === expected.length && timingSafeEqual(got, expected);
}
```

**Slack.** If the URL's host ends in `hooks.slack.com`, Handsal sends the `{"text": ...}` body that Slack incoming webhooks require, for example `Approval needed: Refund bot wants orders:refund on https://api.acme.example/orders (task refund-4411). Review: <https://auth.example.com/t/<tenantId>/approvals|Approvals>`. Create an incoming webhook in Slack and paste its URL; a secret has no use there because Slack does not verify signatures.

## 8. Delegation (token exchange)

When an agent acts on behalf of someone, the resource server should see both who the request is for (`sub`) and which agent performs it (`act`). The agent sends the credential of that someone (the subject token) to the token endpoint and gets back an access token for the target API (RFC 8693).

**Enable it** per agent application with `mayActFor` (UI, or the [management API](api.md#applications)), choosing whose tokens the agent may exchange:

| `mayActFor` | Subject tokens accepted |
|---|---|
| `users` | JWTs of the tenant's external IdP (your login provider), see below |
| `services` | Handsal access tokens issued to `service` applications of this tenant |
| `tenant` | Any Handsal access token of this tenant, agents included, except tokens whose chain started with a user (`sub_kind=user` needs `users`); a token that already has an `act` keeps it, nested under the new one (at most 3 levels, deeper is `invalid_grant`) |

An empty list (the default) disables exchange for the application. The application also needs a grant on the target `resource`, and a Handsal subject token must have been issued for that same `resource` (`aud`); it cannot be rebound to another API.

**Scopes.** `delegationScopeMode` decides what the new token may carry. `intersection` (default): only scopes that the agent is granted on the target resource and that the subject token itself carries (`scope` string or `scp` array), so the agent never does more than the subject. `agent_only`: the agent's grants, whatever the subject had; use it when the subject token comes from an IdP that knows nothing about your API's scopes. IdP scope names are matched by name against the agent's scopes on the target resource, so name them as that resource does. A `scope` parameter can narrow the result further. Scopes with `agent_policy` `never` or `approval` are refused in an exchange (`invalid_scope`); for `approval` the agent requests them with a normal request and the [approval flow](#7-human-approval-for-agent-scopes). Guardrails apply as always.

**External IdP.** To accept user tokens, set the tenant's `externalIdp` (Settings, or `PATCH /api/tenants/$TENANT_ID`):

```bash
curl -s -X PATCH -H "Cookie: handsal_session=$SESSION" -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"externalIdp":{"issuer":"https://login.acme.example/","jwksUri":"https://login.acme.example/.well-known/jwks.json","audience":"https://auth.example.com/t/acme"}}' \
  https://auth.example.com/api/tenants/$TENANT_ID
```

Handsal checks the signature against `jwksUri` (https and no internal addresses in production, see [deployment](deployment.md#outbound-urls); redirects not followed, keys cached; `RS256`, `PS256`, `ES256`, `ES384` or `EdDSA`), `iss` = `issuer`, `aud` contains `audience`, `exp` (required, 5 s tolerance), and requires a `sub`. An `act` claim in the IdP token is ignored. One IdP per tenant; `null` removes it.

**Exchange:**

```bash
curl -s https://auth.example.com/t/acme/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  --data-urlencode "subject_token=$USER_JWT" \
  -d resource=https://api.acme.example/orders \
  -d scope=orders:read
```

```json
{"access_token":"eyJ...","issued_token_type":"urn:ietf:params:oauth:token-type:access_token","token_type":"Bearer","expires_in":3600,"scope":"orders:read"}
```

`subject_token_type` is `urn:ietf:params:oauth:token-type:access_token` or `urn:ietf:params:oauth:token-type:jwt`; both work for either source. Failures: `unauthorized_client` (not an agent, `mayActFor` empty or not covering this kind of subject), `invalid_grant` (the subject token is not valid, deliberately without detail), `invalid_target`, `invalid_scope`. `actor_token` is not supported.

**Reading the token in the resource server.** Verify it as in [section 2](#2-resource-server-verifying-a-token-locally). The claims of an exchanged token:

| Claim | Meaning |
|---|---|
| `sub` | The subject: the user's ID at your IdP, or the `client_id` of the service whose token was exchanged. Use it as the identity for authorization and audit |
| `sub_kind` | What `sub` is: `user` (from your IdP), `service` or `agent` (a Handsal `client_id`). It stays the same when an exchanged token is exchanged again |
| `act.sub` | The agent that is acting (its `client_id`). A nested `act.act` is an earlier actor in the chain; the most recent is outermost |
| `client_id` | Always the agent application that holds the token |
| `scope`, `aud` | What was granted and for which API, as usual |

A token with `act` present is delegated: authorize on `sub` + `sub_kind` + `act.sub`, never on `sub` alone. An IdP user ID can look like a Handsal `client_id`, and only `sub_kind` tells them apart.

Treat the pair as "`sub`, via the agent `act.sub`". A token without `act` is a direct token (`sub` equals `client_id`). Log both. Do not authorize on `act` alone, and do not assume `sub` is a Handsal client when it comes from an external IdP. Exchanged tokens are independent tokens: introspect and revoke them like any other.
