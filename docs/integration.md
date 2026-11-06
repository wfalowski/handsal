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

### Node (fetch, with caching)

```js
const ISSUER = "https://auth.example.com/t/acme";
let cached; // { token, expiresAt }

export async function getToken() {
  if (cached && Date.now() < cached.expiresAt - 30_000) return cached.token;

  const basic = Buffer.from(
    `${encodeURIComponent(process.env.CLIENT_ID)}:${encodeURIComponent(process.env.CLIENT_SECRET)}`,
  ).toString("base64");
  const res = await fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "client_credentials",
      resource: "https://api.acme.example/orders",
      scope: "orders:read",
    }),
  });
  const body = await res.json();
  if (!res.ok) throw Object.assign(new Error(body.error_description), { code: body.error, status: res.status });

  cached = { token: body.access_token, expiresAt: Date.now() + body.expires_in * 1000 };
  return cached.token;
}
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
  "scopes_supported": ["orders:read", "orders:write"],
  "id_token_signing_alg_values_supported": ["ES256"]
}
```

`introspection_endpoint` is omitted when introspection is disabled for the tenant. Read `token_endpoint` and `jwks_uri` from this document at startup instead of building the paths by hand; validate that `issuer` equals the value you configured.

## 5. Authenticating with private_key_jwt

Instead of a shared secret, the application proves its identity with a short-lived JWT signed by a private key that only the client holds (RFC 7523). Handsal stores only the public key. Only ES256 / P-256 keys are supported.

1. **Generate a key pair** (keep `key.pem` in your secret store):

   ```bash
   openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out key.pem
   openssl pkey -in key.pem -pubout -out pub.pem   # SPKI PEM: "-----BEGIN PUBLIC KEY-----"
   ```

2. **Register the public key**, in the UI (application detail) or through the management API (`admin` role; the `kid` is your choice, up to 128 characters of `A-Za-z0-9._:-`, unique per application):

   ```bash
   curl -s -X POST -H "Authorization: Bearer $ADMIN_API_KEY" -H "Content-Type: application/json" \
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

**Task grouping.** The optional form parameter `task_id` (1 to 128 characters of `A-Za-z0-9._:-`) names the job the agent is working on. It is meant to become the `task_id` claim of the access token and to group the token events, which the admin UI and `GET .../token-events?taskId=` show per task. A value that does not match the format is `400 invalid_request`.

> Differs from the design note: the token route validates `task_id` but does not pass it on to token issuance, so on this version the claim is not set and events are not grouped by task (the issuance code supports it and is unit-tested directly). Do not rely on it until the route forwards it.

**Guardrails** are fields of the agent application (UI, or `allowedCidrs`, `maxScopesPerToken`, `tokenBudgetPerHour` plus the informational `agentRuntime` and `operatorEmail` in the [management API](api.md#applications)). They are checked on every token request after authentication:

| Guardrail | Rule | Response | Token event `reason` |
|---|---|---|---|
| Allowed CIDRs | The source IP must be inside one of the IPv4/IPv6 CIDRs (up to 20). An empty list means unrestricted. | `400 unauthorized_client`, `Source address is not allowed` | `cidr_denied` |
| Max scopes per token | At most N scopes (1 to 50) in one token. With `scope` omitted, all granted scopes on the resource count, so an agent with a wide grant must request scopes explicitly. | `400 invalid_scope`, `Too many scopes requested for one token` | `scope_ceiling` |
| Token budget per hour | At most N tokens (1 to 100000) issued in the trailing hour. | `429 too_many_requests`, `Hourly token budget exhausted`, with `Retry-After` | `budget_exhausted` |

`Retry-After` is the number of seconds until the oldest counted token leaves the window (1 to 3600). The budget response has no `X-RateLimit-*` headers, unlike the rate limiter; handle both 429s by waiting for `Retry-After`. The budget is read just before issuing, so concurrent requests can overshoot it slightly. The CIDR check uses the client IP Handsal derives from the connection or `X-Forwarded-For`; behind a proxy see [deployment](deployment.md#reverse-proxies-and-agent-cidr-rules).

**Scope policy.** A scope with `agent_policy=never` cannot be in an agent's token. Requesting it, or omitting `scope` while it is granted, returns `400 invalid_scope` (`Requested scope is not available to agents`). Other policies do not change this path.
