---
title: Protect an API
description: Verify Handsal access tokens in a Hono, Express, or Next.js app.
---

# Protect an API

`@handsal/sdk` checks a bearer token on your API. It is the resource-server side. Your service still asks Handsal for a token, and this package decides whether a call may proceed.

The check is local. The package fetches the tenant's public keys, then verifies each request:

- the signature is ES256, and the header type is `at+jwt` (any other `alg`, including `none`, is rejected);
- `iss` is your tenant issuer;
- `aud` is this API's audience, so a token minted for another API of the same tenant is rejected;
- `exp` has not passed;
- `scope` contains every scope you named.

A missing or invalid token is `401` with `WWW-Authenticate: Bearer`. A valid token without the scope is `403` with `insufficient_scope`. The body is `{ "error": "invalid_token" }` or `{ "error": "insufficient_scope" }`. The response does not say whether the token was expired, unsigned, or signed by the wrong key.

A token stays valid until `exp` after a revoke, a disabled application, or a paused tenant. For a payment or a deletion, introspect as well. This package does not introspect: that call needs the resource server's own client secret, and most routes should not pay for it. The [integration guide](integration.md#3-introspection-when-local-verification-is-not-enough) has the request.

If the JWKS document cannot be fetched, the request fails. It is not reported as a bad token.

## Install

```bash
npm install @handsal/sdk
```

The package is compiled ESM and TypeScript types. It depends on `jose` and does not import the Handsal server. Inside this repository the dependency is `"@handsal/sdk": "workspace:*"`.

Create the verifier once, at module scope. Key lookups are cached, and an unknown `kid` is fetched again, so a rotation does not need a restart.

```ts
import { createHandsal } from "@handsal/sdk";

export const handsal = createHandsal({
  issuer: "https://auth.example.com/t/acme",
  audience: "https://api.acme.example/orders",
});
```

`issuer` is the tenant issuer, `${PUBLIC_URL}/t/${slug}`. A trailing slash is ignored. `audience` is the resource value of this API, matched exactly, including a trailing slash when the resource has one.

## Hono

```ts
import { Hono } from "hono";
import { type HandsalVariables } from "@handsal/sdk";
import { handsal } from "./handsal";

const app = new Hono<{ Variables: HandsalVariables }>();

app.use("/orders/*", handsal.hono({ scopes: "orders:read" }));

app.get("/orders", (c) => {
  const token = c.get("handsal");
  return c.json({ caller: token.client_id, kind: token.client_kind });
});
```

`scopes` may be one scope or a list. Every listed scope must be on the token. Omit `scopes` to accept any valid token for this audience.

## Express

```ts
import express from "express";
import { handsal } from "./handsal";

const app = express();

app.get("/orders", handsal.express({ scopes: ["orders:read"] }), (req, res) => {
  res.json({ caller: req.handsal?.client_id });
});
```

`req.handsal` is set only after the token verifies. Importing `@handsal/sdk` adds that field to the Express request type.

## Next.js

Wrap a route handler. The wrapper reads `Authorization` and either returns the `401` or `403`, or calls you with the claims. A second argument, such as the route context, is passed through.

```ts
// app/orders/route.ts
import { handsal } from "./handsal";

export const GET = handsal.handler({ scopes: "orders:read" }, async (_request, token) => {
  return Response.json({ caller: token.client_id });
});
```

To refuse anonymous calls for a whole subtree, export the middleware. Returning no response lets Next continue. A blocked call gets the same JSON error as the other adapters.

```ts
// middleware.ts
import { handsal } from "./handsal";

export default handsal.next({ scopes: "orders:read" });

export const config = { matcher: ["/orders/:path*"] };
```

The middleware only blocks. It does not copy the claims onto the request, because a client could send that header itself. A route that needs the claims uses `handler`, which verifies the token again. The keys are already cached.

## Any other server

`authenticate` takes a `Request` or the `Authorization` header. It returns the claims or throws `HandsalError` (`status`, `code`, `wwwAuthenticate`).

```ts
import { HandsalError } from "@handsal/sdk";

try {
  const token = await handsal.authenticate(request, { scopes: "orders:read" });
  return Response.json({ caller: token.client_id });
} catch (error) {
  if (error instanceof HandsalError) {
    return new Response(JSON.stringify({ error: error.code }), {
      status: error.status,
      headers: { "WWW-Authenticate": error.wwwAuthenticate },
    });
  }
  throw error;
}
```

## Claims

| Claim | Meaning |
| --- | --- |
| `sub` | Client id of the caller, or the subject of a delegated token |
| `client_id` | Application that asked for the token |
| `aud` | Audience. A string, or a list when the token carries more than one |
| `scope` | Space-separated scopes, as issued |
| `scopes` | `scope` as a list. The SDK adds this field |
| `tenant` | Tenant slug |
| `client_kind` | `service` or `agent` |
| `jti`, `iat`, `exp` | Id and lifetime, in seconds |
| `task_id` | Present when an agent named the task |
| `act`, `sub_kind` | Present on a delegated token |

## What this does not do

It does not request tokens. A caller still posts to `<issuer>/oauth/token`. It does not call introspection, and it does not revoke tokens. Both are in the [integration guide](integration.md).
