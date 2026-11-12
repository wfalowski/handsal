# @handsal/sdk

Request a Handsal client-credentials token, and verify an access token in a Hono, Express, or Next.js API.

```bash
npm install @handsal/sdk
```

```ts
import { createHandsal, createHandsalClient } from "@handsal/sdk";

export const orders = createHandsalClient({
  issuer: "https://auth.example.com/t/acme",
  clientId: process.env.CLIENT_ID ?? "",
  clientSecret: process.env.CLIENT_SECRET ?? "",
  resource: "https://api.acme.example/orders",
  scope: "orders:read",
});

export const handsal = createHandsal({
  issuer: "https://auth.example.com/t/acme",
  audience: "https://api.acme.example/orders",
});
```

The check is local. The package fetches the tenant JWKS and verifies the ES256 `at+jwt` signature, issuer, audience, expiry, and scopes. The client calls the token endpoint and caches the bearer token. It depends on `jose`.

`scopes` is one scope or a list. Every listed scope must be on the token. Omit it to accept any valid token for this audience. A missing or invalid token is `401`. A valid token without the scope is `403`.

## Hono

```ts
import { Hono } from "hono";
import { type HandsalVariables } from "@handsal/sdk";

const app = new Hono<{ Variables: HandsalVariables }>();

app.use("/orders/*", handsal.hono({ scopes: "orders:read" }));

app.get("/orders", (c) => {
  const token = c.get("handsal");
  return c.json({ caller: token.client_id });
});
```

## Express

```ts
import express from "express";

const app = express();

app.get("/orders", handsal.express({ scopes: ["orders:read"] }), (req, res) => {
  res.json({ caller: req.handsal?.client_id });
});
```

Importing `@handsal/sdk` adds `handsal` to the Express request type. It is set only after the token verifies.

## Next.js

Wrap a route handler. The wrapper returns the `401` or `403`, or calls you with the claims.

```ts
// app/orders/route.ts
export const GET = handsal.handler({ scopes: "orders:read" }, async (_request, token) => {
  return Response.json({ caller: token.client_id });
});
```

`handsal.next()` is the middleware for a whole subtree. It only blocks. It does not copy the claims onto the request, because a client could send that header itself. A route that needs the claims uses `handler`.

```ts
// middleware.ts
export default handsal.next({ scopes: "orders:read" });

export const config = { matcher: ["/orders/:path*"] };
```

## Any other server

`authenticate` takes a `Request` or the `Authorization` header. It returns the claims or throws `HandsalError` (`status`, `code`, `wwwAuthenticate`).

Guide: <https://github.com/wfalowski/handsal/blob/main/docs/sdk.md>

Apache-2.0
