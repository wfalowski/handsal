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

Guide: <https://github.com/wfalowski/handsal/blob/main/docs/sdk.md>

Apache-2.0
