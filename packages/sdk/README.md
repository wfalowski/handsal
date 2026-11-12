# @handsal/sdk

Verify a Handsal access token in a Hono, Express, or Next.js API.

```bash
npm install @handsal/sdk
```

```ts
import { createHandsal } from "@handsal/sdk";

export const handsal = createHandsal({
  issuer: "https://auth.example.com/t/acme",
  audience: "https://api.acme.example/orders",
});
```

The check is local. The package fetches the tenant JWKS and verifies the ES256 `at+jwt` signature, issuer, audience, expiry, and scopes. It depends on `jose` and does not call the Handsal server.

Guide: <https://github.com/wfalowski/handsal/blob/main/docs/sdk.md>

Apache-2.0
