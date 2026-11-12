---
title: Zabezpiecz API
description: Sprawdzanie tokenów Handsal w aplikacji Hono, Express albo Next.js.
---

# Zabezpiecz API

`@handsal/sdk` obsługuje obie strony wywołania. `createHandsalClient` prosi Handsal o token `client_credentials`. `createHandsal` sprawdza token bearer na twoim API.

Sprawdzenie jest lokalne. Pakiet pobiera klucze publiczne tenanta i weryfikuje każde żądanie:

- podpis jest ES256, a typ nagłówka to `at+jwt` (każdy inny `alg`, także `none`, jest odrzucany);
- `iss` to issuer twojego tenanta;
- `aud` to audience tego API, więc token wydany dla innego API tego samego tenanta jest odrzucany;
- `exp` jeszcze nie minął;
- `scope` zawiera każdy zakres, który podałeś.

Brak tokena albo zły token to `401` z `WWW-Authenticate: Bearer`. Poprawny token bez zakresu to `403` z `insufficient_scope`. Treść to `{ "error": "invalid_token" }` albo `{ "error": "insufficient_scope" }`. Odpowiedź nie mówi, czy token wygasł, był niepodpisany, czy podpisał go zły klucz.

Po unieważnieniu, wyłączeniu aplikacji albo wstrzymaniu tenanta token zostaje ważny do `exp`. Przy płatności albo usunięciu dopytaj jeszcze introspekcją. Ten pakiet jej nie woła: takie wywołanie potrzebuje własnego sekretu serwera zasobów i większość ścieżek nie powinna za nie płacić. Prośba jest w [przewodniku integracji](integration.md#3-introspection-when-local-verification-is-not-enough).

Gdy dokumentu JWKS nie da się pobrać, żądanie kończy się błędem. Nie jest zgłaszane jako zły token.

## Instalacja

```bash
npm install @handsal/sdk
```

Pakiet to skompilowany ESM i typy TypeScript. Zależy od `jose` i nie importuje serwera Handsal. W tym repozytorium zależność workspace to `"@handsal/sdk": "workspace:*"`.

Weryfikator tworzysz raz, w zakresie modułu. Odczyty kluczy są cache'owane, a nieznany `kid` jest pobierany ponownie, więc rotacja nie wymaga restartu.

```ts
import { createHandsal } from "@handsal/sdk";

export const handsal = createHandsal({
  issuer: "https://auth.example.com/t/acme",
  audience: "https://api.acme.example/orders",
});
```

`issuer` to issuer tenanta, `${PUBLIC_URL}/t/${slug}`. Końcowy ukośnik jest ignorowany. `audience` to wartość resource tego API, porównywana dokładnie, razem z końcowym ukośnikiem, gdy zasób go ma.

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

`scopes` to jeden zakres albo lista. Każdy podany zakres musi być na tokenie. Pomiń `scopes`, żeby przyjąć dowolny ważny token dla tego audience.

## Express

```ts
import express from "express";
import { handsal } from "./handsal";

const app = express();

app.get("/orders", handsal.express({ scopes: ["orders:read"] }), (req, res) => {
  res.json({ caller: req.handsal?.client_id });
});
```

`req.handsal` jest ustawiane dopiero po weryfikacji tokena. Import `@handsal/sdk` dodaje to pole do typu żądania Express.

## Next.js

Owiń procedurę trasy. Opakowanie czyta `Authorization` i albo zwraca `401` lub `403`, albo woła ciebie z claimami. Drugi argument, na przykład kontekst trasy, jest przekazywany dalej.

```ts
// app/orders/route.ts
import { handsal } from "./handsal";

export const GET = handsal.handler({ scopes: "orders:read" }, async (_request, token) => {
  return Response.json({ caller: token.client_id });
});
```

Żeby odmówić anonimowym wywołaniom dla całego poddrzewa, wyeksportuj middleware. Brak odpowiedzi pozwala Nextowi iść dalej. Zablokowane wywołanie dostaje ten sam błąd JSON co pozostałe adaptery.

```ts
// middleware.ts
import { handsal } from "./handsal";

export default handsal.next({ scopes: "orders:read" });

export const config = { matcher: ["/orders/:path*"] };
```

Middleware tylko blokuje. Nie kopiuje claimów na żądanie, bo klient mógłby sam wysłać taki nagłówek. Trasa, która potrzebuje claimów, używa `handler`, a ten weryfikuje token jeszcze raz. Klucze są już w cache.

## Inny serwer

`authenticate` przyjmuje `Request` albo nagłówek `Authorization`. Zwraca claimy albo rzuca `HandsalError` (`status`, `code`, `wwwAuthenticate`).

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

## Pola tokena

| Pole | Znaczenie |
| --- | --- |
| `sub` | Client id wołającego albo podmiot delegowanego tokena |
| `client_id` | Aplikacja, która poprosiła o token |
| `aud` | Audience. Napis albo lista, gdy token niesie więcej niż jedno |
| `scope` | Zakresy rozdzielone spacją, tak jak zostały wydane |
| `scopes` | `scope` jako lista. To pole dodaje SDK |
| `tenant` | Slug tenanta |
| `client_kind` | `service` albo `agent` |
| `jti`, `iat`, `exp` | Identyfikator i czas życia, w sekundach |
| `task_id` | Jest, gdy agent nazwał zadanie |
| `act`, `sub_kind` | Są na delegowanym tokenie |

## Prośba o token

Jeden klient na jedno API. Trzyma token do 30 sekund przed `exp` (albo do połowy czasu życia, gdy ta wypada wcześniej). Jednoczesne wywołania dzielą jedno żądanie. Sekret i token nie trafiają do błędu.

```ts
import { createHandsalClient } from "@handsal/sdk";

export const orders = createHandsalClient({
  issuer: "https://auth.example.com/t/acme",
  clientId: process.env.CLIENT_ID ?? "",
  clientSecret: process.env.CLIENT_SECRET ?? "",
  resource: "https://api.acme.example/orders",
  scope: "orders:read",
});

const authorization = await orders.authorization();
```

`issuer` to issuer tenanta. `resource` to audience tego API, porównywane dokładnie. `scope` to jeden zakres albo lista; pominięty zakres oznacza wszystkie przyznane na tym zasobie. Domyślne uwierzytelnienie to HTTP Basic (`client_secret_basic`). Aplikacja zarejestrowana jako `client_secret_post` potrzebuje `authentication: "client_secret_post"`.

`taskId`, `actorHint` i `justification` idą w żądaniu, gdy zakres może czekać na człowieka. Ten klient nie podpisuje `private_key_jwt` i sam nie odpytuje zgody. Wstrzymane żądanie rzuca `HandsalClientError` z `code` równym `authorization_pending` oraz z `approvalId` i `interval`. Limit ustawia `retryAfter` z nagłówka `Retry-After`. Inna odmowa OAuth używa tego samego błędu (`status`, `code`, `description`). `clear()` kasuje cache.

## Czego ten pakiet nie robi

Nie podpisuje `private_key_jwt`, nie odpytuje zgody, nie woła introspekcji i nie unieważnia tokenu. Te żądania są w [przewodniku integracji](integration.md).
