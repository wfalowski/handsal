---
title: Zabezpiecz API
description: Sprawdzanie tokenów Handsal w aplikacji Hono, Express albo Next.js.
---

# Zabezpiecz API

`@handsal/sdk` sprawdza token bearer na twoim API. To strona serwera zasobów. Usługa nadal prosi Handsal o token, a ten pakiet decyduje, czy wywołanie może przejść.

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

Pakiet to `@handsal/sdk` w `packages/sdk`. Zależy od `jose` i nie importuje serwera Handsal.

W tym repozytorium zależność workspace:

```json
{ "dependencies": { "@handsal/sdk": "workspace:*" } }
```

Z innej aplikacji wskaż zależność na ten katalog. Pakiet jest źródłem TypeScript, tak jak reszta tego repozytorium. Next.js potrzebuje jednego ustawienia, żeby go skompilować:

```ts
const nextConfig = { transpilePackages: ["@handsal/sdk"] };
```

Serwer, który już kompiluje zależności, na przykład `tsx` albo bundler, importuje go wprost. Weryfikator tworzysz raz, w zakresie modułu. Odczyty kluczy są cache'owane, a nieznany `kid` jest pobierany ponownie, więc rotacja nie wymaga restartu.

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

## Czego ten pakiet nie robi

Nie prosi o tokeny. Wołający nadal wysyła POST na `<issuer>/oauth/token`. Nie woła introspekcji i nie unieważnia tokenów. Jedno i drugie jest w [przewodniku integracji](integration.md).
