import { createLocalJWKSet, exportJWK, generateKeyPair, type JWTPayload, SignJWT } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createHandsal, type HandsalAccessToken, HandsalError } from "./handsal.js";

function b64url(value: string): string {
  return btoa(value).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

const ISSUER = "https://auth.example.com/t/acme";
const AUDIENCE = "https://api.acme.example/orders";

const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
const jwk = await exportJWK(publicKey);
jwk.kid = "test";
jwk.alg = "ES256";
jwk.use = "sig";
const getKey = createLocalJWKSet({ keys: [jwk] });

function handsal() {
  return createHandsal({ issuer: ISSUER, audience: AUDIENCE, getKey });
}

async function sign(
  claims: JWTPayload = {},
  header: { alg?: string; typ?: string; kid?: string } = {},
  times: { issuer?: string; audience?: string; exp?: string } = {},
  key: CryptoKey = privateKey,
) {
  return new SignJWT({
    sub: "app_test",
    client_id: "app_test",
    scope: "orders:read orders:write",
    tenant: "acme",
    client_kind: "service",
    ...claims,
  })
    .setProtectedHeader({
      alg: header.alg ?? "ES256",
      kid: header.kid ?? "test",
      typ: header.typ ?? "at+jwt",
    })
    .setIssuer(times.issuer ?? ISSUER)
    .setAudience(times.audience ?? AUDIENCE)
    .setJti("jti-1")
    .setIssuedAt()
    .setExpirationTime(times.exp ?? "2m")
    .sign(key);
}

async function expectInvalid(run: Promise<unknown>) {
  await expect(run).rejects.toMatchObject({ status: 401, code: "invalid_token" });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("createHandsal", () => {
  it("requires an issuer and an audience", () => {
    expect(() => createHandsal({ issuer: "  ", audience: AUDIENCE })).toThrow(/issuer/);
    expect(() => createHandsal({ issuer: ISSUER, audience: " " })).toThrow(/audience/);
  });

  it("rejects an http jwksUri on another host without an option", () => {
    expect(() =>
      createHandsal({
        issuer: ISSUER,
        audience: AUDIENCE,
        jwksUri: "http://evil.example/jwks.json",
      }),
    ).toThrow(/jwksUri/);
    // Checked on the getKey path too.
    expect(() =>
      createHandsal({
        issuer: ISSUER,
        audience: AUDIENCE,
        getKey,
        jwksUri: "http://evil.example/jwks.json",
      }),
    ).toThrow(/jwksUri/);
  });

  it("requires https for jwksUri unless loopback or allowInsecureHttp", () => {
    const base = { issuer: ISSUER, audience: AUDIENCE, allowCrossOrigin: true };
    const jwksUri = "http://keys.example.net/jwks.json";
    expect(() => createHandsal({ ...base, jwksUri })).toThrow("Handsal jwksUri is invalid");
    expect(() => createHandsal({ ...base, jwksUri })).toThrow(/allowInsecureHttp/);
    expect(() => createHandsal({ ...base, jwksUri, allowInsecureHttp: true })).not.toThrow();
    // A name that only starts like 127.0.0.0/8 is not loopback.
    expect(() => createHandsal({ ...base, jwksUri: "http://127.evil.com/jwks.json" })).toThrow(
      /allowInsecureHttp/,
    );
    expect(() =>
      createHandsal({ ...base, jwksUri: "https://keys.example.net/jwks.json" }),
    ).not.toThrow();
  });

  it("requires jwksUri on the issuer's host and port unless allowCrossOrigin", () => {
    const base = { issuer: ISSUER, audience: AUDIENCE, getKey };
    expect(() =>
      createHandsal({ ...base, jwksUri: "https://auth.example.com/t/acme/keys.json" }),
    ).not.toThrow();
    expect(() =>
      createHandsal({ ...base, jwksUri: "https://auth.example.com:443/t/acme/keys.json" }),
    ).not.toThrow();
    for (const jwksUri of [
      "https://keys.example.net/jwks.json",
      "https://auth.example.com:8443/t/acme/keys.json",
    ]) {
      expect(() => createHandsal({ ...base, jwksUri })).toThrow(/jwksUri.*allowCrossOrigin/);
      expect(() => createHandsal({ ...base, jwksUri, allowCrossOrigin: true })).not.toThrow();
    }
  });

  it("needs both options for an http container address next to an https issuer", () => {
    const base = { issuer: ISSUER, audience: AUDIENCE };
    const jwksUri = "http://handsal:3000/t/acme/.well-known/jwks.json";
    expect(() => createHandsal({ ...base, jwksUri, allowInsecureHttp: true })).toThrow(
      /allowCrossOrigin/,
    );
    expect(() => createHandsal({ ...base, jwksUri, allowCrossOrigin: true })).toThrow(
      /allowInsecureHttp/,
    );
    expect(() =>
      createHandsal({ ...base, jwksUri, allowInsecureHttp: true, allowCrossOrigin: true }),
    ).not.toThrow();
  });

  it("requires an https issuer unless loopback or allowInsecureHttp", () => {
    const issuer = "http://auth.example.com/t/acme";
    expect(() => createHandsal({ issuer, audience: AUDIENCE, getKey })).toThrow(
      /issuer.*allowInsecureHttp/,
    );
    expect(() =>
      createHandsal({ issuer, audience: AUDIENCE, getKey, allowInsecureHttp: true }),
    ).not.toThrow();
    for (const loopback of [
      "http://localhost:3000/t/acme",
      "http://api.localhost:3000/t/acme",
      "http://127.0.0.1:3000/t/acme",
      "http://[::1]:3000/t/acme",
    ]) {
      expect(() => createHandsal({ issuer: loopback, audience: AUDIENCE })).not.toThrow();
    }
    expect(() =>
      createHandsal({
        issuer: "http://api.localhost:3000/t/acme",
        audience: AUDIENCE,
        jwksUri: "http://api.localhost:3000/t/acme/.well-known/jwks.json",
      }),
    ).not.toThrow();
    expect(() => createHandsal({ issuer: "not a url", audience: AUDIENCE })).toThrow(
      "Handsal issuer is invalid",
    );
    // The issuer rule is not replaced by a cross-origin jwksUri.
    const message = (() => {
      try {
        createHandsal({
          issuer: "http://handsal.internal/t/acme",
          audience: AUDIENCE,
          jwksUri: "https://keys.example.net/jwks.json",
          allowCrossOrigin: true,
        });
      } catch (error) {
        return (error as Error).message;
      }
      return "";
    })();
    expect(message).toMatch(/issuer.*allowInsecureHttp/);
    expect(message).not.toMatch(/jwksUri/);
  });

  it("rejects userinfo and non-http schemes even with both options", () => {
    const base = { audience: AUDIENCE, allowInsecureHttp: true, allowCrossOrigin: true };
    expect(() =>
      createHandsal({ ...base, issuer: "https://evil.example@auth.example.com/t/acme" }),
    ).toThrow(/issuer.*username or password/);
    expect(() =>
      createHandsal({
        ...base,
        issuer: ISSUER,
        jwksUri: "https://evil.example@auth.example.com/jwks.json",
      }),
    ).toThrow(/jwksUri.*username or password/);
    expect(() => createHandsal({ ...base, issuer: ISSUER, jwksUri: "file:///etc/passwd" })).toThrow(
      "Handsal jwksUri is invalid",
    );
    expect(() => createHandsal({ ...base, issuer: "file:///etc/passwd" })).toThrow(
      "Handsal issuer is invalid",
    );
  });

  it("treats a blank jwksUri as absent and fetches the derived key set", async () => {
    const token = await sign();
    for (const jwksUri of ["", "   "]) {
      const fetchImpl = vi.fn(async (..._args: unknown[]) => Response.json({ keys: [jwk] }));
      vi.stubGlobal("fetch", fetchImpl);
      const auth = createHandsal({ issuer: ISSUER, audience: AUDIENCE, jwksUri });
      await expect(auth.authenticate(`Bearer ${token}`)).resolves.toMatchObject({ iss: ISSUER });
      expect(String(fetchImpl.mock.calls[0]?.[0])).toBe(`${ISSUER}/.well-known/jwks.json`);
    }
  });

  it("verifies an ES256 at+jwt for this issuer and audience", async () => {
    const token = await sign({ client_kind: "agent", task_id: "run-42" });
    const claims = await handsal().authenticate(`Bearer ${token}`, { scopes: "orders:read" });
    expect(claims).toMatchObject({
      iss: ISSUER,
      sub: "app_test",
      aud: AUDIENCE,
      client_id: "app_test",
      tenant: "acme",
      client_kind: "agent",
      task_id: "run-42",
      jti: "jti-1",
    });
    expect(claims.scopes).toEqual(["orders:read", "orders:write"]);
  });

  it("accepts a trailing slash on the configured issuer", async () => {
    const auth = createHandsal({ issuer: `${ISSUER}/`, audience: AUDIENCE, getKey });
    await expect(auth.authenticate(`Bearer ${await sign()}`)).resolves.toMatchObject({
      iss: ISSUER,
    });
  });

  it("rejects a missing token, a bad scheme, and a non-bearer header", async () => {
    const auth = handsal();
    await expectInvalid(auth.authenticate(undefined));
    await expectInvalid(auth.authenticate("Basic abc"));
    await expectInvalid(auth.authenticate("Bearer one two"));
    const error = await auth.authenticate(null).catch((caught: unknown) => caught);
    expect(error).toMatchObject({ wwwAuthenticate: "Bearer" });
  });

  it("rejects none, a foreign key, the wrong audience, the wrong issuer, and expiry", async () => {
    const auth = handsal();
    const header = b64url(JSON.stringify({ alg: "none", typ: "at+jwt", kid: "test" }));
    const body = b64url(JSON.stringify({ iss: ISSUER, aud: AUDIENCE, exp: 9_999_999_999 }));
    await expectInvalid(auth.authenticate(`Bearer ${header}.${body}.`));

    const other = await generateKeyPair("ES256", { extractable: true });
    const foreign = await sign({}, { kid: "other" }, {}, other.privateKey);
    await expectInvalid(auth.authenticate(`Bearer ${foreign}`));

    const rsa = await generateKeyPair("RS256", { extractable: true });
    const rsaToken = await sign({}, { alg: "RS256", kid: "rsa" }, {}, rsa.privateKey);
    await expectInvalid(auth.authenticate(`Bearer ${rsaToken}`));

    await expectInvalid(
      auth.authenticate(`Bearer ${await sign({}, {}, { audience: "https://other.example" })}`),
    );
    await expectInvalid(
      auth.authenticate(
        `Bearer ${await sign({}, {}, { issuer: "https://auth.example.com/t/other" })}`,
      ),
    );
    await expectInvalid(auth.authenticate(`Bearer ${await sign({}, {}, { exp: "-30s" })}`));
    await expectInvalid(auth.authenticate(`Bearer ${await sign({}, { typ: "JWT" })}`));
  });

  it("rejects a token that is not a Handsal access token", async () => {
    const auth = handsal();
    await expectInvalid(auth.authenticate(`Bearer ${await sign({ client_kind: "widget" })}`));
    await expectInvalid(
      auth.authenticate(`Bearer ${await sign({ scope: 1 as unknown as string })}`),
    );
  });

  it("returns 403 when a required scope is missing and 200-path when every scope is present", async () => {
    const auth = handsal();
    const token = `Bearer ${await sign({ scope: "orders:read" })}`;
    await expect(
      auth.authenticate(token, { scopes: ["orders:read", "orders:write"] }),
    ).rejects.toMatchObject({
      status: 403,
      code: "insufficient_scope",
      wwwAuthenticate: 'Bearer error="insufficient_scope", scope="orders:read orders:write"',
    });
    await expect(auth.authenticate(token, { scopes: ["orders:read"] })).resolves.toMatchObject({
      scope: "orders:read",
    });
  });

  it("keeps act and sub_kind on a delegated token", async () => {
    const claims = await handsal().authenticate(
      `Bearer ${await sign({
        sub: "user_1",
        sub_kind: "user",
        act: { sub: "app_test" },
      })}`,
    );
    expect(claims.sub).toBe("user_1");
    expect(claims.client_id).toBe("app_test");
    expect(claims.act).toEqual({ sub: "app_test" });
    expect(claims.sub_kind).toBe("user");
  });
});

describe("adapters", () => {
  it("hono sets the claims and turns a bad token into a response", async () => {
    const auth = handsal();
    const token = await sign();
    let stored: HandsalAccessToken | undefined;
    let continued = false;
    const ok = await auth.hono({ scopes: "orders:read" })(
      {
        req: { header: () => `Bearer ${token}` },
        set(_key: string, value: HandsalAccessToken) {
          stored = value;
        },
      },
      async () => {
        continued = true;
      },
    );
    expect(ok).toBeUndefined();
    expect(continued).toBe(true);
    expect(stored?.client_id).toBe("app_test");

    const denied = await auth.hono()({ req: { header: () => undefined }, set() {} }, async () => {
      throw new Error("should not run");
    });
    expect(denied).toBeInstanceOf(Response);
    expect(denied?.status).toBe(401);
    expect(denied?.headers.get("WWW-Authenticate")).toBe("Bearer");
    await expect(denied?.json()).resolves.toEqual({ error: "invalid_token" });
  });

  it("express writes 403 and passes unexpected failures to next", async () => {
    const auth = handsal();
    const token = await sign({ scope: "orders:read" });
    let status = 0;
    let header = "";
    let body: unknown;
    const req: { headers: { authorization: string }; handsal?: HandsalAccessToken } = {
      headers: { authorization: `Bearer ${token}` },
    };
    await auth.express({ scopes: "orders:write" })(
      req,
      {
        status(code: number) {
          status = code;
          return this;
        },
        setHeader(name: string, value: string) {
          if (name === "WWW-Authenticate") header = value;
        },
        json(value: unknown) {
          body = value;
        },
      },
      () => {
        throw new Error("next on 403");
      },
    );
    expect(status).toBe(403);
    expect(header).toContain("insufficient_scope");
    expect(body).toEqual({ error: "insufficient_scope" });
    expect(req.handsal).toBeUndefined();

    const allowed = await sign();
    const good: { headers: { authorization: string }; handsal?: HandsalAccessToken } = {
      headers: { authorization: `Bearer ${allowed}` },
    };
    let called = false;
    await auth.express()(good, { status() {}, setHeader() {}, json() {} }, () => {
      called = true;
    });
    expect(called).toBe(true);
    expect(good.handsal?.client_kind).toBe("service");

    const broken = createHandsal({
      issuer: ISSUER,
      audience: AUDIENCE,
      getKey: () => {
        throw new Error("jwks down");
      },
    });
    let forwarded: unknown;
    await broken.express()(
      { headers: { authorization: `Bearer ${allowed}` } },
      { status() {}, setHeader() {}, json() {} },
      (error) => {
        forwarded = error;
      },
    );
    expect(forwarded).toBeInstanceOf(Error);
    expect(forwarded).not.toBeInstanceOf(HandsalError);
  });

  it("next middleware blocks, and handler calls the route with the claims", async () => {
    const auth = handsal();
    const token = await sign();
    const request = new Request("https://api.acme.example/orders", {
      headers: { authorization: `Bearer ${token}` },
    });
    await expect(auth.next({ scopes: "orders:read" })(request)).resolves.toBeUndefined();

    const blocked = await auth.next()(new Request("https://api.acme.example/orders"));
    expect(blocked?.status).toBe(401);

    let seen = "";
    const get = auth.handler(
      { scopes: ["orders:read"] },
      async (_request, claims, ctx: { id: string }) => {
        seen = claims.sub;
        return Response.json({ id: ctx.id });
      },
    );
    const response = await get(request, { id: "1" });
    expect(response.status).toBe(200);
    expect(seen).toBe("app_test");
    await expect(response.json()).resolves.toEqual({ id: "1" });

    const missed = await get(new Request("https://api.acme.example/orders"), { id: "1" });
    expect(missed.status).toBe(401);
  });
});
