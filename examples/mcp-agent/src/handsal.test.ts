import { generateKeyPairSync, type KeyObject, verify } from "node:crypto";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { HandsalClient, loadPrivateKey } from "./handsal.js";

const CLIENT_ID = "app_test";
const KID = "key-1";

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const pkcs8Pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const sec1Pem = privateKey.export({ type: "sec1", format: "pem" }).toString();

interface Scripted {
  status: number;
  body: Record<string, unknown>;
  headers?: Record<string, string>;
}

let server: Server;
let tokenEndpoint: string;
let script: Scripted[] = [];
let requests: Record<string, string>[] = [];
const seenJtis = new Set<string>();

function decode(part: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

/** Throws (failing the request with 500) unless the assertion is valid for `key`. */
function checkAssertion(jwt: string, key: KeyObject): void {
  const [h, p, s] = jwt.split(".");
  const ok = verify(
    "sha256",
    Buffer.from(`${h}.${p}`),
    { key, dsaEncoding: "ieee-p1363" },
    Buffer.from(s, "base64url"),
  );
  if (!ok) throw new Error("bad signature");
  const header = decode(h);
  const payload = decode(p);
  if (header.alg !== "ES256" || header.kid !== KID || header.typ !== "JWT")
    throw new Error("bad header");
  if (payload.iss !== CLIENT_ID || payload.sub !== CLIENT_ID) throw new Error("bad iss/sub");
  if (payload.aud !== tokenEndpoint) throw new Error("bad aud");
  if (payload.exp !== (payload.iat as number) + 120) throw new Error("bad exp");
  if (typeof payload.jti !== "string" || seenJtis.has(payload.jti)) throw new Error("jti reused");
  seenJtis.add(payload.jti);
}

beforeAll(async () => {
  server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
    });
    req.on("end", () => {
      const form = Object.fromEntries(new URLSearchParams(raw));
      try {
        if (
          form.client_assertion_type !== "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ) {
          throw new Error("bad assertion type");
        }
        checkAssertion(form.client_assertion ?? "", publicKey);
      } catch (err) {
        res.writeHead(500).end((err as Error).message);
        return;
      }
      requests.push(form);
      const next = script.shift() ?? { status: 500, body: { error: "script_exhausted" } };
      res.writeHead(next.status, { "content-type": "application/json", ...next.headers });
      res.end(JSON.stringify(next.body));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  tokenEndpoint = `http://127.0.0.1:${(server.address() as AddressInfo).port}/t/acme/oauth/token`;
});

afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

beforeEach(() => {
  script = [];
  requests = [];
});

function client(approvalWaitSeconds = 30, pem = pkcs8Pem) {
  return new HandsalClient({
    tokenEndpoint,
    clientId: CLIENT_ID,
    kid: KID,
    privateKeyPem: pem,
    approvalWaitSeconds,
  });
}

const tokenBody = (token: string) => ({
  access_token: token,
  token_type: "Bearer",
  expires_in: 300,
  scope: "invoices:read",
});
const pendingBody = {
  error: "authorization_pending",
  error_description: "Waiting",
  approval_id: "ap-1",
  interval: 1,
};
const request = {
  resource: "https://api.acme.io/invoices",
  scope: "invoices:read",
  taskId: "task-1",
};

describe("HandsalClient", () => {
  it("issues a token with client_credentials and serves the second call from cache", async () => {
    script = [{ status: 200, body: tokenBody("tok-1") }];
    const c = client();
    const first = await c.getToken({ ...request, actorHint: "jane", justification: "why" });
    expect(first).toMatchObject({ kind: "token", accessToken: "tok-1" });
    expect(requests[0]).toMatchObject({
      grant_type: "client_credentials",
      resource: request.resource,
      scope: request.scope,
      task_id: "task-1",
      actor_hint: "jane",
      justification: "why",
    });
    expect(await c.getToken(request)).toMatchObject({ kind: "token", accessToken: "tok-1" });
    expect(requests).toHaveLength(1);
  });

  it("polls the approval grant until the token is issued", async () => {
    script = [
      { status: 400, body: pendingBody },
      { status: 400, body: pendingBody },
      { status: 200, body: tokenBody("tok-approved") },
    ];
    const result = await client().getToken(request);
    expect(result).toMatchObject({ kind: "token", accessToken: "tok-approved" });
    expect(requests).toHaveLength(3);
    for (const poll of requests.slice(1)) {
      expect(poll.grant_type).toBe("urn:handsal:params:grant-type:approval");
      expect(poll.approval_id).toBe("ap-1");
      expect(poll.resource).toBeUndefined();
      expect(poll.scope).toBeUndefined();
      expect(poll.task_id).toBeUndefined();
    }
  }, 10_000);

  it("returns pending when the approval outlasts the wait", async () => {
    script = [
      { status: 400, body: pendingBody },
      { status: 400, body: pendingBody },
      { status: 400, body: pendingBody },
    ];
    const result = await client(1).getToken(request);
    expect(result).toMatchObject({ kind: "pending", approvalId: "ap-1" });
  }, 10_000);

  it("stops polling when the approval is denied", async () => {
    script = [
      { status: 400, body: pendingBody },
      { status: 400, body: { error: "access_denied", error_description: "Denied by a human" } },
    ];
    const result = await client().getToken(request);
    expect(result).toEqual({
      kind: "denied",
      error: "access_denied",
      description: "Denied by a human",
    });
    expect(requests).toHaveLength(2);
  }, 10_000);

  it("reports Retry-After on 429", async () => {
    script = [
      {
        status: 429,
        body: { error: "too_many_requests", error_description: "Hourly token budget exhausted" },
        headers: { "retry-after": "42" },
      },
    ];
    expect(await client().getToken(request)).toEqual({
      kind: "denied",
      error: "too_many_requests",
      description: "Hourly token budget exhausted",
      retryAfterSeconds: 42,
    });
  });
});

describe("loadPrivateKey", () => {
  it("accepts SEC1 and PKCS8 P-256 keys and signs with both", async () => {
    expect(loadPrivateKey(sec1Pem).asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
    expect(loadPrivateKey(pkcs8Pem).asymmetricKeyDetails?.namedCurve).toBe("prime256v1");
    script = [{ status: 200, body: tokenBody("tok-sec1") }];
    expect(await client(30, sec1Pem).getToken(request)).toMatchObject({ kind: "token" });
  });

  it("rejects non-P-256 keys without echoing them", () => {
    const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" })
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString();
    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 })
      .privateKey.export({ type: "pkcs8", format: "pem" })
      .toString();
    expect(() => client(30, p384)).toThrow(/P-256/);
    expect(() => client(30, rsa)).toThrow(/P-256/);
    expect(() => loadPrivateKey("not a key")).toThrow(/not a readable PEM/);
  });
});
