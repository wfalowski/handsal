import { createPrivateKey, type KeyObject, randomUUID, sign } from "node:crypto";

const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const APPROVAL_GRANT = "urn:handsal:params:grant-type:approval";
const TERMINAL_APPROVAL_ERRORS = new Set(["access_denied", "expired_token", "invalid_grant"]);
const CACHE_MARGIN_MS = 10_000;
const DEFAULT_POLL_INTERVAL_SECONDS = 5;

/** Parse a PEM private key (SEC1 or PKCS8) and require EC P-256. The error never echoes the key. */
export function loadPrivateKey(privateKeyPem: string): KeyObject {
  let key: KeyObject;
  try {
    key = createPrivateKey(privateKeyPem);
  } catch {
    throw new Error("The private key is not a readable PEM private key");
  }
  if (key.asymmetricKeyType !== "ec" || key.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new Error(
      "The private key must be an EC P-256 (prime256v1) key; Handsal accepts ES256 only",
    );
  }
  return key;
}

function base64url(input: string | Buffer): string {
  return Buffer.from(input).toString("base64url");
}

/** A fresh RFC 7523 client assertion (ES256) for the Handsal token endpoint. */
export function signClientAssertion(opts: {
  privateKeyPem: string;
  clientId: string;
  kid: string;
  tokenEndpoint: string;
}): string {
  const key = loadPrivateKey(opts.privateKeyPem);
  const iat = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: "ES256", kid: opts.kid, typ: "JWT" }));
  const payload = base64url(
    JSON.stringify({
      iss: opts.clientId,
      sub: opts.clientId,
      aud: opts.tokenEndpoint,
      iat,
      exp: iat + 120,
      jti: randomUUID(),
    }),
  );
  const input = `${header}.${payload}`;
  const signature = sign("sha256", Buffer.from(input), { key, dsaEncoding: "ieee-p1363" });
  return `${input}.${base64url(signature)}`;
}

export interface TokenRequest {
  resource: string;
  scope: string;
  taskId: string;
  actorHint?: string;
  justification?: string;
}

export type TokenResult =
  | { kind: "token"; accessToken: string; expiresAt: number }
  | { kind: "pending"; approvalId: string; waitedSeconds: number }
  | { kind: "denied"; error: string; description: string; retryAfterSeconds?: number };

export interface HandsalClientOptions {
  tokenEndpoint: string;
  clientId: string;
  kid: string;
  privateKeyPem: string;
  approvalWaitSeconds: number;
  fetch?: typeof fetch;
}

type EndpointResponse =
  | { ok: true; accessToken: string; expiresAt: number }
  | {
      ok: false;
      error: string;
      description: string;
      approvalId?: string;
      interval?: number;
      retryAfterSeconds?: number;
    };

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Obtains Handsal access tokens with private_key_jwt, waiting for human approval when needed. */
export class HandsalClient {
  private readonly cache = new Map<string, { accessToken: string; expiresAt: number }>();
  private readonly fetchFn: typeof fetch;

  constructor(private readonly opts: HandsalClientOptions) {
    loadPrivateKey(opts.privateKeyPem); // fail at startup, not on the first tool call
    this.fetchFn = opts.fetch ?? fetch;
  }

  async getToken(req: TokenRequest): Promise<TokenResult> {
    const cacheKey = `${req.resource}\n${req.scope}\n${req.taskId}`;
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt - CACHE_MARGIN_MS > Date.now()) {
      return { kind: "token", ...cached };
    }
    this.cache.delete(cacheKey);

    const started = Date.now();
    const deadline = started + this.opts.approvalWaitSeconds * 1000;
    let res = await this.post({
      grant_type: "client_credentials",
      resource: req.resource,
      scope: req.scope,
      task_id: req.taskId,
      actor_hint: req.actorHint,
      justification: req.justification,
    });
    let approvalId: string | undefined;
    let interval = DEFAULT_POLL_INTERVAL_SECONDS;

    for (;;) {
      if (res.ok) {
        const token = { accessToken: res.accessToken, expiresAt: res.expiresAt };
        this.cache.set(cacheKey, token);
        return { kind: "token", ...token };
      }
      const waiting = res.error === "authorization_pending" || res.error === "slow_down";
      approvalId = res.approvalId ?? approvalId;
      if (!waiting || !approvalId || TERMINAL_APPROVAL_ERRORS.has(res.error)) {
        return {
          kind: "denied",
          error: res.error,
          description: res.description,
          ...(res.retryAfterSeconds !== undefined && { retryAfterSeconds: res.retryAfterSeconds }),
        };
      }
      interval = res.error === "slow_down" ? interval * 2 : Math.max(1, res.interval ?? interval);
      // Overshoots the wait by at most one interval; polling sooner than `interval` is not allowed.
      if (Date.now() >= deadline) {
        return {
          kind: "pending",
          approvalId,
          waitedSeconds: Math.round((Date.now() - started) / 1000),
        };
      }
      await sleep(interval * 1000);
      res = await this.post({ grant_type: APPROVAL_GRANT, approval_id: approvalId });
    }
  }

  private async post(params: Record<string, string | undefined>): Promise<EndpointResponse> {
    const body = new URLSearchParams();
    for (const [name, value] of Object.entries(params)) {
      if (value !== undefined) body.set(name, value);
    }
    body.set("client_assertion_type", ASSERTION_TYPE);
    body.set(
      "client_assertion",
      signClientAssertion({
        privateKeyPem: this.opts.privateKeyPem,
        clientId: this.opts.clientId,
        kid: this.opts.kid,
        tokenEndpoint: this.opts.tokenEndpoint,
      }),
    );
    const res = await this.fetchFn(this.opts.tokenEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body,
    });
    const json: Record<string, unknown> = await res.json().catch(() => ({}));
    if (res.ok && typeof json.access_token === "string") {
      const expiresIn = typeof json.expires_in === "number" ? json.expires_in : 0;
      return { ok: true, accessToken: json.access_token, expiresAt: Date.now() + expiresIn * 1000 };
    }
    const retryAfter = Number.parseInt(res.headers.get("retry-after") ?? "", 10);
    return {
      ok: false,
      error: typeof json.error === "string" ? json.error : `http_${res.status}`,
      description:
        typeof json.error_description === "string" ? json.error_description : res.statusText,
      approvalId: typeof json.approval_id === "string" ? json.approval_id : undefined,
      interval: typeof json.interval === "number" ? json.interval : undefined,
      retryAfterSeconds: Number.isFinite(retryAfter) ? retryAfter : undefined,
    };
  }
}
