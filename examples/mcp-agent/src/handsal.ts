import { createPrivateKey, type KeyObject, randomUUID, sign } from "node:crypto";

const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const APPROVAL_GRANT = "urn:handsal:params:grant-type:approval";
const CACHE_MARGIN_MS = 10_000;
const DEFAULT_POLL_INTERVAL_SECONDS = 5;
const TOKEN_ENDPOINT_TIMEOUT_MS = 15_000;
const MAX_TRANSIENT_POLL_FAILURES = 3;
const DESCRIPTION_LIMIT = 300;

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

/** Removes the given secrets, bearer credentials and client assertions from text shown to the model. */
export function redact(value: string, secrets: readonly string[] = []): string {
  let out = value;
  for (const secret of secrets) {
    if (secret) out = out.split(secret).join("[redacted]");
  }
  return out
    .replace(/authorization:\s*bearer\s+\S+/gi, "authorization: [redacted]")
    .replace(/client_assertion=[^&\s"']*/gi, "client_assertion=[redacted]");
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
  /** `viaApproval` tokens are never cached: one human approval covers exactly one HTTP call. */
  | { kind: "token"; accessToken: string; expiresAt: number; viaApproval: boolean }
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
      /** Network error, 5xx or 429: worth retrying while an approval is pending. */
      transient: boolean;
      approvalId?: string;
      interval?: number;
      retryAfterSeconds?: number;
    };

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Obtains Handsal access tokens with private_key_jwt, waiting for human approval when needed. */
export class HandsalClient {
  private readonly cache = new Map<string, { accessToken: string; expiresAt: number }>();
  private readonly inFlight = new Map<string, Promise<TokenResult>>();
  private readonly fetchFn: typeof fetch;

  constructor(private readonly opts: HandsalClientOptions) {
    loadPrivateKey(opts.privateKeyPem); // fail at startup, not on the first tool call
    this.fetchFn = opts.fetch ?? fetch;
  }

  getToken(req: TokenRequest): Promise<TokenResult> {
    const cacheKey = `${req.resource}\n${req.scope}\n${req.taskId}`;
    const cached = this.cache.get(cacheKey);
    if (cached && cached.expiresAt - CACHE_MARGIN_MS > Date.now()) {
      return Promise.resolve({ kind: "token", ...cached, viaApproval: false });
    }
    // Concurrent identical calls share one request, so they cannot race on (and burn) one approval.
    let pending = this.inFlight.get(cacheKey);
    if (!pending) {
      pending = this.requestToken(req, cacheKey).finally(() => this.inFlight.delete(cacheKey));
      this.inFlight.set(cacheKey, pending);
    }
    return pending;
  }

  private remember(cacheKey: string, token: { accessToken: string; expiresAt: number }): void {
    const now = Date.now();
    for (const [key, entry] of this.cache) {
      if (entry.expiresAt - CACHE_MARGIN_MS <= now) this.cache.delete(key);
    }
    this.cache.set(cacheKey, token);
  }

  private async requestToken(req: TokenRequest, cacheKey: string): Promise<TokenResult> {
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
    let immediatePollUsed = false;
    let transientFailures = 0;

    for (;;) {
      if (res.ok) {
        const token = { accessToken: res.accessToken, expiresAt: res.expiresAt };
        const viaApproval = approvalId !== undefined;
        if (!viaApproval) this.remember(cacheKey, token);
        return { kind: "token", ...token, viaApproval };
      }

      let delaySeconds: number;
      if (res.error === "authorization_pending" || res.error === "slow_down") {
        approvalId = res.approvalId ?? approvalId;
        if (!approvalId) return denied(res);
        transientFailures = 0;
        if (res.error === "slow_down") {
          interval = Math.max(1, interval) * 2;
          delaySeconds = interval;
        } else if (res.interval === 0 && !immediatePollUsed) {
          // An auto-approve rule matched: the first poll returns the token.
          immediatePollUsed = true;
          interval = 1;
          delaySeconds = 0;
        } else {
          interval = Math.max(1, res.interval ?? interval);
          delaySeconds = interval;
        }
      } else if (res.transient && approvalId) {
        // The approval is still live on the server; a blip must not make the model start over.
        transientFailures += 1;
        if (transientFailures > MAX_TRANSIENT_POLL_FAILURES) return pendingResult();
        delaySeconds = Math.max(1, interval);
      } else {
        return denied(res);
      }

      // Overshoots the wait by at most one interval; polling sooner than `interval` is not allowed.
      if (Date.now() >= deadline) return pendingResult();
      await sleep(delaySeconds * 1000);
      res = await this.post({ grant_type: APPROVAL_GRANT, approval_id: approvalId }).catch(
        (err: unknown): EndpointResponse => ({
          ok: false,
          error: "network_error",
          description: err instanceof Error ? err.message : String(err),
          transient: true,
        }),
      );
    }

    function pendingResult(): TokenResult {
      return {
        kind: "pending",
        approvalId: approvalId as string,
        waitedSeconds: Math.round((Date.now() - started) / 1000),
      };
    }
  }

  private async post(params: Record<string, string | undefined>): Promise<EndpointResponse> {
    const body = new URLSearchParams();
    for (const [name, value] of Object.entries(params)) {
      if (value !== undefined) body.set(name, value);
    }
    const assertion = signClientAssertion({
      privateKeyPem: this.opts.privateKeyPem,
      clientId: this.opts.clientId,
      kid: this.opts.kid,
      tokenEndpoint: this.opts.tokenEndpoint,
    });
    body.set("client_assertion_type", ASSERTION_TYPE);
    body.set("client_assertion", assertion);
    const res = await this.fetchFn(this.opts.tokenEndpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body,
      signal: AbortSignal.timeout(TOKEN_ENDPOINT_TIMEOUT_MS),
    });
    const json: Record<string, unknown> = await res.json().catch(() => ({}));
    const accessToken = json.access_token;
    if (res.ok && typeof accessToken === "string" && accessToken.length > 0) {
      const expiresIn = typeof json.expires_in === "number" ? json.expires_in : 0;
      return { ok: true, accessToken, expiresAt: Date.now() + expiresIn * 1000 };
    }
    if (res.ok) {
      return {
        ok: false,
        error: "invalid_response",
        description: "The token endpoint answered 200 without an access_token",
        transient: false,
      };
    }
    const retryAfter = Number.parseInt(res.headers.get("retry-after") ?? "", 10);
    // Error text comes from the network: it never carries our assertion and is length-capped.
    const clean = (value: string, limit: number) => redact(value, [assertion]).slice(0, limit);
    return {
      ok: false,
      error: clean(typeof json.error === "string" ? json.error : `http_${res.status}`, 64),
      description: clean(
        typeof json.error_description === "string" ? json.error_description : res.statusText,
        DESCRIPTION_LIMIT,
      ),
      transient: res.status >= 500 || res.status === 429,
      approvalId: typeof json.approval_id === "string" ? json.approval_id : undefined,
      interval: typeof json.interval === "number" ? json.interval : undefined,
      retryAfterSeconds: Number.isFinite(retryAfter) ? retryAfter : undefined,
    };
  }
}

function denied(res: Extract<EndpointResponse, { ok: false }>): TokenResult {
  return {
    kind: "denied",
    error: res.error,
    description: res.description,
    ...(res.retryAfterSeconds !== undefined && { retryAfterSeconds: res.retryAfterSeconds }),
  };
}
