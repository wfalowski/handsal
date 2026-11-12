/** A cached client-credentials token. `expiresAt` is Unix milliseconds. */
export interface HandsalClientToken {
  accessToken: string;
  tokenType: "Bearer";
  scope: string;
  expiresAt: number;
}

export interface HandsalClientOptions {
  /** Tenant issuer, for example `https://auth.example.com/t/acme`. A trailing slash is ignored. */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Audience of the API this client calls. Sent as `resource`. */
  resource: string;
  /** One scope or a list. Omitted: the server returns every scope granted on `resource`. */
  scope?: string | readonly string[];
  /**
   * Must match the application's registered method. The default is HTTP Basic.
   * `client_secret_post` sends the id and secret in the form body instead.
   */
  authentication?: "client_secret_basic" | "client_secret_post";
  /** Optional agent task id (`task_id`). */
  taskId?: string;
  /** Shown to the person approving a held request (`actor_hint`). */
  actorHint?: string;
  /** Shown to the person approving a held request (`justification`). */
  justification?: string;
  /** Refresh this many milliseconds before expiry. The default is 30 seconds. */
  leewayMs?: number;
  /** Replaces `fetch`. Tests pass a stub. */
  fetch?: typeof fetch;
}

export interface HandsalClient {
  /** Cached access token. Concurrent calls share one token request. */
  getToken(): Promise<HandsalClientToken>;
  /** `Bearer <token>` for an `Authorization` header. */
  authorization(): Promise<string>;
  /** Drops the cached token. The next call requests a new one. */
  clear(): void;
}

/** The token endpoint refused the call, or the success body was not a bearer token. */
export class HandsalClientError extends Error {
  readonly status: number;
  readonly code: string;
  readonly description: string | undefined;
  /** Seconds from `Retry-After`, when the server sent one. */
  readonly retryAfter: number | undefined;
  /** Set when a scope is waiting for a person (`authorization_pending`). */
  readonly approvalId: string | undefined;
  /** Seconds the server asked the caller to wait before polling the approval. */
  readonly interval: number | undefined;

  constructor(init: {
    status: number;
    code: string;
    description?: string;
    retryAfter?: number;
    approvalId?: string;
    interval?: number;
  }) {
    super(init.description ?? init.code);
    this.name = "HandsalClientError";
    this.status = init.status;
    this.code = init.code;
    this.description = init.description;
    this.retryAfter = init.retryAfter;
    this.approvalId = init.approvalId;
    this.interval = init.interval;
  }
}

const TASK_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const DEFAULT_LEEWAY_MS = 30_000;

function required(value: string | undefined, label: string): string {
  const trimmed = value?.trim() ?? "";
  if (trimmed === "") throw new Error(`Handsal ${label} is required`);
  return trimmed;
}

function scopeParam(scope: HandsalClientOptions["scope"]): string | undefined {
  if (scope === undefined) return undefined;
  const parts = (typeof scope === "string" ? scope.split(/\s+/) : scope)
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  return parts.length > 0 ? parts.join(" ") : undefined;
}

function basicAuthorization(clientId: string, clientSecret: string): string {
  const raw = `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`;
  return `Basic ${btoa(raw)}`;
}

function retryAfterSeconds(header: string | null): number | undefined {
  if (header === null || !/^\d+$/.test(header)) return undefined;
  return Number(header);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Client-credentials caller for one resource. Create it once and reuse it.
 * The token is cached until shortly before `exp`, and overlapping calls share
 * one request. The secret and the token are not written to errors.
 *
 * This client does not sign `private_key_jwt` and does not poll an approval.
 * A held scope throws `HandsalClientError` with `approvalId`.
 */
export function createHandsalClient(options: HandsalClientOptions): HandsalClient {
  const issuer = required(options.issuer, "issuer").replace(/\/+$/, "");
  const clientId = required(options.clientId, "clientId");
  const clientSecret = required(options.clientSecret, "clientSecret");
  const resource = required(options.resource, "resource");
  if (resource.length > 512) throw new Error("Handsal resource is too long");
  const scope = scopeParam(options.scope);
  const authentication = options.authentication ?? "client_secret_basic";
  if (authentication !== "client_secret_basic" && authentication !== "client_secret_post") {
    throw new Error("Handsal authentication must be client_secret_basic or client_secret_post");
  }
  const taskId = options.taskId?.trim();
  if (taskId !== undefined && taskId !== "" && !TASK_ID.test(taskId)) {
    throw new Error("Handsal taskId is invalid");
  }
  const actorHint = options.actorHint?.trim();
  if (actorHint !== undefined && actorHint.length > 255) {
    throw new Error("Handsal actorHint is too long");
  }
  const justification = options.justification?.trim();
  if (justification !== undefined && justification.length > 2000) {
    throw new Error("Handsal justification is too long");
  }
  const leewayMs = options.leewayMs ?? DEFAULT_LEEWAY_MS;
  if (!Number.isFinite(leewayMs) || leewayMs < 0) throw new Error("Handsal leewayMs is invalid");
  const fetchImpl = options.fetch ?? fetch;
  const endpoint = `${issuer}/oauth/token`;

  let generation = 0;
  let cached: { token: HandsalClientToken; receivedAt: number } | null = null;
  let pending: Promise<HandsalClientToken> | null = null;

  function usable(entry: { token: HandsalClientToken; receivedAt: number }): boolean {
    const lifetime = entry.token.expiresAt - entry.receivedAt;
    const margin = Math.min(leewayMs, Math.floor(lifetime / 2));
    return Date.now() < entry.token.expiresAt - margin;
  }

  async function request(): Promise<{ token: HandsalClientToken; receivedAt: number }> {
    const body = new URLSearchParams({ grant_type: "client_credentials", resource });
    if (scope !== undefined) body.set("scope", scope);
    if (taskId) body.set("task_id", taskId);
    if (actorHint) body.set("actor_hint", actorHint);
    if (justification) body.set("justification", justification);
    const headers: Record<string, string> = {
      "Content-Type": "application/x-www-form-urlencoded",
    };
    if (authentication === "client_secret_basic") {
      headers.Authorization = basicAuthorization(clientId, clientSecret);
    } else {
      body.set("client_id", clientId);
      body.set("client_secret", clientSecret);
    }

    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers,
      body,
      redirect: "error",
      cache: "no-store",
    });
    const payload: unknown = await response.json().catch(() => null);
    const record = isRecord(payload) ? payload : {};
    const retryAfter = retryAfterSeconds(response.headers.get("Retry-After"));

    if (!response.ok) {
      const code = typeof record.error === "string" ? record.error : "invalid_response";
      const description =
        typeof record.error_description === "string" ? record.error_description : undefined;
      throw new HandsalClientError({
        status: response.status,
        code,
        description,
        retryAfter,
        approvalId: typeof record.approval_id === "string" ? record.approval_id : undefined,
        interval: typeof record.interval === "number" ? record.interval : undefined,
      });
    }

    const accessToken = record.access_token;
    const tokenType = record.token_type;
    const expiresIn = record.expires_in;
    const granted = record.scope;
    if (
      typeof accessToken !== "string" ||
      accessToken === "" ||
      typeof tokenType !== "string" ||
      tokenType.toLowerCase() !== "bearer" ||
      typeof expiresIn !== "number" ||
      !Number.isFinite(expiresIn) ||
      expiresIn <= 0 ||
      typeof granted !== "string"
    ) {
      throw new HandsalClientError({
        status: response.status,
        code: "invalid_response",
        description: "Token response was not a bearer token",
      });
    }
    const receivedAt = Date.now();
    return {
      receivedAt,
      token: {
        accessToken,
        tokenType: "Bearer",
        scope: granted,
        expiresAt: receivedAt + expiresIn * 1000,
      },
    };
  }

  function getToken(): Promise<HandsalClientToken> {
    if (cached && usable(cached)) return Promise.resolve(cached.token);
    if (pending) return pending;
    const gen = generation;
    pending = request()
      .then((entry) => {
        if (gen === generation) cached = entry;
        return entry.token;
      })
      .finally(() => {
        if (gen === generation) pending = null;
      });
    return pending;
  }

  return {
    getToken,
    authorization: async () => `Bearer ${(await getToken()).accessToken}`,
    clear() {
      generation += 1;
      cached = null;
      pending = null;
    },
  };
}
