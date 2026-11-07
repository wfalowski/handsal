import { createRemoteJWKSet, errors, type JWTPayload, type JWTVerifyGetKey, jwtVerify } from "jose";

/** Claims Handsal puts on an access token, plus `scopes` split from `scope`. */
export interface HandsalAccessToken {
  iss: string;
  sub: string;
  aud: string | string[];
  /** Space-separated, as issued. */
  scope: string;
  /** `scope` split on whitespace. Empty pieces are dropped. */
  scopes: string[];
  client_id: string;
  tenant: string;
  client_kind: "service" | "agent";
  jti: string;
  iat: number;
  exp: number;
  task_id?: string;
  /** Set on a delegated token. The acting agent chain. */
  act?: Record<string, unknown>;
  /** Set on a delegated token: `user`, `service`, or `agent`. */
  sub_kind?: string;
}

export interface HandsalOptions {
  /** Tenant issuer. Exact `iss`, for example `https://auth.example.com/t/acme`. */
  issuer: string;
  /** This API's audience. A token for another audience is rejected. */
  audience: string;
  /** Defaults to `${issuer}/.well-known/jwks.json`. */
  jwksUri?: string;
  /** Replaces the remote JWKS lookup. Tests pass a local key set. */
  getKey?: JWTVerifyGetKey;
}

export interface ProtectOptions {
  /** Every listed scope must be present. One scope or a list. Omit to accept any valid token. */
  scopes?: string | readonly string[];
}

/** Hono variables set by `handsal.hono()`. */
export interface HandsalVariables {
  handsal: HandsalAccessToken;
}

declare global {
  namespace Express {
    interface Request {
      /** Set by `handsal.express()` after the bearer token is verified. */
      handsal?: HandsalAccessToken;
    }
  }
}

export class HandsalError extends Error {
  readonly status: 401 | 403;
  readonly code: "invalid_token" | "insufficient_scope";
  readonly wwwAuthenticate: string;

  constructor(
    status: 401 | 403,
    code: "invalid_token" | "insufficient_scope",
    wwwAuthenticate: string,
  ) {
    super(code);
    this.name = "HandsalError";
    this.status = status;
    this.code = code;
    this.wwwAuthenticate = wwwAuthenticate;
  }
}

type Handler = (
  request: Request,
  token: HandsalAccessToken,
  ...rest: any[]
) => Response | Promise<Response>;

export interface Handsal {
  authenticate(
    input: Request | string | null | undefined,
    options?: ProtectOptions,
  ): Promise<HandsalAccessToken>;
  /** Untyped context so the function stays assignable to Hono without a Hono dependency. */
  hono(
    options?: ProtectOptions,
  ): (c: any, next: () => Promise<void>) => Promise<Response | undefined>;
  /** Untyped so the function stays assignable to Express without an Express dependency. */
  express(
    options?: ProtectOptions,
  ): (req: any, res: any, next: (error?: unknown) => void) => Promise<void>;
  /** Next.js middleware. Returns a response to stop the request, or `undefined` to continue. */
  next(
    options?: ProtectOptions,
  ): (request: { headers: { get(name: string): string | null } }) => Promise<Response | undefined>;
  handler(route: Handler): (request: Request, ...rest: any[]) => Promise<Response>;
  handler(
    options: ProtectOptions,
    route: Handler,
  ): (request: Request, ...rest: any[]) => Promise<Response>;
}

const INVALID = new HandsalError(401, "invalid_token", 'Bearer error="invalid_token"');

function invalidToken(): HandsalError {
  return INVALID;
}

function listedScopes(scopes: ProtectOptions["scopes"]): string[] {
  if (scopes === undefined) return [];
  const list = typeof scopes === "string" ? [scopes] : scopes;
  return list.map((scope) => scope.trim()).filter((scope) => scope.length > 0);
}

function quoteHeader(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function insufficientScope(required: string[]): HandsalError {
  return new HandsalError(
    403,
    "insufficient_scope",
    `Bearer error="insufficient_scope", scope=${quoteHeader(required.join(" "))}`,
  );
}

function toResponse(error: HandsalError): Response {
  return new Response(JSON.stringify({ error: error.code }), {
    status: error.status,
    headers: {
      "Content-Type": "application/json",
      "WWW-Authenticate": error.wwwAuthenticate,
      "Cache-Control": "no-store",
    },
  });
}

function bearer(header: string | null | undefined): string | undefined {
  if (!header) return undefined;
  const match = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return match?.[1];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readClaims(payload: JWTPayload): HandsalAccessToken {
  const {
    scope,
    client_id,
    tenant,
    client_kind,
    jti,
    sub,
    iss,
    aud,
    iat,
    exp,
    task_id,
    act,
    sub_kind,
  } = payload;
  if (
    typeof scope !== "string" ||
    typeof client_id !== "string" ||
    typeof tenant !== "string" ||
    typeof jti !== "string" ||
    typeof sub !== "string" ||
    typeof iss !== "string" ||
    (typeof aud !== "string" && !Array.isArray(aud)) ||
    typeof iat !== "number" ||
    typeof exp !== "number" ||
    (client_kind !== "service" && client_kind !== "agent")
  ) {
    throw invalidToken();
  }
  if (task_id !== undefined && typeof task_id !== "string") throw invalidToken();
  if (sub_kind !== undefined && typeof sub_kind !== "string") throw invalidToken();
  if (act !== undefined && !isRecord(act)) throw invalidToken();

  const claims: HandsalAccessToken = {
    iss,
    sub,
    aud,
    scope,
    scopes: scope.split(/\s+/).filter((part) => part.length > 0),
    client_id,
    tenant,
    client_kind,
    jti,
    iat,
    exp,
  };
  if (typeof task_id === "string") claims.task_id = task_id;
  if (isRecord(act)) claims.act = act;
  if (typeof sub_kind === "string") claims.sub_kind = sub_kind;
  return claims;
}

function authorizationOf(input: Request | string | null | undefined): string | null {
  if (typeof input === "string") return input;
  if (input == null) return null;
  return input.headers.get("authorization");
}

/**
 * Verifier for one API. Create it once and reuse it: the JWKS lookup is cached,
 * and an unknown `kid` is fetched again, so a key rotation needs no restart.
 *
 * Local verification does not see revocation. A token stays valid until `exp`.
 */
export function createHandsal(options: HandsalOptions): Handsal {
  const issuer = options.issuer?.trim().replace(/\/+$/, "") ?? "";
  if (issuer === "") throw new Error("Handsal issuer is required");
  if (typeof options.audience !== "string" || options.audience.trim() === "") {
    throw new Error("Handsal audience is required");
  }
  const audience = options.audience;
  const getKey =
    options.getKey ??
    createRemoteJWKSet(new URL(options.jwksUri ?? `${issuer}/.well-known/jwks.json`));

  async function authenticate(
    input: Request | string | null | undefined,
    protect?: ProtectOptions,
  ): Promise<HandsalAccessToken> {
    const token = bearer(authorizationOf(input));
    if (!token) throw new HandsalError(401, "invalid_token", "Bearer");

    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, getKey, {
        issuer,
        audience,
        algorithms: ["ES256"],
        typ: "at+jwt",
      }));
    } catch (error) {
      // A JWKS timeout means this process could not check the token. That is not a bad token.
      if (error instanceof errors.JOSEError && error.code !== "ERR_JWKS_TIMEOUT")
        throw invalidToken();
      throw error;
    }

    const claims = readClaims(payload);
    const required = listedScopes(protect?.scopes);
    if (required.some((scope) => !claims.scopes.includes(scope))) throw insufficientScope(required);
    return claims;
  }

  function hono(protect?: ProtectOptions) {
    return async (c: any, next: () => Promise<void>): Promise<Response | undefined> => {
      try {
        const token = await authenticate(c.req.header("authorization"), protect);
        c.set("handsal", token);
        await next();
      } catch (error) {
        if (error instanceof HandsalError) return toResponse(error);
        throw error;
      }
    };
  }

  function express(protect?: ProtectOptions) {
    return async (req: any, res: any, next: (error?: unknown) => void): Promise<void> => {
      try {
        const header = req.headers?.authorization ?? req.header?.("authorization");
        const value = Array.isArray(header) ? header[0] : header;
        req.handsal = await authenticate(typeof value === "string" ? value : undefined, protect);
      } catch (error) {
        if (error instanceof HandsalError) {
          res.status(error.status);
          res.setHeader("WWW-Authenticate", error.wwwAuthenticate);
          res.setHeader("Cache-Control", "no-store");
          res.json({ error: error.code });
          return;
        }
        next(error);
        return;
      }
      next();
    };
  }

  function nextMiddleware(protect?: ProtectOptions) {
    return async (request: {
      headers: { get(name: string): string | null };
    }): Promise<Response | undefined> => {
      try {
        await authenticate(request.headers.get("authorization"), protect);
        return undefined;
      } catch (error) {
        if (error instanceof HandsalError) return toResponse(error);
        throw error;
      }
    };
  }

  function handler(route: Handler): (request: Request, ...rest: any[]) => Promise<Response>;
  function handler(
    protect: ProtectOptions,
    route: Handler,
  ): (request: Request, ...rest: any[]) => Promise<Response>;
  function handler(
    protectOrRoute: ProtectOptions | Handler,
    maybeRoute?: Handler,
  ): (request: Request, ...rest: any[]) => Promise<Response> {
    const protect = typeof protectOrRoute === "function" ? undefined : protectOrRoute;
    const route = typeof protectOrRoute === "function" ? protectOrRoute : maybeRoute;
    if (!route) throw new Error("handsal.handler requires a route");
    return async (request: Request, ...rest: any[]): Promise<Response> => {
      try {
        const token = await authenticate(request, protect);
        return await route(request, token, ...rest);
      } catch (error) {
        if (error instanceof HandsalError) return toResponse(error);
        throw error;
      }
    };
  }

  return { authenticate, hono, express, next: nextMiddleware, handler };
}
