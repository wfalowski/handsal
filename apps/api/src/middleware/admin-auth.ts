import crypto from "node:crypto";
import type { TenantRole } from "@handsal/shared";
import type { Context, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import type { AppEnv } from "../app.js";
import { env } from "../env.js";
import { getAdminUser } from "../services/admin-user.service.js";
import { deriveKey } from "../utils/crypto.js";
import {
  extractRequestInfo,
  logSecurityEvent,
  SecurityEvent,
  SecuritySeverity,
} from "../utils/security-logger.js";
import { ApiError } from "./error-handler.js";

export type Actor =
  | { kind: "user"; userId: string; email: string; name: string; isSuperAdmin: boolean }
  | { kind: "api-key"; isSuperAdmin: true };

/** Hono env for management routers: `c.var.actor` set by `adminAuth`, `c.var.tenantRole` by `requireTenantAccess`. */
export type AdminEnv = {
  Variables: AppEnv["Variables"] & { actor: Actor; tenantRole?: TenantRole };
};

export const SESSION_COOKIE = "handsal_session";
export const SESSION_TTL_SECONDS = 12 * 60 * 60;

const SESSION_KEY = deriveKey(env.KEY_ENCRYPTION_SECRET, "admin-session");
const CSRF_KEY = deriveKey(env.KEY_ENCRYPTION_SECRET, "admin-csrf");

interface SessionPayload {
  sub: string;
  iat: number;
  exp: number;
}

const hmac = (key: Buffer, data: string) =>
  crypto.createHmac("sha256", key).update(data).digest("base64url");

/** Constant-time string compare (false on length mismatch). */
function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}

/** `base64url(payload).base64url(hmac)`; `nowMs` is injectable for tests. */
export function createSessionToken(adminUserId: string, nowMs = Date.now()): string {
  const iat = Math.floor(nowMs / 1000);
  const payload: SessionPayload = { sub: adminUserId, iat, exp: iat + SESSION_TTL_SECONDS };
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${encoded}.${hmac(SESSION_KEY, encoded)}`;
}

/** Returns the payload when the signature is valid and not expired, else null. */
export function verifySessionToken(token: string, nowMs = Date.now()): SessionPayload | null {
  const [encoded, signature, ...rest] = token.split(".");
  if (!encoded || !signature || rest.length > 0) return null;
  if (!safeEqual(signature, hmac(SESSION_KEY, encoded))) return null;
  try {
    const payload = JSON.parse(
      Buffer.from(encoded, "base64url").toString("utf8"),
    ) as SessionPayload;
    if (typeof payload.sub !== "string" || typeof payload.exp !== "number") return null;
    return nowMs / 1000 < payload.exp ? payload : null;
  } catch {
    return null;
  }
}

/** CSRF token bound to one session token (HMAC of its payload segment). */
export function csrfTokenFor(sessionToken: string): string {
  return hmac(CSRF_KEY, sessionToken.split(".")[0] ?? "");
}

export function setSessionCookie(c: Context, token: string): void {
  setCookie(c, SESSION_COOKIE, token, {
    httpOnly: true,
    secure: env.NODE_ENV === "production",
    sameSite: "Strict",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
}

export function clearSessionCookie(c: Context): void {
  deleteCookie(c, SESSION_COOKIE, {
    httpOnly: true,
    secure: env.NODE_ENV === "production",
    sameSite: "Strict",
    path: "/",
  });
}

function authFailure(c: Context, reason: string): ApiError {
  logSecurityEvent({
    ...extractRequestInfo(c),
    event: SecurityEvent.ADMIN_AUTH_FAILURE,
    severity: SecuritySeverity.MEDIUM,
    details: { reason },
  });
  return new ApiError(401, "unauthenticated", "Authentication required");
}

/**
 * Accepts `Authorization: Bearer <ADMIN_API_KEY>` (super-admin, no CSRF) or the
 * session cookie. `apiKey` is injectable for tests; undefined disables the bearer path.
 */
export function createAdminAuth({
  apiKey = env.ADMIN_API_KEY,
}: {
  apiKey?: string;
} = {}): MiddlewareHandler<AdminEnv> {
  const apiKeyBuf = apiKey === undefined ? undefined : Buffer.from(apiKey);

  return async (c, next) => {
    const authHeader = c.req.header("Authorization");
    if (apiKeyBuf && authHeader?.startsWith("Bearer ")) {
      const given = Buffer.from(authHeader.slice(7));
      if (given.length !== apiKeyBuf.length || !crypto.timingSafeEqual(given, apiKeyBuf)) {
        throw authFailure(c, "invalid_api_key");
      }
      c.set("actor", { kind: "api-key", isSuperAdmin: true });
      await next();
      return;
    }

    const token = getCookie(c, SESSION_COOKIE);
    if (!token) throw authFailure(c, "no_credentials");
    const session = verifySessionToken(token);
    if (!session) throw authFailure(c, "invalid_session_cookie");
    const user = await getAdminUser(session.sub);
    if (!user?.isActive) throw authFailure(c, "inactive_or_deleted_user");

    c.set("actor", {
      kind: "user",
      userId: user.id,
      email: user.email,
      name: user.name,
      isSuperAdmin: user.isSuperAdmin,
    });
    await next();
  };
}

export const adminAuth = createAdminAuth();

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

/** Requires `X-CSRF-Token` on mutating requests from session actors. Runs after `adminAuth`. */
export const csrfProtection: MiddlewareHandler<AdminEnv> = async (c, next) => {
  if (!SAFE_METHODS.has(c.req.method) && c.var.actor.kind === "user") {
    const token = getCookie(c, SESSION_COOKIE) ?? "";
    const header = c.req.header("X-CSRF-Token") ?? "";
    if (!header || !safeEqual(header, csrfTokenFor(token))) {
      throw new ApiError(403, "csrf_required", "Missing or invalid X-CSRF-Token header");
    }
  }
  await next();
};
