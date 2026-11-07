import { loginSchema } from "@handsal/shared";
import { Hono } from "hono";
import { getCookie } from "hono/cookie";
import {
  type AdminEnv,
  clearSessionCookie,
  createSessionToken,
  csrfTokenFor,
  SESSION_COOKIE,
  setSessionCookie,
  verifySessionToken,
} from "../../middleware/admin-auth.js";
import { ApiError } from "../../middleware/error-handler.js";
import { ipKey, type RateLimitEntry, rateLimit } from "../../middleware/rate-limit.js";
import {
  authenticateAdminUser,
  getAdminUser,
  listAllTenantsAsOwner,
  listTenantsForUser,
  revokeAdminSessions,
  touchLastLogin,
} from "../../services/admin-user.service.js";
import {
  extractRequestInfo,
  logSecurityEvent,
  SecurityEvent,
  SecuritySeverity,
} from "../../utils/security-logger.js";
import { MemoryStore } from "../../utils/store.js";

/** Exported so tests (and `loginAs`) can reset the login limiter between cases. */
export const loginRateLimitStore = new MemoryStore<RateLimitEntry>();

// Mounted at /api/auth. `/me` is behind adminAuth (applied in ./index.ts); login/logout are public.
export const authRoutes = new Hono<AdminEnv>();

authRoutes.post(
  "/login",
  rateLimit({ keyFn: ipKey, max: 5, windowMs: 15 * 60 * 1000, store: loginRateLimitStore }),
  async (c) => {
    const { email, password } = loginSchema.parse(await c.req.json().catch(() => ({})));
    const user = await authenticateAdminUser(email, password);
    if (!user) {
      logSecurityEvent({
        ...extractRequestInfo(c),
        event: SecurityEvent.ADMIN_LOGIN_FAILURE,
        severity: SecuritySeverity.HIGH,
      });
      throw new ApiError(401, "invalid_credentials", "Invalid email or password");
    }

    await touchLastLogin(user.id);
    // Do not bump sessionVersion: other browsers stay logged in until one of them logs out.
    const token = createSessionToken(user.id, Date.now(), user.sessionVersion);
    setSessionCookie(c, token);
    logSecurityEvent({
      ...extractRequestInfo(c),
      event: SecurityEvent.ADMIN_LOGIN_SUCCESS,
      severity: SecuritySeverity.LOW,
      details: { adminUserId: user.id },
    });

    return c.json({
      user: { id: user.id, email: user.email, name: user.name, isSuperAdmin: user.isSuperAdmin },
      csrfToken: csrfTokenFor(token),
    });
  },
);

// A current cookie revokes every session (session_version + 1), then the cookie is cleared.
// Missing, invalid, or already-stale cookies are cleared only — they must not bump the version.
// No CSRF header: SameSite=Strict, so a cross-site POST does not include the cookie.
authRoutes.post("/logout", async (c) => {
  const token = getCookie(c, SESSION_COOKIE);
  if (token) {
    const session = verifySessionToken(token);
    if (session) {
      const user = await getAdminUser(session.sub);
      if (user && user.sessionVersion === session.sv) {
        await revokeAdminSessions(user.id, session.sv);
      }
    }
    logSecurityEvent({
      ...extractRequestInfo(c),
      event: SecurityEvent.ADMIN_LOGOUT,
      severity: SecuritySeverity.LOW,
    });
  }
  clearSessionCookie(c);
  return c.body(null, 204);
});

authRoutes.get("/me", async (c) => {
  const actor = c.var.actor;
  const tenants = actor.isSuperAdmin
    ? await listAllTenantsAsOwner()
    : await listTenantsForUser(actor.userId);
  const user = {
    id: actor.userId,
    email: actor.email,
    name: actor.name,
    isSuperAdmin: actor.isSuperAdmin,
  };
  // The SPA loses its in-memory CSRF token on reload; re-derive it from the session cookie.
  const session = getCookie(c, SESSION_COOKIE);
  const csrfToken = session ? csrfTokenFor(session) : null;
  return c.json({ user, tenants, csrfToken });
});
