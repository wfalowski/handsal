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
} from "../../middleware/admin-auth.js";
import { ApiError } from "../../middleware/error-handler.js";
import { ipKey, type RateLimitEntry, rateLimit } from "../../middleware/rate-limit.js";
import {
  authenticateAdminUser,
  listAllTenantsAsOwner,
  listTenantsForUser,
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
    const token = createSessionToken(user.id);
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

// Stateless sessions: logout only clears the cookie; a copied token stays valid until exp.
authRoutes.post("/logout", (c) => {
  if (getCookie(c, SESSION_COOKIE)) {
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
  const user =
    actor.kind === "user"
      ? { id: actor.userId, email: actor.email, name: actor.name, isSuperAdmin: actor.isSuperAdmin }
      : { id: null, email: null, name: "API key", isSuperAdmin: true };
  return c.json({ user, tenants });
});
