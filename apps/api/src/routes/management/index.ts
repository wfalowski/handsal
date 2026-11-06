import { Hono } from "hono";
import { except } from "hono/combine";
import { type AdminEnv, adminAuth, csrfProtection } from "../../middleware/admin-auth.js";
import { applicationRoutes } from "./applications.js";
import { authRoutes } from "./auth.js";
import { signingKeyRoutes } from "./signing-keys.js";
import { tokenEventRoutes } from "./token-events.js";
import { resourceRoutes } from "./resources.js";

// Mounted at /api. Everything except login/logout requires an actor (session or API key)
// and, for session actors, X-CSRF-Token on mutating methods.
export const managementRoutes = new Hono<AdminEnv>();

managementRoutes.use(
  "*",
  except(["/api/auth/login", "/api/auth/logout"], adminAuth, csrfProtection),
);

managementRoutes.route("/auth", authRoutes);
managementRoutes.route("/tenants", signingKeyRoutes);
managementRoutes.route("/tenants", tokenEventRoutes);
managementRoutes.route("/tenants", applicationRoutes);
managementRoutes.route("/tenants", resourceRoutes);
