import { Hono } from "hono";
import { except } from "hono/combine";
import { type AdminEnv, adminAuth, csrfProtection } from "../../middleware/admin-auth.js";
import { authRoutes } from "./auth.js";

// Mounted at /api. Everything except login/logout requires an actor (session or API key)
// and, for session actors, X-CSRF-Token on mutating methods.
export const managementRoutes = new Hono<AdminEnv>();

managementRoutes.use(
  "*",
  except(["/api/auth/login", "/api/auth/logout"], adminAuth, csrfProtection),
);

managementRoutes.route("/auth", authRoutes);
