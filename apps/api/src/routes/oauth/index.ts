import { Hono } from "hono";
import type { AppEnv } from "../../app.js";

// Mounted at /t/:slug. Endpoints are added in Phase 2.
export const oauthRoutes = new Hono<AppEnv>();
