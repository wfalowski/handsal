import { Hono } from "hono";
import type { AppEnv } from "../../app.js";

// Mounted at /api. Endpoints are added in Phase 3.
export const managementRoutes = new Hono<AppEnv>();
