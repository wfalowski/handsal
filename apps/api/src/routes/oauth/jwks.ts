import { Hono } from "hono";
import type { AppEnv } from "../../app.js";
import { ensureActiveKey, getJwks } from "../../services/signing-key.service.js";

/** Public JWKS (also for paused tenants, so issued tokens stay verifiable). Mounted at `/.well-known`. */
export function createJwksRoutes() {
  const routes = new Hono<AppEnv>();
  routes.get("/jwks.json", async (c) => {
    const { id } = c.var.tenant;
    await ensureActiveKey(id);
    c.header("Cache-Control", "public, max-age=300");
    return c.json(await getJwks(id));
  });
  return routes;
}
