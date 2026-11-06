import { applicationKeyCreateSchema, applicationKeyRetireSchema } from "@handsal/shared";
import { type Context, Hono } from "hono";
import { z } from "zod";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { ApiError } from "../../middleware/error-handler.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import {
  createApplicationKey,
  deleteApplicationKey,
  listApplicationKeys,
  retireApplicationKey,
} from "../../services/application-key.service.js";
import { appIdParam } from "./grants.js";

/** `:keyId` from the path; a non-UUID is indistinguishable from a missing key (404). */
function keyIdParam(c: Context<AdminEnv>): string {
  const keyId = c.req.param("keyId");
  if (!z.uuid().safeParse(keyId).success) {
    throw new ApiError(404, "application_key_not_found", "Application key not found");
  }
  return keyId as string;
}

const readJson = (c: Context<AdminEnv>): Promise<unknown> => c.req.json().catch(() => ({}));

const KEYS = "/:tenantId/applications/:appId/keys";

// Mounted under /api/tenants via ./applications.ts.
export const applicationKeyRoutes = new Hono<AdminEnv>();

applicationKeyRoutes.get(KEYS, requireTenantAccess("auditor"), async (c) =>
  c.json({ items: await listApplicationKeys(c.req.param("tenantId"), appIdParam(c)) }),
);

applicationKeyRoutes.post(KEYS, requireTenantAccess("admin"), async (c) => {
  const appId = appIdParam(c);
  const input = applicationKeyCreateSchema.parse(await readJson(c));
  return c.json(await createApplicationKey(c.req.param("tenantId"), appId, input), 201);
});

applicationKeyRoutes.post(`${KEYS}/:keyId/retire`, requireTenantAccess("admin"), async (c) => {
  const appId = appIdParam(c);
  const keyId = keyIdParam(c);
  const input = applicationKeyRetireSchema.parse(await readJson(c));
  return c.json(await retireApplicationKey(c.req.param("tenantId"), appId, keyId, input));
});

applicationKeyRoutes.delete(`${KEYS}/:keyId`, requireTenantAccess("admin"), async (c) => {
  await deleteApplicationKey(c.req.param("tenantId"), appIdParam(c), keyIdParam(c));
  return c.body(null, 204);
});
