import type { SigningKeyDto } from "@handsal/shared";
import { Hono } from "hono";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import { listKeys, rotateKey, type SigningKey } from "../../services/signing-key.service.js";

export const signingKeyRoutes = new Hono<AdminEnv>();

// Explicit mapping: PEMs never leave the API.
const toDto = (k: SigningKey): SigningKeyDto => ({
  id: k.id,
  kid: k.kid,
  algorithm: k.algorithm,
  status: k.status,
  retiresAt: k.retiresAt?.toISOString() ?? null,
  createdAt: k.createdAt.toISOString(),
});

signingKeyRoutes.get("/:tenantId/signing-keys", requireTenantAccess("auditor"), async (c) => {
  const keys = await listKeys(c.req.param("tenantId"));
  return c.json({ items: keys.map(toDto) });
});

signingKeyRoutes.post("/:tenantId/signing-keys/rotate", requireTenantAccess("admin"), async (c) =>
  c.json(toDto(await rotateKey(c.req.param("tenantId"), {})), 201),
);
