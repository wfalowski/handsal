import {
  applicationCreateSchema,
  applicationUpdateSchema,
  rotateSecretSchema,
} from "@handsal/shared";
import { type Context, Hono } from "hono";
import { z } from "zod";
import { env } from "../../env.js";
import type { AdminEnv } from "../../middleware/admin-auth.js";
import { ApiError } from "../../middleware/error-handler.js";
import { requireTenantAccess } from "../../middleware/tenant-access.js";
import {
  createApplication,
  deleteApplication,
  getApplication,
  listApplications,
  revokeAllApplicationTokens,
  rotateSecret,
  setApplicationStatus,
  updateApplication,
} from "../../services/application.service.js";
import { getGrants } from "../../services/grant.service.js";
import { getTenantById } from "../../services/tenant.service.js";
import { countIssuedLastHour, listTokenEvents } from "../../services/token-event.service.js";
import { applicationKeyRoutes } from "./application-keys.js";
import { appIdParam, grantRoutes } from "./grants.js";

// strict(): any unknown key is a 400.
const createBodySchema = applicationCreateSchema.strict();

const listQuerySchema = z.object({
  q: z.string().max(255).optional(),
  status: z.enum(["active", "disabled", "needs_attention"]).optional(),
  kind: z.enum(["service", "agent"]).optional(),
});

const RECENT_TOKENS_LIMIT = 5;

const readJson = (c: Context<AdminEnv>): Promise<unknown> => c.req.json().catch(() => ({}));

// Mounted at /api/tenants.
export const applicationRoutes = new Hono<AdminEnv>();

applicationRoutes.get("/:tenantId/applications", requireTenantAccess("auditor"), async (c) => {
  const filters = listQuerySchema.parse(c.req.query());
  return c.json({ items: await listApplications(c.req.param("tenantId"), filters) });
});

applicationRoutes.post("/:tenantId/applications", requireTenantAccess("admin"), async (c) => {
  const input = createBodySchema.parse(await readJson(c));
  const actor = c.var.actor;
  const created = await createApplication(c.req.param("tenantId"), input, actor.userId);
  return c.json(created, 201);
});

applicationRoutes.get(
  "/:tenantId/applications/:appId",
  requireTenantAccess("auditor"),
  async (c) => {
    const tenantId = c.req.param("tenantId");
    const appId = appIdParam(c);
    const application = await getApplication(tenantId, appId);
    const budgeted = application.kind === "agent" && application.tokenBudgetPerHour !== null;
    const [tenant, grants, recent, budget] = await Promise.all([
      getTenantById(tenantId),
      getGrants(tenantId, appId),
      listTokenEvents(tenantId, { applicationId: appId, limit: RECENT_TOKENS_LIMIT }),
      budgeted ? countIssuedLastHour(tenantId, appId) : null,
    ]);
    // requireTenantAccess just confirmed the tenant; a miss means it was deleted mid-request.
    if (!tenant) throw new ApiError(404, "tenant_not_found", "Tenant not found");
    const issuer = `${env.PUBLIC_URL}/t/${tenant.slug}`;
    return c.json({
      application,
      grants,
      issuer,
      tokenEndpoint: `${issuer}/oauth/token`,
      recentTokens: recent.items,
      agentBudgetUsed: budget?.count ?? null,
    });
  },
);

applicationRoutes.patch(
  "/:tenantId/applications/:appId",
  requireTenantAccess("admin"),
  async (c) => {
    const appId = appIdParam(c);
    const input = applicationUpdateSchema.parse(await readJson(c));
    return c.json(await updateApplication(c.req.param("tenantId"), appId, input));
  },
);

applicationRoutes.delete(
  "/:tenantId/applications/:appId",
  requireTenantAccess("admin"),
  async (c) => {
    await deleteApplication(c.req.param("tenantId"), appIdParam(c));
    return c.body(null, 204);
  },
);

applicationRoutes.post(
  "/:tenantId/applications/:appId/rotate-secret",
  requireTenantAccess("admin"),
  async (c) => {
    const appId = appIdParam(c);
    const { graceSeconds } = rotateSecretSchema.parse(await readJson(c));
    return c.json(await rotateSecret(c.req.param("tenantId"), appId, graceSeconds));
  },
);

applicationRoutes.post(
  "/:tenantId/applications/:appId/disable",
  requireTenantAccess("admin"),
  async (c) =>
    c.json(await setApplicationStatus(c.req.param("tenantId"), appIdParam(c), "disabled")),
);

applicationRoutes.post(
  "/:tenantId/applications/:appId/enable",
  requireTenantAccess("admin"),
  async (c) => c.json(await setApplicationStatus(c.req.param("tenantId"), appIdParam(c), "active")),
);

applicationRoutes.post(
  "/:tenantId/applications/:appId/revoke-all-tokens",
  requireTenantAccess("admin"),
  async (c) => c.json(await revokeAllApplicationTokens(c.req.param("tenantId"), appIdParam(c))),
);

applicationRoutes.route("/", grantRoutes);
applicationRoutes.route("/", applicationKeyRoutes);
