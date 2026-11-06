import { applications, db, resources, tenantMembers, tenants, tokenEvents } from "@handsal/db";
import type {
  TenantDto,
  TenantRole,
  TokenStatsDto,
  tenantCreateSchema,
  tenantUpdateSchema,
} from "@handsal/shared";
import { and, asc, count, eq, sql } from "drizzle-orm";
import type { z } from "zod";
import { env } from "../env.js";
import { ApiError } from "../middleware/error-handler.js";
import { encryptPrivateKey } from "../utils/crypto.js";
import { ensureActiveKey } from "./signing-key.service.js";
import { getTokenStats } from "./token-event.service.js";

export type Tenant = typeof tenants.$inferSelect;
export type TenantCreateInput = z.infer<typeof tenantCreateSchema>;
export type TenantUpdateInput = z.infer<typeof tenantUpdateSchema>;
export type TenantListItem = TenantDto & {
  appCount: number;
  resourceCount: number;
  tokens24h: number;
  role: TenantRole;
};
export type TenantDetail = TenantDto & {
  discoveryUrl: string;
  jwksUrl: string;
  stats: TokenStatsDto;
};

export const issuerFor = (slug: string) => `${env.PUBLIC_URL}/t/${slug}`;

export function toTenantDto(row: Tenant): TenantDto {
  return {
    id: row.id,
    name: row.name,
    slug: row.slug,
    status: row.status,
    defaultTokenTtlSeconds: row.defaultTokenTtlSeconds,
    introspectionEnabled: row.introspectionEnabled,
    keyRotationDays: row.keyRotationDays,
    tokensNotBefore: row.tokensNotBefore ? row.tokensNotBefore.toISOString() : null,
    issuer: issuerFor(row.slug),
    externalIdp: row.externalIdp ?? null,
    approvalWebhookUrl: row.approvalWebhookUrl,
    // The secret is write-only.
    approvalWebhookSecretSet: row.approvalWebhookSecretEnc !== null,
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
}

const notFound = () => new ApiError(404, "tenant_not_found", "Tenant not found");

export async function getTenantBySlug(slug: string): Promise<Tenant | null> {
  const [tenant] = await db.select().from(tenants).where(eq(tenants.slug, slug)).limit(1);
  return tenant ?? null;
}

export async function getTenantById(id: string): Promise<Tenant | null> {
  const [tenant] = await db.select().from(tenants).where(eq(tenants.id, id)).limit(1);
  return tenant ?? null;
}

/**
 * Tenants with dashboard counters. `memberUserId` limits the list to that user's memberships
 * (with their role); omit it for the super-admin / API-key view (every tenant as `owner`).
 * One grouped subquery per counter, left-joined: no N+1.
 */
export async function listTenantsWithStats(memberUserId?: string): Promise<TenantListItem[]> {
  const appCounts = db
    .select({ tenantId: applications.tenantId, n: count().as("app_count") })
    .from(applications)
    .groupBy(applications.tenantId)
    .as("app_counts");
  const resourceCounts = db
    .select({ tenantId: resources.tenantId, n: count().as("resource_count") })
    .from(resources)
    .groupBy(resources.tenantId)
    .as("resource_counts");
  const tokenCounts = db
    .select({ tenantId: tokenEvents.tenantId, n: count().as("tokens_24h") })
    .from(tokenEvents)
    .where(
      and(
        eq(tokenEvents.outcome, "issued"),
        sql`${tokenEvents.createdAt} >= now() - interval '24 hours'`,
      ),
    )
    .groupBy(tokenEvents.tenantId)
    .as("token_counts");

  const base = db
    .select({
      tenant: tenants,
      role: memberUserId ? tenantMembers.role : sql<TenantRole>`'owner'::tenant_role`,
      appCount: appCounts.n,
      resourceCount: resourceCounts.n,
      tokens24h: tokenCounts.n,
    })
    .from(tenants)
    .leftJoin(appCounts, eq(appCounts.tenantId, tenants.id))
    .leftJoin(resourceCounts, eq(resourceCounts.tenantId, tenants.id))
    .leftJoin(tokenCounts, eq(tokenCounts.tenantId, tenants.id))
    .$dynamic();
  const rows = await (memberUserId
    ? base.innerJoin(
        tenantMembers,
        and(eq(tenantMembers.tenantId, tenants.id), eq(tenantMembers.adminUserId, memberUserId)),
      )
    : base
  ).orderBy(asc(tenants.name));

  return rows.map((r) => ({
    ...toTenantDto(r.tenant),
    appCount: r.appCount ?? 0,
    resourceCount: r.resourceCount ?? 0,
    tokens24h: r.tokens24h ?? 0,
    role: r.role,
  }));
}

/**
 * One transaction: insert tenant → first signing key → creator as `owner`
 * (`creatorUserId` is omitted for the API key, which gets no membership).
 */
export async function createTenant(
  input: TenantCreateInput,
  creatorUserId?: string,
): Promise<TenantDto> {
  const row = await db.transaction(async (tx) => {
    const [tenant] = await tx
      .insert(tenants)
      .values({ name: input.name, slug: input.slug })
      .returning()
      .catch((err: unknown) => {
        const cause = (err as { cause?: { code?: string; constraint?: string } }).cause;
        if (cause?.code === "23505" && cause.constraint === "tenants_slug_unique") {
          throw new ApiError(409, "slug_exists", "A tenant with this slug already exists");
        }
        throw err;
      });
    await ensureActiveKey(tenant.id, tx);
    if (creatorUserId) {
      await tx
        .insert(tenantMembers)
        .values({ tenantId: tenant.id, adminUserId: creatorUserId, role: "owner" });
    }
    return tenant;
  });
  return toTenantDto(row);
}

export async function getTenantDetail(tenantId: string): Promise<TenantDetail> {
  const tenant = await getTenantById(tenantId);
  if (!tenant) throw notFound();
  const dto = toTenantDto(tenant);
  return {
    ...dto,
    discoveryUrl: `${dto.issuer}/.well-known/openid-configuration`,
    jwksUrl: `${dto.issuer}/.well-known/jwks.json`,
    stats: await getTokenStats(tenantId),
  };
}

async function updateOne(
  tenantId: string,
  values: Partial<typeof tenants.$inferInsert>,
): Promise<TenantDto> {
  const [row] = await db.update(tenants).set(values).where(eq(tenants.id, tenantId)).returning();
  if (!row) throw notFound();
  return toTenantDto(row);
}

export async function updateTenant(tenantId: string, input: TenantUpdateInput): Promise<TenantDto> {
  const { approvalWebhookSecret, ...rest } = input;
  if (rest.approvalWebhookUrl) assertWebhookUrl(rest.approvalWebhookUrl);
  // Empty PATCH still bumps updated_at (Drizzle rejects an empty SET).
  return updateOne(tenantId, {
    ...rest,
    // An HMAC key cannot be hashed: AES-256-GCM at rest, like signing keys. `null` clears it.
    ...(approvalWebhookSecret !== undefined && {
      approvalWebhookSecretEnc:
        approvalWebhookSecret === null
          ? null
          : encryptPrivateKey(approvalWebhookSecret, env.KEY_ENCRYPTION_SECRET),
    }),
    updatedAt: new Date(),
  });
}

/** Outbound destination control: https only in production (http allowed for local development). */
function assertWebhookUrl(url: string): void {
  const { protocol } = new URL(url);
  if (protocol === "https:" || (protocol === "http:" && env.NODE_ENV !== "production")) return;
  throw new ApiError(
    400,
    "validation_error",
    env.NODE_ENV === "production"
      ? "approvalWebhookUrl must use https"
      : "approvalWebhookUrl must use http or https",
  );
}

export async function setTenantStatus(
  tenantId: string,
  status: Tenant["status"],
): Promise<TenantDto> {
  return updateOne(tenantId, { status });
}

/** Tokens of this tenant with `iat < tokens_not_before` become inactive (enforced by introspection). */
export async function revokeAllTenantTokens(tenantId: string): Promise<TenantDto> {
  return updateOne(tenantId, { tokensNotBefore: new Date() });
}

/** Deletes the tenant (children cascade) when `confirmSlug` equals its slug. */
export async function deleteTenant(tenantId: string, confirmSlug: string): Promise<void> {
  const tenant = await getTenantById(tenantId);
  if (!tenant) throw notFound();
  if (tenant.slug !== confirmSlug) {
    throw new ApiError(400, "confirm_slug_mismatch", "confirmSlug does not match the tenant slug");
  }
  await db.delete(tenants).where(eq(tenants.id, tenantId));
}
