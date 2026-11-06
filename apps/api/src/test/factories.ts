import { randomUUID } from "node:crypto";
import { applicationGrants, db, resources, scopes, tenantMembers, tenants } from "@handsal/db";
import type { TenantRole } from "@handsal/shared";
import { sql } from "drizzle-orm";
import {
  exportSPKI,
  generateKeyPair,
  type JWTHeaderParameters,
  type JWTPayload,
  SignJWT,
} from "jose";
import {
  type AdminUserCreateInput,
  createAdminUser as createAdminUserService,
} from "../services/admin-user.service.js";
import {
  type ApplicationCreateInput,
  createApplication as createApplicationService,
} from "../services/application.service.js";
import { createApplicationKey as createApplicationKeyService } from "../services/application-key.service.js";

const TABLES = [
  "token_events",
  "revoked_tokens",
  "signing_keys",
  "application_grants",
  "scopes",
  "resources",
  "applications",
  "tenant_members",
  "admin_users",
  "tenants",
];

export async function truncateAll(): Promise<void> {
  await db.execute(sql.raw(`TRUNCATE TABLE ${TABLES.join(", ")} RESTART IDENTITY CASCADE`));
}

const uniq = () => randomUUID().slice(0, 8);

export async function createTenant(over: Partial<typeof tenants.$inferInsert> = {}) {
  const slug = over.slug ?? `tenant-${uniq()}`;
  const [tenant] = await db
    .insert(tenants)
    .values({ name: slug, slug, ...over })
    .returning();
  return tenant;
}

export async function createApplication(
  tenantId: string,
  over: Partial<ApplicationCreateInput> = {},
) {
  return createApplicationService(tenantId, { name: `app-${uniq()}`, ...over });
}

export async function createResourceWithScopes(
  tenantId: string,
  audience: string,
  scopeNames: string[],
  over: Partial<typeof resources.$inferInsert> = {},
) {
  const [resource] = await db
    .insert(resources)
    .values({ tenantId, name: `resource-${uniq()}`, audience, ...over })
    .returning();
  const created =
    scopeNames.length === 0
      ? []
      : await db
          .insert(scopes)
          .values(scopeNames.map((name) => ({ tenantId, resourceId: resource.id, name })))
          .returning();
  return { resource, scopes: created };
}

export async function grant(tenantId: string, appId: string, scopeIds: string[]): Promise<void> {
  await db
    .insert(applicationGrants)
    .values(scopeIds.map((scopeId) => ({ tenantId, applicationId: appId, scopeId })));
}

/** Admin user with a known plaintext password (for `loginAs`). */
export async function createAdminUser(over: Partial<AdminUserCreateInput> = {}) {
  const password = over.password ?? `password-${uniq()}`;
  const user = await createAdminUserService({
    email: `admin-${uniq()}@example.com`,
    name: "Test Admin",
    ...over,
    password,
  });
  return { user, password };
}

export async function addMember(tenantId: string, adminUserId: string, role: TenantRole) {
  await db.insert(tenantMembers).values({ tenantId, adminUserId, role });
}

/** Registers a fresh ES256 key for an application; returns the row and its private key. */
export async function createApplicationKey(tenantId: string, appId: string, kid = `kid-${uniq()}`) {
  const { publicKey, privateKey } = await generateKeyPair("ES256", { extractable: true });
  const key = await createApplicationKeyService(tenantId, appId, {
    kid,
    publicKeyPem: await exportSPKI(publicKey),
  });
  return { key, privateKey };
}

/** Signs an RFC 7523 client assertion for `clientId`; `claims`/`header` override the defaults. */
export async function signClientAssertion(
  privateKey: CryptoKey,
  opts: {
    clientId: string;
    kid: string;
    tenantSlug: string;
    claims?: JWTPayload;
    header?: Partial<JWTHeaderParameters>;
  },
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    iss: opts.clientId,
    sub: opts.clientId,
    aud: `${process.env.PUBLIC_URL}/t/${opts.tenantSlug}/oauth/token`,
    jti: randomUUID(),
    iat: now,
    exp: now + 60,
    ...opts.claims,
  })
    .setProtectedHeader({ alg: "ES256", kid: opts.kid, ...opts.header })
    .sign(privateKey);
}
