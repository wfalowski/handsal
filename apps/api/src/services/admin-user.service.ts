import { adminUsers, db, tenantMembers, tenants } from "@handsal/db";
import type { TenantRole } from "@handsal/shared";
import { and, asc, eq } from "drizzle-orm";
import { ApiError } from "../middleware/error-handler.js";
import { hashSecret, verifySecret } from "../utils/crypto.js";

export type AdminUser = typeof adminUsers.$inferSelect;

export interface AdminUserCreateInput {
  email: string;
  password: string;
  name: string;
  isSuperAdmin?: boolean;
}

export interface UserTenant {
  id: string;
  name: string;
  slug: string;
  role: TenantRole;
}

// Real Argon2id hash so the unknown-user path costs the same as a real verify.
// Created lazily: hashing at import time would slow every module that imports this file.
let dummyHashPromise: Promise<string> | undefined;
const dummyHash = () => {
  dummyHashPromise ??= hashSecret("dummy-admin-password-for-timing-safety");
  return dummyHashPromise;
};

const normalizeEmail = (email: string) => email.trim().toLowerCase();

export async function createAdminUser(input: AdminUserCreateInput): Promise<AdminUser> {
  const passwordHash = await hashSecret(input.password);
  try {
    const [user] = await db
      .insert(adminUsers)
      .values({
        email: normalizeEmail(input.email),
        passwordHash,
        name: input.name,
        isSuperAdmin: input.isSuperAdmin ?? false,
      })
      .returning();
    return user;
  } catch (err) {
    const cause = (err as { cause?: { code?: string; constraint?: string } }).cause;
    if (cause?.code === "23505" && cause.constraint === "admin_users_email_unique") {
      throw new ApiError(409, "email_exists", "An admin user with this email already exists");
    }
    throw err;
  }
}

/** Returns the active user whose password matches, or null (timing-equalised for unknown emails). */
export async function authenticateAdminUser(
  email: string,
  password: string,
): Promise<AdminUser | null> {
  const [user] = await db
    .select()
    .from(adminUsers)
    .where(eq(adminUsers.email, normalizeEmail(email)))
    .limit(1);

  if (!user?.isActive) {
    await verifySecret(password, await dummyHash());
    return null;
  }
  return (await verifySecret(password, user.passwordHash)) ? user : null;
}

export async function getAdminUser(id: string): Promise<AdminUser | null> {
  const [user] = await db.select().from(adminUsers).where(eq(adminUsers.id, id)).limit(1);
  return user ?? null;
}

export async function touchLastLogin(id: string): Promise<void> {
  await db.update(adminUsers).set({ lastLoginAt: new Date() }).where(eq(adminUsers.id, id));
}

/** Tenants the user is a member of, with their role. */
export async function listTenantsForUser(userId: string): Promise<UserTenant[]> {
  return db
    .select({ id: tenants.id, name: tenants.name, slug: tenants.slug, role: tenantMembers.role })
    .from(tenantMembers)
    .innerJoin(tenants, eq(tenants.id, tenantMembers.tenantId))
    .where(eq(tenantMembers.adminUserId, userId))
    .orderBy(asc(tenants.name));
}

/** Every tenant as `owner` (super-admin / API key view). */
export async function listAllTenantsAsOwner(): Promise<UserTenant[]> {
  const rows = await db
    .select({ id: tenants.id, name: tenants.name, slug: tenants.slug })
    .from(tenants)
    .orderBy(asc(tenants.name));
  return rows.map((t) => ({ ...t, role: "owner" as const }));
}

export async function getTenantRole(userId: string, tenantId: string): Promise<TenantRole | null> {
  const [row] = await db
    .select({ role: tenantMembers.role })
    .from(tenantMembers)
    .where(and(eq(tenantMembers.adminUserId, userId), eq(tenantMembers.tenantId, tenantId)))
    .limit(1);
  return row?.role ?? null;
}
