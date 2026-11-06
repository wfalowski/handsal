import { adminUsers, db, tenantMembers } from "@handsal/db";
import type { MemberDto, memberCreateSchema, TenantRole } from "@handsal/shared";
import { and, asc, eq } from "drizzle-orm";
import type { z } from "zod";
import { ApiError } from "../middleware/error-handler.js";
import { generateClientSecret } from "../utils/crypto.js";
import { createAdminUser } from "./admin-user.service.js";

type Tx = Parameters<Parameters<typeof db.transaction>[0]>[0];
export type MemberCreateInput = z.infer<typeof memberCreateSchema>;

const memberColumns = {
  adminUserId: tenantMembers.adminUserId,
  email: adminUsers.email,
  name: adminUsers.name,
  role: tenantMembers.role,
  isActive: adminUsers.isActive,
  lastLoginAt: adminUsers.lastLoginAt,
  createdAt: adminUsers.createdAt,
};

type MemberRow = {
  adminUserId: string;
  email: string;
  name: string;
  role: TenantRole;
  isActive: boolean;
  lastLoginAt: Date | null;
  createdAt: Date;
};

const toMemberDto = (row: MemberRow): MemberDto => ({
  ...row,
  lastLoginAt: row.lastLoginAt ? row.lastLoginAt.toISOString() : null,
  createdAt: row.createdAt.toISOString(),
});

const notFound = () => new ApiError(404, "member_not_found", "Member not found");

async function getMember(
  tx: Tx | typeof db,
  tenantId: string,
  adminUserId: string,
): Promise<MemberDto> {
  const [row] = await tx
    .select(memberColumns)
    .from(tenantMembers)
    .innerJoin(adminUsers, eq(adminUsers.id, tenantMembers.adminUserId))
    .where(and(eq(tenantMembers.tenantId, tenantId), eq(tenantMembers.adminUserId, adminUserId)));
  if (!row) throw notFound();
  return toMemberDto(row);
}

export async function listMembers(tenantId: string): Promise<MemberDto[]> {
  const rows = await db
    .select(memberColumns)
    .from(tenantMembers)
    .innerJoin(adminUsers, eq(adminUsers.id, tenantMembers.adminUserId))
    .where(eq(tenantMembers.tenantId, tenantId))
    .orderBy(asc(adminUsers.email));
  return rows.map(toMemberDto);
}

/**
 * Links an existing admin user (by email) or creates one with a 24-char temporary password,
 * which is returned exactly once.
 */
export async function addMember(
  tenantId: string,
  input: MemberCreateInput,
): Promise<{ member: MemberDto; temporaryPassword?: string }> {
  const email = input.email.trim().toLowerCase();
  const [existing] = await db
    .select({ id: adminUsers.id })
    .from(adminUsers)
    .where(eq(adminUsers.email, email))
    .limit(1);

  let adminUserId = existing?.id;
  let temporaryPassword: string | undefined;
  if (!adminUserId) {
    temporaryPassword = generateClientSecret().slice(3, 27); // 24 base62 chars after `hs_`
    const user = await createAdminUser({
      email,
      password: temporaryPassword,
      name: input.name ?? email.split("@")[0],
    });
    adminUserId = user.id;
  }

  const [linked] = await db
    .insert(tenantMembers)
    .values({ tenantId, adminUserId, role: input.role })
    .onConflictDoNothing()
    .returning({ adminUserId: tenantMembers.adminUserId });
  if (!linked) throw new ApiError(409, "already_member", "This user is already a member");

  const member = await getMember(db, tenantId, adminUserId);
  return temporaryPassword ? { member, temporaryPassword } : { member };
}

/**
 * Shared guard for role changes and removals, run under row locks so two concurrent
 * demotions cannot both pass the last-owner check. `newRole` null = removal.
 */
async function changeMembership(
  tenantId: string,
  adminUserId: string,
  newRole: TenantRole | null,
  actorUserId: string | undefined,
): Promise<MemberDto | null> {
  if (actorUserId === adminUserId) {
    throw new ApiError(400, "cannot_modify_self", "You cannot change your own membership");
  }
  return db.transaction(async (tx) => {
    // Lock every owner row first (stable lock order), then the target.
    const owners = await tx
      .select({ adminUserId: tenantMembers.adminUserId })
      .from(tenantMembers)
      .where(and(eq(tenantMembers.tenantId, tenantId), eq(tenantMembers.role, "owner")))
      .for("update");
    const [target] = await tx
      .select({ role: tenantMembers.role })
      .from(tenantMembers)
      .where(and(eq(tenantMembers.tenantId, tenantId), eq(tenantMembers.adminUserId, adminUserId)))
      .for("update");
    if (!target) throw notFound();
    if (target.role === "owner" && newRole !== "owner" && owners.length <= 1) {
      throw new ApiError(409, "last_owner", "A tenant must keep at least one owner");
    }

    const where = and(
      eq(tenantMembers.tenantId, tenantId),
      eq(tenantMembers.adminUserId, adminUserId),
    );
    if (newRole === null) {
      await tx.delete(tenantMembers).where(where);
      return null;
    }
    await tx.update(tenantMembers).set({ role: newRole }).where(where);
    return getMember(tx, tenantId, adminUserId);
  });
}

export async function updateMemberRole(
  tenantId: string,
  adminUserId: string,
  role: TenantRole,
  actorUserId?: string,
): Promise<MemberDto> {
  return (await changeMembership(tenantId, adminUserId, role, actorUserId)) as MemberDto;
}

export async function removeMember(
  tenantId: string,
  adminUserId: string,
  actorUserId?: string,
): Promise<void> {
  await changeMembership(tenantId, adminUserId, null, actorUserId);
}
