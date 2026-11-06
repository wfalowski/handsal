import { randomUUID } from "node:crypto";
import { adminUsers, db, pool, runMigrations, tenantMembers } from "@handsal/db";
import { and, eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "../middleware/error-handler.js";
import {
  addMember as addMemberRow,
  createAdminUser,
  createTenant,
  truncateAll,
} from "../test/factories.js";
import { authenticateAdminUser } from "./admin-user.service.js";
import { addMember, listMembers, removeMember, updateMemberRole } from "./member.service.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

async function apiErrorOf(promise: Promise<unknown>): Promise<ApiError> {
  const err = await promise.then(
    () => {
      throw new Error("expected rejection");
    },
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(ApiError);
  return err as ApiError;
}

const roleOf = async (tenantId: string, adminUserId: string) =>
  (
    await db
      .select({ role: tenantMembers.role })
      .from(tenantMembers)
      .where(and(eq(tenantMembers.tenantId, tenantId), eq(tenantMembers.adminUserId, adminUserId)))
  )[0]?.role;

describe("addMember", () => {
  it("links an existing user (email case-insensitive) without a temporary password", async () => {
    const t = await createTenant();
    const { user } = await createAdminUser({ name: "Ada" });
    const res = await addMember(t.id, { email: user.email.toUpperCase(), role: "admin" });
    expect(res.temporaryPassword).toBeUndefined();
    expect(res.member).toMatchObject({ adminUserId: user.id, email: user.email, role: "admin" });
  });

  it("creates an unknown user with a 24-char temporary password that works for login", async () => {
    const t = await createTenant();
    const res = await addMember(t.id, { email: "new@example.com", name: "New", role: "auditor" });
    expect(res.temporaryPassword).toMatch(/^[0-9A-Za-z]{24}$/);
    expect(res.member).toMatchObject({ email: "new@example.com", name: "New", role: "auditor" });
    const user = await authenticateAdminUser("new@example.com", res.temporaryPassword as string);
    expect(user?.id).toBe(res.member.adminUserId);
  });

  it("creates no admin user when the membership insert fails", async () => {
    // Unknown tenant id → FK violation on tenant_members after the user insert.
    await expect(
      addMember(randomUUID(), { email: "orphan@example.com", role: "admin" }),
    ).rejects.toThrow();
    expect(
      await db.select().from(adminUsers).where(eq(adminUsers.email, "orphan@example.com")),
    ).toEqual([]);
  });

  it("already a member → 409 already_member", async () => {
    const t = await createTenant();
    const { user } = await createAdminUser();
    await addMemberRow(t.id, user.id, "auditor");
    const err = await apiErrorOf(addMember(t.id, { email: user.email, role: "admin" }));
    expect([err.statusCode, err.errorCode]).toEqual([409, "already_member"]);
  });

  it("listMembers returns only this tenant's members", async () => {
    const t = await createTenant();
    const other = await createTenant();
    const a = await createAdminUser();
    const b = await createAdminUser();
    await addMemberRow(t.id, a.user.id, "owner");
    await addMemberRow(other.id, b.user.id, "owner");
    const members = await listMembers(t.id);
    expect(members.map((m) => m.adminUserId)).toEqual([a.user.id]);
    expect(members[0]).toEqual({
      adminUserId: a.user.id,
      email: a.user.email,
      name: a.user.name,
      role: "owner",
      isActive: true,
      lastLoginAt: null,
      createdAt: a.user.createdAt.toISOString(),
    });
  });
});

describe("updateMemberRole / removeMember", () => {
  it("refuses to demote or remove the last owner (409 last_owner)", async () => {
    const t = await createTenant();
    const owner = await createAdminUser();
    await addMemberRow(t.id, owner.user.id, "owner");

    for (const attempt of [
      updateMemberRole(t.id, owner.user.id, "admin"),
      removeMember(t.id, owner.user.id),
    ]) {
      const err = await apiErrorOf(attempt);
      expect([err.statusCode, err.errorCode]).toEqual([409, "last_owner"]);
    }
    expect(await roleOf(t.id, owner.user.id)).toBe("owner");
  });

  it("allows demoting/removing an owner while another owner remains", async () => {
    const t = await createTenant();
    const a = await createAdminUser();
    const b = await createAdminUser();
    await addMemberRow(t.id, a.user.id, "owner");
    await addMemberRow(t.id, b.user.id, "owner");

    expect((await updateMemberRole(t.id, b.user.id, "auditor", a.user.id)).role).toBe("auditor");
    await apiErrorOf(removeMember(t.id, a.user.id)); // a is now the last owner
    await removeMember(t.id, b.user.id, a.user.id);
    expect(await roleOf(t.id, b.user.id)).toBeUndefined();
  });

  it("concurrent demotions of the two owners leave exactly one owner", async () => {
    const t = await createTenant();
    const a = await createAdminUser();
    const b = await createAdminUser();
    await addMemberRow(t.id, a.user.id, "owner");
    await addMemberRow(t.id, b.user.id, "owner");

    const results = await Promise.allSettled([
      updateMemberRole(t.id, a.user.id, "admin"),
      updateMemberRole(t.id, b.user.id, "admin"),
    ]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    const roles = [await roleOf(t.id, a.user.id), await roleOf(t.id, b.user.id)];
    expect(roles.filter((r) => r === "owner")).toHaveLength(1);
  });

  it("cannot modify own membership (400 cannot_modify_self)", async () => {
    const t = await createTenant();
    const a = await createAdminUser();
    await addMemberRow(t.id, a.user.id, "owner");
    for (const attempt of [
      updateMemberRole(t.id, a.user.id, "owner", a.user.id),
      removeMember(t.id, a.user.id, a.user.id),
    ]) {
      const err = await apiErrorOf(attempt);
      expect([err.statusCode, err.errorCode]).toEqual([400, "cannot_modify_self"]);
    }
  });

  it("unknown member → 404 member_not_found", async () => {
    const t = await createTenant();
    const { user } = await createAdminUser();
    const err = await apiErrorOf(updateMemberRole(t.id, user.id, "admin"));
    expect([err.statusCode, err.errorCode]).toEqual([404, "member_not_found"]);
  });
});
