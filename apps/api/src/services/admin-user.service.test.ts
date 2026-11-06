import { adminUsers, db, pool, runMigrations } from "@handsal/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "../middleware/error-handler.js";
import { addMember, createTenant, truncateAll } from "../test/factories.js";
import {
  authenticateAdminUser,
  createAdminUser,
  getTenantRole,
  listTenantsForUser,
} from "./admin-user.service.js";
import { bootstrapAdmin } from "./bootstrap.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

const input = { email: "Ada@Example.com", password: "correct-horse-battery", name: "Ada" };

describe("admin-user.service", () => {
  it("creates with an Argon2id hash and authenticates case-insensitively", async () => {
    const user = await createAdminUser(input);
    expect(user.email).toBe("ada@example.com");
    expect(user.passwordHash).toMatch(/^\$argon2id\$/);
    expect((await authenticateAdminUser("ADA@example.com", input.password))?.id).toBe(user.id);
    expect(await authenticateAdminUser(input.email, "wrong-password")).toBeNull();
    expect(await authenticateAdminUser("nobody@example.com", input.password)).toBeNull();
  });

  it("duplicate email → ApiError 409 email_exists", async () => {
    await createAdminUser(input);
    const err = await createAdminUser({ ...input, email: "ada@example.com" }).catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ statusCode: 409, errorCode: "email_exists" });
  });

  it("participates in a caller's transaction and rolls back with it", async () => {
    const rollback = new Error("rollback");
    await expect(
      db.transaction(async (tx) => {
        await createAdminUser(input, tx);
        throw rollback;
      }),
    ).rejects.toBe(rollback);
    expect(
      await db.select().from(adminUsers).where(eq(adminUsers.email, "ada@example.com")),
    ).toEqual([]);
  });

  it("lists tenants with role and resolves the role per tenant", async () => {
    const user = await createAdminUser(input);
    const t1 = await createTenant({ name: "One" });
    const t2 = await createTenant({ name: "Two" });
    await addMember(t1.id, user.id, "auditor");
    expect(await listTenantsForUser(user.id)).toEqual([
      { id: t1.id, name: "One", slug: t1.slug, role: "auditor" },
    ]);
    expect(await getTenantRole(user.id, t1.id)).toBe("auditor");
    expect(await getTenantRole(user.id, t2.id)).toBeNull();
  });
});

describe("bootstrapAdmin", () => {
  it("creates a super-admin once, then is a no-op", async () => {
    await bootstrapAdmin({ email: "root@example.com", password: "a-long-password-123" });
    await bootstrapAdmin({ email: "other@example.com", password: "a-long-password-123" });
    const rows = await db.select().from(adminUsers);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ email: "root@example.com", isSuperAdmin: true });
  });

  it("does nothing without credentials", async () => {
    await bootstrapAdmin({ email: undefined, password: undefined });
    expect(await db.select().from(adminUsers)).toHaveLength(0);
  });
});
