import { pool, runMigrations } from "@handsal/db";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { app } from "../../app.js";
import { addMember, createAdminUser, createTenant, truncateAll } from "../../test/factories.js";
import { jsonRequest, loginAs } from "../../test/helpers.js";

beforeAll(async () => {
  await runMigrations();
});

beforeEach(async () => {
  await truncateAll();
});

afterAll(async () => {
  await pool.end();
});

async function ownerSession() {
  const t = await createTenant();
  const { user, password } = await createAdminUser({ name: "Owner" });
  await addMember(t.id, user.id, "owner");
  const s = await loginAs(app, user.email, password);
  const call = (method: string, path: string, body?: unknown) =>
    jsonRequest(app, method, `/api/tenants/${t.id}/members${path}`, body, {
      cookie: s.cookie,
      "x-csrf-token": s.csrf,
    });
  return { t, owner: user, call };
}

describe("members routes", () => {
  it("GET lists members as MemberDto", async () => {
    const { owner, call } = await ownerSession();
    const res = await call("GET", "");
    expect(res.status).toBe(200);
    const [member] = await res.json();
    expect(member).toMatchObject({
      adminUserId: owner.id,
      email: owner.email,
      name: "Owner",
      role: "owner",
      isActive: true,
    });
    expect(typeof member.lastLoginAt).toBe("string"); // set by loginAs
    expect(member).not.toHaveProperty("passwordHash");
  });

  it("POST unknown email → 201 with a temporary password that logs in", async () => {
    const { call } = await ownerSession();
    const res = await call("POST", "", { email: "new@example.com", role: "admin" });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.temporaryPassword).toMatch(/^[0-9A-Za-z]{24}$/);
    expect(body.member).toMatchObject({ email: "new@example.com", name: "new", role: "admin" });
    await expect(loginAs(app, "new@example.com", body.temporaryPassword)).resolves.toBeTruthy();
  });

  it("POST existing user → linked without a password; twice → 409 already_member", async () => {
    const { call } = await ownerSession();
    const { user } = await createAdminUser();
    const res = await call("POST", "", { email: user.email, role: "auditor" });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body).not.toHaveProperty("temporaryPassword");
    expect(body.member.adminUserId).toBe(user.id);

    const again = await call("POST", "", { email: user.email, role: "admin" });
    expect(again.status).toBe(409);
    expect((await again.json()).error).toBe("already_member");
  });

  it("POST invalid body → 400", async () => {
    const { call } = await ownerSession();
    expect((await call("POST", "", { email: "nope", role: "admin" })).status).toBe(400);
    expect((await call("POST", "", { email: "a@b.co", role: "boss" })).status).toBe(400);
  });

  it("PATCH changes the role; DELETE removes", async () => {
    const { t, call } = await ownerSession();
    const { user } = await createAdminUser();
    await addMember(t.id, user.id, "auditor");

    const res = await call("PATCH", `/${user.id}`, { role: "owner" });
    expect(res.status).toBe(200);
    expect((await res.json()).role).toBe("owner");

    expect((await call("DELETE", `/${user.id}`)).status).toBe(204);
    const list = await (await call("GET", "")).json();
    expect(list.map((m: { adminUserId: string }) => m.adminUserId)).not.toContain(user.id);
  });

  it("own membership → 400 cannot_modify_self", async () => {
    const { owner, call } = await ownerSession();
    for (const res of [
      await call("PATCH", `/${owner.id}`, { role: "admin" }),
      await call("DELETE", `/${owner.id}`),
    ]) {
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("cannot_modify_self");
    }
  });

  it("last owner (changed by a super-admin) → 409 last_owner", async () => {
    const { t, owner } = await ownerSession();
    const sa = await createAdminUser({ isSuperAdmin: true });
    const s = await loginAs(app, sa.user.email, sa.password);
    const headers = { cookie: s.cookie, "x-csrf-token": s.csrf };
    const base = `/api/tenants/${t.id}/members/${owner.id}`;

    const demote = await jsonRequest(app, "PATCH", base, { role: "admin" }, headers);
    expect(demote.status).toBe(409);
    expect((await demote.json()).error).toBe("last_owner");
    const remove = await jsonRequest(app, "DELETE", base, undefined, headers);
    expect(remove.status).toBe(409);
  });

  it("unknown member or invalid UUID → 404 member_not_found", async () => {
    const { call } = await ownerSession();
    const { user } = await createAdminUser();
    for (const res of [
      await call("PATCH", `/${user.id}`, { role: "admin" }),
      await call("DELETE", `/${user.id}`),
      await call("PATCH", "/not-a-uuid", { role: "admin" }),
      await call("DELETE", "/not-a-uuid"),
    ]) {
      expect(res.status).toBe(404);
      expect((await res.json()).error).toBe("member_not_found");
    }
  });

  it("a member of another tenant cannot be modified through this tenant", async () => {
    const { call } = await ownerSession();
    const other = await createTenant();
    const { user } = await createAdminUser();
    await addMember(other.id, user.id, "auditor");
    expect((await call("DELETE", `/${user.id}`)).status).toBe(404);
  });
});
