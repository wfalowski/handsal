import "dotenv/config";
import crypto from "node:crypto";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import argon2 from "argon2";
import { and, eq } from "drizzle-orm";
import { db, pool } from "./client.js";
import {
  adminUsers,
  applicationGrants,
  applications,
  resources,
  scopes,
  tenants,
} from "./schema/index.js";

const ADMIN_EMAIL = "admin@handsal.local";
const ADMIN_PASSWORD = "handsal-dev-password";
const TENANT_SLUG = "acme-payments";
const APP_NAME = "billing-service";
const RESOURCES = [
  {
    name: "Payments API",
    audience: "https://api.acme.io/payments",
    scopes: ["payments:read", "payments:write", "payments:refund"],
  },
  {
    name: "Invoices API",
    audience: "https://api.acme.io/invoices",
    scopes: ["invoices:read", "invoices:write", "invoices:void"],
  },
];
const GRANTED_SCOPES = ["payments:read", "invoices:write"];

const BASE32_LOWER = "abcdefghijklmnopqrstuvwxyz234567";
const BASE62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

function randomString(alphabet: string, length: number): string {
  return Array.from({ length }, () => alphabet[crypto.randomInt(alphabet.length)]).join("");
}

const hash = (plain: string) => argon2.hash(plain, { type: argon2.argon2id });

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/** True only for a URL whose host is localhost, 127.0.0.1, or ::1 (brackets optional). */
export function seedDatabaseHostAllowed(databaseUrl: string | undefined): boolean {
  if (!databaseUrl) return false;
  try {
    let hostname = new URL(databaseUrl).hostname.toLowerCase();
    if (hostname.startsWith("[") && hostname.endsWith("]")) hostname = hostname.slice(1, -1);
    return LOOPBACK_HOSTS.has(hostname);
  } catch {
    return false;
  }
}

async function seed() {
  if (process.env.NODE_ENV === "production") {
    console.error("Seed script must not be run in production");
    process.exit(1);
  }

  if (!seedDatabaseHostAllowed(process.env.DATABASE_URL)) {
    console.error(
      "Seed script must not be run unless DATABASE_URL uses a loopback host (localhost, 127.0.0.1, or ::1)",
    );
    process.exit(1);
  }

  console.log("Seeding database...");

  const [existingAdmin] = await db
    .select()
    .from(adminUsers)
    .where(eq(adminUsers.email, ADMIN_EMAIL));
  if (existingAdmin) {
    console.log(`Admin exists: ${ADMIN_EMAIL}`);
  } else {
    await db.insert(adminUsers).values({
      email: ADMIN_EMAIL,
      passwordHash: await hash(ADMIN_PASSWORD),
      name: "Handsal Admin",
      isSuperAdmin: true,
    });
    console.log(`Created super-admin: ${ADMIN_EMAIL} / ${ADMIN_PASSWORD}`);
  }

  let [tenant] = await db.select().from(tenants).where(eq(tenants.slug, TENANT_SLUG));
  if (!tenant) {
    [tenant] = await db
      .insert(tenants)
      .values({ name: "Acme Payments", slug: TENANT_SLUG })
      .returning();
    console.log(`Created tenant: ${tenant.slug} (${tenant.id})`);
  }

  const scopeIdsByName = new Map<string, string>();
  for (const spec of RESOURCES) {
    let [resource] = await db
      .select()
      .from(resources)
      .where(and(eq(resources.tenantId, tenant.id), eq(resources.name, spec.name)));
    if (!resource) {
      [resource] = await db
        .insert(resources)
        .values({ tenantId: tenant.id, name: spec.name, audience: spec.audience })
        .returning();
      console.log(`Created resource: ${resource.audience}`);
    }
    for (const name of spec.scopes) {
      let [scope] = await db
        .select()
        .from(scopes)
        .where(and(eq(scopes.resourceId, resource.id), eq(scopes.name, name)));
      if (!scope) {
        [scope] = await db
          .insert(scopes)
          .values({ tenantId: tenant.id, resourceId: resource.id, name })
          .returning();
      }
      scopeIdsByName.set(name, scope.id);
    }
  }

  let [app] = await db
    .select()
    .from(applications)
    .where(and(eq(applications.tenantId, tenant.id), eq(applications.name, APP_NAME)));
  let plainSecret: string | undefined;
  if (!app) {
    plainSecret = `hs_${randomString(BASE62, 48)}`;
    [app] = await db
      .insert(applications)
      .values({
        tenantId: tenant.id,
        name: APP_NAME,
        clientId: `app_${randomString(BASE32_LOWER, 20)}`,
        clientSecretHash: await hash(plainSecret),
      })
      .returning();
  }

  await db
    .insert(applicationGrants)
    .values(
      GRANTED_SCOPES.map((name) => ({
        tenantId: tenant.id,
        applicationId: app.id,
        scopeId: scopeIdsByName.get(name)!,
      })),
    )
    .onConflictDoNothing();

  if (plainSecret) {
    console.log("\n--- Test Credentials (development only, shown once) ---");
    console.log(`Client ID:     ${app.clientId}`);
    console.log(`Client Secret: ${plainSecret}`);
    console.log(`Token URL:     /t/${tenant.slug}/oauth/token`);
    console.log("-------------------------------------------------------\n");
  } else {
    console.log(`Application exists: ${app.clientId} (secret was shown when it was created)`);
  }

  await pool.end();
  console.log("Seeding complete.");
}

// Direct `tsx src/seed.ts` only. Importing the helper from tests must not insert rows.
function isDirectRun(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  seed().catch((err) => {
    console.error("Seed failed:", err);
    process.exit(1);
  });
}
