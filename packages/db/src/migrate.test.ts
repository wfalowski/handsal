import { readFileSync } from "node:fs";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runMigrations } from "./migrate.js";

// A throwaway database next to the test one, so migrations start from empty.
const adminUrl = process.env.DATABASE_URL as string;
const freshName = `${new URL(adminUrl).pathname.slice(1)}_mig`;
const freshUrl = Object.assign(new URL(adminUrl), { pathname: `/${freshName}` }).toString();

const journal = JSON.parse(
  readFileSync(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8"),
) as { entries: unknown[] };

async function admin(sql: string) {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

beforeAll(async () => {
  await admin(`DROP DATABASE IF EXISTS "${freshName}" WITH (FORCE)`);
  await admin(`CREATE DATABASE "${freshName}"`);
});

afterAll(async () => {
  await admin(`DROP DATABASE IF EXISTS "${freshName}" WITH (FORCE)`);
});

describe("runMigrations", () => {
  it("serialises concurrent runs on a fresh database via the advisory lock", async () => {
    await Promise.all([runMigrations(freshUrl), runMigrations(freshUrl)]);

    const client = new pg.Client({ connectionString: freshUrl });
    await client.connect();
    try {
      const { rows } = await client.query(
        "select count(*)::int as n from drizzle.__drizzle_migrations",
      );
      expect(rows[0].n).toBe(journal.entries.length);
    } finally {
      await client.end();
    }
  });
});
