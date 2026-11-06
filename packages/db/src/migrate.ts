import { fileURLToPath } from "node:url";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import pg from "pg";

// `../drizzle` resolves to packages/db/drizzle from both src/ (tsx) and dist/ (node).
const migrationsFolder = fileURLToPath(new URL("../drizzle", import.meta.url));

// Arbitrary fixed key: serialises migrations across replicas starting together.
const MIGRATION_LOCK_KEY = 7264181;

export async function runMigrations(connectionString = process.env.DATABASE_URL) {
  const pool = new pg.Pool({ connectionString, max: 1 });
  const client = await pool.connect();
  try {
    // Session-level lock: must stay on this one connection for the whole migration.
    await client.query("select pg_advisory_lock($1)", [MIGRATION_LOCK_KEY]);
    try {
      await migrate(drizzle(client), { migrationsFolder });
    } finally {
      await client.query("select pg_advisory_unlock($1)", [MIGRATION_LOCK_KEY]);
    }
  } finally {
    client.release();
    await pool.end();
  }
}
