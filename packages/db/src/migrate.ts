import { fileURLToPath } from "node:url";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import pg from "pg";

// `../drizzle` resolves to packages/db/drizzle from both src/ (tsx) and dist/ (node).
const migrationsFolder = fileURLToPath(new URL("../drizzle", import.meta.url));

export async function runMigrations() {
  const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL });
  try {
    await migrate(drizzle(pool), { migrationsFolder });
  } finally {
    await pool.end();
  }
}
