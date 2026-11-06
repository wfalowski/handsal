import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as relations from "./relations.js";
import * as tables from "./schema/index.js";

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  maxLifetimeSeconds: 60 * 60,
});

// node-postgres emits 'error' on an idle client when the backend drops the
// connection (DB restart/failover, idle-connection reaping, network blip). With
// no listener, Node re-throws it as an uncaughtException and crashes the whole
// process. Log and swallow — the pool discards the broken client and reconnects
// on the next checkout. (@handsal/db has no logger of its own, so use console.)
pool.on("error", (err) => {
  console.error("[db] Unexpected error on idle PostgreSQL client:", err);
});

export const db = drizzle(pool, { schema: { ...tables, ...relations } });
export { pool };
