// Tests TRUNCATE every table: only ever point them at a dedicated *_test database,
// never at whatever DATABASE_URL the shell happens to export.
const url =
  process.env.TEST_DATABASE_URL ?? "postgresql://handsal:handsal_dev@localhost:5434/handsal_test";
const dbName = new URL(url).pathname.slice(1);
if (!dbName.endsWith("_test")) {
  throw new Error(`TEST_DATABASE_URL must name a database ending in _test (got "${dbName}")`);
}
process.env.NODE_ENV = "test";
process.env.DATABASE_URL = url;
process.env.PUBLIC_URL = "https://test.example.com";
process.env.KEY_ENCRYPTION_SECRET =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.CORS_ORIGINS = "http://localhost:5173";
process.env.LOG_LEVEL = "silent";
