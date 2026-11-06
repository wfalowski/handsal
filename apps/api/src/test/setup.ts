process.env.NODE_ENV = "test";
process.env.DATABASE_URL ??= "postgresql://handsal:handsal_dev@localhost:5434/handsal_test";
process.env.PUBLIC_URL = "https://test.example.com";
process.env.KEY_ENCRYPTION_SECRET =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
process.env.CORS_ORIGINS = "http://localhost:5173";
process.env.LOG_LEVEL = "silent";
