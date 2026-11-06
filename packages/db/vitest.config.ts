import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.ts"],
    testTimeout: 20000,
    env: {
      DATABASE_URL:
        process.env.DATABASE_URL ?? "postgresql://handsal:handsal_dev@localhost:5434/handsal_test",
    },
  },
});
