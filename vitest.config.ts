import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: ["apps/api", "packages/shared", "packages/db"],
    // Integration tests truncate shared tables; run test files one at a time.
    fileParallelism: false,
  },
});
