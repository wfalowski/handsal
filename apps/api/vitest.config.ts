import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    environment: "node",
    include: ["src/**/*.test.ts"],
    setupFiles: ["./src/test/setup.ts"],
    mockReset: true,
    // Integration tests truncate shared tables; run test files one at a time.
    fileParallelism: false,
  },
});
