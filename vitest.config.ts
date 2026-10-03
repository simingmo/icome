import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    exclude: ["tests/performance/**", "node_modules/**", "dist/**"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: [
        "src/contracts.ts",
        "src/index.ts",
        "src/cli.ts",
        "src/modules/project-audit-module.ts",
      ],
      reporter: ["text", "json-summary", "html"],
      thresholds: {
        statements: 75,
        branches: 65,
        functions: 75,
        lines: 75,
      },
    },
  },
});
