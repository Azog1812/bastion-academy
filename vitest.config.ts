import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    environment: 'node',
    testTimeout: 15_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      // Entry points (process wiring, signals) are exercised end to end, not by unit tests.
      exclude: ['src/server.ts', 'src/cli.ts', 'src/labs/runner/main.ts', 'src/labs/gateway/main.ts', 'src/security/common-passwords.ts'],
      reporter: ['text', 'lcov', 'json-summary'],
      thresholds: { lines: 90, functions: 90, branches: 80, statements: 90 },
    },
  },
});
