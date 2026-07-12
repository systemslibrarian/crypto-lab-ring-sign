/// <reference types="vitest/config" />
import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-ring-sign/',
  test: {
    // Unit tests live in src/**; the Playwright a11y suite lives in e2e/ and
    // must NOT be collected by vitest.
    include: ['src/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
    // WebCrypto key generation + real curve arithmetic makes crypto tests
    // slower than the 5s default, especially on shared CI runners.
    testTimeout: 30_000,
    hookTimeout: 30_000
  }
});
