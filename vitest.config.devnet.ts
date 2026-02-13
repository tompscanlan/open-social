import { defineConfig } from 'vitest/config';
import path from 'path';

// Configuration for devnet smoke tests that require a local devnet environment
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    setupFiles: ['./src/test/setup.ts'],
    include: ['test/devnet-*.test.ts'],
    testTimeout: 10000,
    hookTimeout: 10000,
    pool: 'forks',
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});
