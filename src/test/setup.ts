/**
 * Global test setup file.
 * Runs before all tests to configure the test environment.
 */

import dotenv from 'dotenv';
import { beforeAll, afterAll, afterEach } from 'vitest';

// Load test environment variables
dotenv.config({ path: '.env.test' });

// Set default test environment variables if not provided
if (!process.env.DATABASE_URL) {
  process.env.DATABASE_URL = 'postgresql://opensocial_api:test_password@localhost:5432/opensocial_test';
}

if (!process.env.ENCRYPTION_KEY) {
  // Test encryption key (32 bytes = 64 hex chars)
  process.env.ENCRYPTION_KEY = 'a'.repeat(64);
}

if (!process.env.COOKIE_SECRET) {
  process.env.COOKIE_SECRET = 'test-cookie-secret-for-testing-purposes';
}

if (!process.env.NODE_ENV) {
  process.env.NODE_ENV = 'test';
}

// Setup global test hooks
beforeAll(async () => {
  // Global setup tasks
});

afterAll(async () => {
  // Global cleanup tasks
});

afterEach(() => {
  // Clear any mocks after each test
  vi.clearAllMocks();
});
