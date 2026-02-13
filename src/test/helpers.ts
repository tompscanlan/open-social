/**
 * Test helper utilities and factories for creating test data.
 */

import { faker } from '@faker-js/faker';
import type { Kysely } from 'kysely';
import type { Database } from '../db';

/**
 * Create a fake DID for testing
 */
export function createFakeDid(): string {
  return `did:plc:${faker.string.alphanumeric(24)}`;
}

/**
 * Create a fake app for testing
 */
export function createFakeApp(overrides?: Partial<{
  id: string;
  name: string;
  creator_did: string;
  api_key: string;
  status: string;
}>) {
  return {
    id: faker.string.uuid(),
    name: faker.company.name(),
    creator_did: createFakeDid(),
    api_key: faker.string.alphanumeric(32),
    status: 'active',
    ...overrides,
  };
}

/**
 * Create a fake community for testing
 */
export function createFakeCommunity(overrides?: Partial<{
  did: string;
  handle: string;
  display_name: string;
  app_password: string;
  creator_did: string;
}>) {
  return {
    did: createFakeDid(),
    handle: faker.internet.userName().toLowerCase(),
    display_name: faker.company.name(),
    app_password: faker.string.alphanumeric(32),
    creator_did: createFakeDid(),
    ...overrides,
  };
}

/**
 * Create a fake webhook for testing
 */
export function createFakeWebhook(overrides?: Partial<{
  url: string;
  events: string[];
  secret: string | null;
  community_did: string | null;
  active: boolean;
}>) {
  return {
    url: faker.internet.url(),
    events: ['member.joined', 'member.left'],
    secret: faker.string.alphanumeric(32),
    community_did: null,
    active: true,
    ...overrides,
  };
}

/**
 * Create a mock Kysely database for testing
 */
export function createMockDb(): Kysely<Database> {
  return {
    selectFrom: vi.fn().mockReturnThis(),
    select: vi.fn().mockReturnThis(),
    selectAll: vi.fn().mockReturnThis(),
    where: vi.fn().mockReturnThis(),
    execute: vi.fn().mockResolvedValue([]),
    executeTakeFirst: vi.fn().mockResolvedValue(undefined),
    insertInto: vi.fn().mockReturnThis(),
    values: vi.fn().mockReturnThis(),
    updateTable: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
    deleteFrom: vi.fn().mockReturnThis(),
  } as any;
}

/**
 * Create a mock AT Proto agent for testing
 */
export function createMockAgent() {
  return {
    api: {
      com: {
        atproto: {
          repo: {
            listRecords: vi.fn().mockResolvedValue({
              data: { records: [], cursor: undefined },
            }),
            getRecord: vi.fn().mockResolvedValue({
              data: { value: { admins: [] } },
            }),
          },
        },
      },
    },
  };
}

/**
 * Wait for async operations to complete
 */
export function waitForAsync(ms: number = 100): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Create a mock Express request
 */
export function createMockRequest(overrides?: any) {
  return {
    body: {},
    params: {},
    query: {},
    headers: {},
    method: 'GET',
    url: '/',
    ...overrides,
  };
}

/**
 * Create a mock Express response
 */
export function createMockResponse() {
  const res: any = {
    status: vi.fn().mockReturnThis(),
    json: vi.fn().mockReturnThis(),
    send: vi.fn().mockReturnThis(),
    set: vi.fn().mockReturnThis(),
    locals: {},
  };
  return res;
}
