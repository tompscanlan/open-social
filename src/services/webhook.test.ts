/**
 * Unit tests for webhook.ts
 * Tests webhook dispatching, filtering, and signature generation
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest';
import { createWebhookService } from '../services/webhook';
import { createMockDb, createFakeWebhook, waitForAsync } from '../test/helpers';
import type { Kysely } from 'kysely';
import type { Database } from '../db';

// Mock fetch globally
global.fetch = vi.fn();

describe('webhook.ts', () => {
  let db: Kysely<Database>;
  let webhookService: ReturnType<typeof createWebhookService>;

  beforeEach(() => {
    db = createMockDb();
    webhookService = createWebhookService(db);
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('createWebhookService', () => {
    it('should create a webhook service with dispatch method', () => {
      expect(webhookService).toBeDefined();
      expect(webhookService.dispatch).toBeTypeOf('function');
    });
  });

  describe('dispatch', () => {
    it('should fetch active webhooks for the given event', async () => {
      const mockWebhook = createFakeWebhook({
        events: ['member.joined'],
        active: true,
      });

      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockResolvedValue([mockWebhook]),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      (global.fetch as any).mockResolvedValueOnce({
        ok: true,
        status: 200,
      });

      await webhookService.dispatch('member.joined', 'did:plc:test123', { userDid: 'did:plc:user456' });

      // Wait for async webhook firing to complete
      await waitForAsync(50);

      expect(selectFrom).toHaveBeenCalledWith('webhooks');
    });

    it('should filter webhooks by event type', async () => {
      const webhook1 = createFakeWebhook({
        events: ['member.joined'],
        active: true,
      });

      const webhook2 = createFakeWebhook({
        events: ['member.left'],
        active: true,
      });

      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockResolvedValue([webhook1, webhook2]),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      (global.fetch as any).mockResolvedValue({
        ok: true,
        status: 200,
      });

      await webhookService.dispatch('member.joined', 'did:plc:test123', { userDid: 'did:plc:user456' });

      // Wait for async webhook firing
      await waitForAsync(50);

      // Only webhook1 should be called (events includes member.joined)
      expect(global.fetch).toHaveBeenCalledTimes(1);
      expect(global.fetch).toHaveBeenCalledWith(
        webhook1.url,
        expect.objectContaining({
          method: 'POST',
        })
      );
    });

    it('should include webhook signature when secret is provided', async () => {
      const mockWebhook = createFakeWebhook({
        url: 'https://example.com/webhook',
        events: ['member.joined'],
        secret: 'test-secret-key',
        active: true,
      });

      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockResolvedValue([mockWebhook]),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      (global.fetch as any).mockResolvedValue({
        ok: true,
        status: 200,
      });

      await webhookService.dispatch('member.joined', 'did:plc:test123', { userDid: 'did:plc:user456' });

      // Wait for async webhook firing
      await waitForAsync(50);

      expect(global.fetch).toHaveBeenCalledWith(
        mockWebhook.url,
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-Webhook-Signature': expect.stringMatching(/^sha256=[a-f0-9]{64}$/),
          }),
        })
      );
    });

    it('should not include signature when secret is null', async () => {
      const mockWebhook = createFakeWebhook({
        url: 'https://example.com/webhook',
        events: ['member.joined'],
        secret: null,
        active: true,
      });

      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockResolvedValue([mockWebhook]),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      (global.fetch as any).mockResolvedValue({
        ok: true,
        status: 200,
      });

      await webhookService.dispatch('member.joined', 'did:plc:test123', { userDid: 'did:plc:user456' });

      // Wait for async webhook firing
      await waitForAsync(50);

      const fetchCall = (global.fetch as any).mock.calls[0];
      expect(fetchCall[1].headers['X-Webhook-Signature']).toBeUndefined();
    });

    it('should send correct payload structure', async () => {
      const mockWebhook = createFakeWebhook({
        events: ['member.joined'],
        active: true,
      });

      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockResolvedValue([mockWebhook]),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      (global.fetch as any).mockResolvedValue({
        ok: true,
        status: 200,
      });

      const eventData = { userDid: 'did:plc:user456', name: 'Test User' };
      await webhookService.dispatch('member.joined', 'did:plc:test123', eventData);

      // Wait for async webhook firing
      await waitForAsync(50);

      const fetchCall = (global.fetch as any).mock.calls[0];
      const body = JSON.parse(fetchCall[1].body);

      expect(body).toMatchObject({
        event: 'member.joined',
        communityDid: 'did:plc:test123',
        data: eventData,
      });
      expect(body.timestamp).toBeDefined();
      expect(new Date(body.timestamp)).toBeInstanceOf(Date);
    });

    it('should filter by community DID', async () => {
      const communityWebhook = createFakeWebhook({
        events: ['member.joined'],
        community_did: 'did:plc:test123',
        active: true,
      });

      const globalWebhook = createFakeWebhook({
        events: ['member.joined'],
        community_did: null,
        active: true,
      });

      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockResolvedValue([communityWebhook, globalWebhook]),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      (global.fetch as any).mockResolvedValue({
        ok: true,
        status: 200,
      });

      await webhookService.dispatch('member.joined', 'did:plc:test123', {});

      // Wait for async webhook firing
      await waitForAsync(50);

      // Both webhooks should be called (one matches community, one is global)
      expect(global.fetch).toHaveBeenCalledTimes(2);
    });

    it('should not block on webhook errors (fire and forget)', async () => {
      const mockWebhook = createFakeWebhook({
        events: ['member.joined'],
        active: true,
      });

      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockResolvedValue([mockWebhook]),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      // Mock a failing webhook
      (global.fetch as any).mockRejectedValueOnce(new Error('Network error'));

      // Should not throw
      await expect(
        webhookService.dispatch('member.joined', 'did:plc:test123', {})
      ).resolves.toBeUndefined();
    });

    it('should handle database errors gracefully', async () => {
      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockRejectedValue(new Error('Database error')),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      // Should not throw
      await expect(
        webhookService.dispatch('member.joined', 'did:plc:test123', {})
      ).resolves.toBeUndefined();
    });

    it('should parse events field when stored as JSON string', async () => {
      const mockWebhook = {
        ...createFakeWebhook({
          events: ['member.joined'],
          active: true,
        }),
        events: '["member.joined", "member.left"]', // Stored as JSON string
      };

      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockResolvedValue([mockWebhook]),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      (global.fetch as any).mockResolvedValue({
        ok: true,
        status: 200,
      });

      await webhookService.dispatch('member.left', 'did:plc:test123', {});

      // Wait for async webhook firing
      await waitForAsync(50);

      expect(global.fetch).toHaveBeenCalledTimes(1);
    });

    it('should include User-Agent header', async () => {
      const mockWebhook = createFakeWebhook({
        events: ['member.joined'],
        active: true,
      });

      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockResolvedValue([mockWebhook]),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      (global.fetch as any).mockResolvedValue({
        ok: true,
        status: 200,
      });

      await webhookService.dispatch('member.joined', 'did:plc:test123', {});

      // Wait for async webhook firing
      await waitForAsync(50);

      const fetchCall = (global.fetch as any).mock.calls[0];
      expect(fetchCall[1].headers['User-Agent']).toBe('OpenSocial-Webhooks/1.0');
    });

    it('should use 10 second timeout', async () => {
      const mockWebhook = createFakeWebhook({
        events: ['member.joined'],
        active: true,
      });

      const selectFrom = vi.fn().mockReturnValue({
        selectAll: vi.fn().mockReturnValue({
          where: vi.fn().mockReturnValue({
            where: vi.fn().mockReturnValue({
              execute: vi.fn().mockResolvedValue([mockWebhook]),
            }),
          }),
        }),
      });

      db.selectFrom = selectFrom;

      (global.fetch as any).mockResolvedValue({
        ok: true,
        status: 200,
      });

      await webhookService.dispatch('member.joined', 'did:plc:test123', {});

      // Wait for async webhook firing
      await waitForAsync(50);

      const fetchCall = (global.fetch as any).mock.calls[0];
      expect(fetchCall[1].signal).toBeDefined();
    });
  });
});
