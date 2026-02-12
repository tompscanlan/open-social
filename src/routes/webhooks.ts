import { Router } from 'express';
import crypto from 'crypto';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { createVerifyApiKey, type AuthenticatedRequest } from '../middleware/auth';
import { createWebhookSchema, updateWebhookSchema } from '../validation/schemas';
import { parsePagination, encodeCursor, decodeCursor } from '../lib/pagination';
import { logger } from '../lib/logger';

export function createWebhookRouter(db: Kysely<Database>): Router {
  const router = Router();
  const verifyApiKey = createVerifyApiKey(db);

  // Create webhook
  router.post('/', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    try {
      const parsed = createWebhookSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const { url, events, communityDid } = parsed.data;
      const secret = crypto.randomBytes(32).toString('hex');

      const result = await db
        .insertInto('webhooks')
        .values({
          app_id: req.app_data!.app_id,
          url,
          events: JSON.stringify(events),
          secret,
          community_did: communityDid || null,
          active: true,
        })
        .returning(['id', 'url', 'events', 'secret', 'community_did', 'active', 'created_at'])
        .executeTakeFirstOrThrow();

      res.status(201).json({
        webhook: {
          id: result.id,
          url: result.url,
          events: JSON.parse(result.events as string),
          secret: result.secret,
          communityDid: result.community_did,
          active: result.active,
          createdAt: result.created_at,
        },
        message: 'Store the secret securely — it is used to verify webhook signatures.',
      });
    } catch (error) {
      logger.error({ error }, 'Create webhook error');
      res.status(500).json({ error: 'Failed to create webhook' });
    }
  });

  // List webhooks for the app
  router.get('/', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    try {
      const { cursor, limit } = parsePagination(req.query as any);
      const offset = cursor ? decodeCursor(cursor) : 0;

      const webhooks = await db
        .selectFrom('webhooks')
        .select(['id', 'url', 'events', 'community_did', 'active', 'created_at'])
        .where('app_id', '=', req.app_data!.app_id)
        .orderBy('created_at', 'desc')
        .offset(offset)
        .limit(limit + 1)
        .execute();

      const hasMore = webhooks.length > limit;
      const page = hasMore ? webhooks.slice(0, limit) : webhooks;

      res.json({
        webhooks: page.map((w) => ({
          id: w.id,
          url: w.url,
          events: typeof w.events === 'string' ? JSON.parse(w.events) : w.events,
          communityDid: w.community_did,
          active: w.active,
          createdAt: w.created_at,
        })),
        cursor: hasMore ? encodeCursor(offset + limit) : undefined,
      });
    } catch (error) {
      logger.error({ error }, 'List webhooks error');
      res.status(500).json({ error: 'Failed to list webhooks' });
    }
  });

  // Update webhook
  router.put('/:webhookId', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    try {
      const parsed = updateWebhookSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }

      const webhook = await db
        .selectFrom('webhooks')
        .selectAll()
        .where('id', '=', parseInt(req.params.webhookId))
        .where('app_id', '=', req.app_data!.app_id)
        .executeTakeFirst();

      if (!webhook) {
        return res.status(404).json({ error: 'Webhook not found' });
      }

      const updates: Record<string, any> = { updated_at: new Date() };
      if (parsed.data.url) updates.url = parsed.data.url;
      if (parsed.data.events) updates.events = JSON.stringify(parsed.data.events);
      if (parsed.data.active !== undefined) updates.active = parsed.data.active;

      await db
        .updateTable('webhooks')
        .set(updates)
        .where('id', '=', parseInt(req.params.webhookId))
        .execute();

      res.json({ success: true });
    } catch (error) {
      logger.error({ error, webhookId: req.params.webhookId }, 'Update webhook error');
      res.status(500).json({ error: 'Failed to update webhook' });
    }
  });

  // Delete webhook
  router.delete('/:webhookId', verifyApiKey, async (req: AuthenticatedRequest, res) => {
    try {
      const result = await db
        .deleteFrom('webhooks')
        .where('id', '=', parseInt(req.params.webhookId))
        .where('app_id', '=', req.app_data!.app_id)
        .executeTakeFirst();

      if (!result.numDeletedRows) {
        return res.status(404).json({ error: 'Webhook not found' });
      }

      res.json({ success: true });
    } catch (error) {
      logger.error({ error, webhookId: req.params.webhookId }, 'Delete webhook error');
      res.status(500).json({ error: 'Failed to delete webhook' });
    }
  });

  return router;
}
