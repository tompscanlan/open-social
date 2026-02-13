import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { logger } from '../lib/logger';

export type WebhookEvent =
  | 'member.joined'
  | 'member.left'
  | 'member.approved'
  | 'member.rejected'
  | 'member.removed'
  | 'record.created'
  | 'record.updated'
  | 'record.deleted';

interface WebhookPayload {
  event: WebhookEvent;
  communityDid: string;
  data: Record<string, any>;
  timestamp: string;
}

export function createWebhookService(db: Kysely<Database>) {
  async function dispatch(event: WebhookEvent, communityDid: string, data: Record<string, any>) {
    try {
      const webhooks = await db
        .selectFrom('webhooks')
        .selectAll()
        .where('active', '=', true)
        .where((eb) =>
          eb.or([
            eb('community_did', 'is', null),
            eb('community_did', '=', communityDid),
          ])
        )
        .execute();

      const matchingWebhooks = webhooks.filter((w) => {
        const events = typeof w.events === 'string' ? JSON.parse(w.events) : w.events;
        return events.includes(event);
      });

      const payload: WebhookPayload = {
        event,
        communityDid,
        data,
        timestamp: new Date().toISOString(),
      };

      // Fire and forget \u2014 don't block the response
      for (const webhook of matchingWebhooks) {
        fireWebhook(webhook.url, payload, webhook.secret).catch((err) => {
          logger.error({ 
            webhookUrl: webhook.url, 
            event, 
            error: err.message 
          }, 'Webhook delivery failed');
        });
      }
    } catch (err) {
      logger.error({ error: err, event, communityDid }, 'Webhook dispatch error');
    }
  }

  return { dispatch };
}

async function fireWebhook(url: string, payload: WebhookPayload, secret?: string | null) {
  const body = JSON.stringify(payload);
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'OpenSocial-Webhooks/1.0',
  };

  if (secret) {
    const crypto = await import('crypto');
    const signature = crypto.createHmac('sha256', secret).update(body).digest('hex');
    headers['X-Webhook-Signature'] = `sha256=${signature}`;
  }

  const response = await fetch(url, {
    method: 'POST',
    headers,
    body,
    signal: AbortSignal.timeout(10000),
  });

  if (!response.ok) {
    throw new Error(`Webhook returned ${response.status}`);
  }
}
