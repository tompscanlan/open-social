import { Agent } from '@atproto/api';
import express, { Request, Response } from 'express';
import { getIronSession } from 'iron-session';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { NodeOAuthClient } from '@atproto/oauth-client-node';
import crypto from 'crypto';
import { config } from '../config';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { hashApiKey } from '../lib/crypto';
import { registerAppSchema, updateAppSchema } from '../validation/schemas';

type Session = { did?: string };

const MAX_AGE = config.nodeEnv === 'production' ? 60 : 300;

const sessionOptions = {
  cookieName: 'sid',
  password: config.cookieSecret,
  cookieOptions: {
    secure: config.nodeEnv === 'production',
    sameSite: 'lax' as const,
    httpOnly: true,
    path: '/',
  },
};

async function getSessionAgent(
  req: IncomingMessage,
  res: ServerResponse,
  oauthClient: NodeOAuthClient
) {
  res.setHeader('Vary', 'Cookie');
  const session = await getIronSession<Session>(req, res, sessionOptions);
  if (!session.did) return null;
  res.setHeader('cache-control', `max-age=${MAX_AGE}, private`);
  try {
    const oauthSession = await oauthClient.restore(session.did);
    return oauthSession ? new Agent(oauthSession) : null;
  } catch (err) {
    console.warn('OAuth restore failed:', err);
    await session.destroy();
    return null;
  }
}

export function createAppRouter(oauthClient: NodeOAuthClient, db: Kysely<Database>) {
  const router = express.Router();

  // Register a new app (requires OAuth session — user must be logged in)
  router.post('/register', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated. Log in to register an app.' });
      }

      const parsed = registerAppSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }
      const { name, domain } = parsed.data;

      // Check for duplicate domain
      const existing = await db
        .selectFrom('apps')
        .selectAll()
        .where('domain', '=', domain)
        .where('status', '=', 'active')
        .executeTakeFirst();
      if (existing) {
        return res.status(409).json({ error: 'An active app with this domain already exists' });
      }

      const creatorDid = agent.assertDid;
      const appId = `app_${crypto.randomBytes(8).toString('hex')}`;
      const apiKey = `osc_${crypto.randomBytes(32).toString('hex')}`;

      await db
        .insertInto('apps')
        .values({
          app_id: appId,
          name,
          domain,
          creator_did: creatorDid,
          api_key: hashApiKey(apiKey),
          created_at: new Date(),
          updated_at: new Date(),
          status: 'active',
        })
        .execute();

      return res.json({
        app: {
          appId,
          name,
          domain,
          apiKey,
          createdAt: new Date().toISOString(),
        },
        message: 'Store the api_key securely — treat it like a password.',
      });
    } catch (err) {
      console.error('Error registering app:', err);
      return res.status(500).json({ error: 'Failed to register app' });
    }
  });

  // List the current user's registered apps
  router.get('/', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const apps = await db
        .selectFrom('apps')
        .select(['app_id', 'name', 'domain', 'status', 'created_at', 'updated_at'])
        .where('creator_did', '=', agent.assertDid)
        .orderBy('created_at', 'desc')
        .execute();

      return res.json({ apps });
    } catch (err) {
      console.error('Error listing apps:', err);
      return res.status(500).json({ error: 'Failed to list apps' });
    }
  });

  // Get a single app by ID (must be the creator)
  router.get('/:appId', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const app = await db
        .selectFrom('apps')
        .select(['app_id', 'name', 'domain', 'status', 'created_at', 'updated_at'])
        .where('app_id', '=', req.params.appId)
        .where('creator_did', '=', agent.assertDid)
        .executeTakeFirst();

      if (!app) {
        return res.status(404).json({ error: 'App not found' });
      }

      return res.json({ app });
    } catch (err) {
      console.error('Error getting app:', err);
      return res.status(500).json({ error: 'Failed to get app' });
    }
  });

  // Update an app (name and/or domain)
  router.put('/:appId', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const parsed = updateAppSchema.safeParse(req.body);
      if (!parsed.success) {
        return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
      }
      const { name, domain } = parsed.data;

      const existing = await db
        .selectFrom('apps')
        .selectAll()
        .where('app_id', '=', req.params.appId)
        .where('creator_did', '=', agent.assertDid)
        .executeTakeFirst();
      if (!existing) {
        return res.status(404).json({ error: 'App not found' });
      }

      if (domain && domain !== existing.domain) {
        const conflict = await db
          .selectFrom('apps')
          .selectAll()
          .where('domain', '=', domain)
          .where('status', '=', 'active')
          .where('app_id', '!=', req.params.appId)
          .executeTakeFirst();
        if (conflict) {
          return res.status(409).json({ error: 'An active app with this domain already exists' });
        }
      }

      const updateValues: Record<string, any> = { updated_at: new Date() };
      if (name) updateValues.name = name;
      if (domain) updateValues.domain = domain;

      await db
        .updateTable('apps')
        .set(updateValues)
        .where('app_id', '=', req.params.appId)
        .where('creator_did', '=', agent.assertDid)
        .execute();

      return res.json({ success: true });
    } catch (err) {
      console.error('Error updating app:', err);
      return res.status(500).json({ error: 'Failed to update app' });
    }
  });

  // Deactivate an app
  router.delete('/:appId', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const result = await db
        .updateTable('apps')
        .set({ status: 'inactive', updated_at: new Date() })
        .where('app_id', '=', req.params.appId)
        .where('creator_did', '=', agent.assertDid)
        .where('status', '=', 'active')
        .executeTakeFirst();

      if (!result.numUpdatedRows || result.numUpdatedRows === 0n) {
        return res.status(404).json({ error: 'App not found or already inactive' });
      }

      return res.json({ success: true, message: 'App deactivated' });
    } catch (err) {
      console.error('Error deleting app:', err);
      return res.status(500).json({ error: 'Failed to delete app' });
    }
  });

  // Rotate API key (generates new key, invalidates old one)
  router.post('/:appId/rotate-key', async (req: Request, res: Response) => {
    try {
      const agent = await getSessionAgent(req, res, oauthClient);
      if (!agent) {
        return res.status(401).json({ error: 'Not authenticated' });
      }

      const existing = await db
        .selectFrom('apps')
        .selectAll()
        .where('app_id', '=', req.params.appId)
        .where('creator_did', '=', agent.assertDid)
        .where('status', '=', 'active')
        .executeTakeFirst();
      if (!existing) {
        return res.status(404).json({ error: 'App not found or inactive' });
      }

      const newApiKey = `osc_${crypto.randomBytes(32).toString('hex')}`;

      await db
        .updateTable('apps')
        .set({
          api_key: hashApiKey(newApiKey),
          updated_at: new Date(),
        })
        .where('app_id', '=', req.params.appId)
        .execute();

      return res.json({
        apiKey: newApiKey,
        message: 'Store the new api_key securely. The old key is now invalid.',
      });
    } catch (err) {
      console.error('Error rotating key:', err);
      return res.status(500).json({ error: 'Failed to rotate API key' });
    }
  });

  // Verify API key (for external apps to test credentials)
  router.post('/verify', async (req: Request, res: Response) => {
    try {
      const apiKey = req.headers['x-api-key'] as string;

      if (!apiKey) {
        return res.status(401).json({ error: 'API key required (X-Api-Key header)' });
      }

      const app = await db
        .selectFrom('apps')
        .selectAll()
        .where('api_key', '=', hashApiKey(apiKey))
        .where('status', '=', 'active')
        .executeTakeFirst();
      if (!app) {
        return res.status(401).json({ error: 'Invalid API key' });
      }

      return res.json({
        valid: true,
        app: {
          appId: app.app_id,
          name: app.name,
          domain: app.domain,
        },
      });
    } catch (err) {
      console.error('Error verifying credentials:', err);
      return res.status(500).json({ error: 'Failed to verify credentials' });
    }
  });

  return router;
}
