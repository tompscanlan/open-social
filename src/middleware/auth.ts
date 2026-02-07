import { Request, Response, NextFunction } from 'express';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import { hashApiKey } from '../lib/crypto';

export interface AuthenticatedRequest extends Request {
  app_data?: {
    app_id: string;
    name: string;
    domain: string;
    creator_did: string;
    api_key: string;
    status: string;
    created_at: Date;
    updated_at: Date;
  };
}

export function createVerifyApiKey(db: Kysely<Database>) {
  return async function verifyApiKey(
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ) {
    const apiKey = req.headers['x-api-key'] as string;

    if (!apiKey) {
      return res.status(401).json({ error: 'API key required' });
    }

    try {
      // Hash the incoming key and look up the hash in the DB
      const hashedKey = hashApiKey(apiKey);

      const app = await db
        .selectFrom('apps')
        .selectAll()
        .where('api_key', '=', hashedKey)
        .where('status', '=', 'active')
        .executeTakeFirst();

      if (!app) {
        return res.status(401).json({ error: 'Invalid API key' });
      }

      req.app_data = app;
      next();
    } catch (error) {
      console.error('Auth error:', error);
      res.status(500).json({ error: 'Authentication failed' });
    }
  };
}
