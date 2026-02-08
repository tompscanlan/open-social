import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import type { Request, Response } from 'express';
import type { Kysely } from 'kysely';
import type { Database } from '../db';
import type { AuthenticatedRequest } from './auth';

// Default rate limit: 100 requests per minute per app
const DEFAULT_WINDOW_MS = 60 * 1000;
const DEFAULT_MAX_REQUESTS = 100;

export function createRateLimiter(db: Kysely<Database>) {
  return rateLimit({
    windowMs: DEFAULT_WINDOW_MS,
    max: async (req: Request) => {
      const authReq = req as AuthenticatedRequest;
      if (authReq.app_data) {
        try {
          const appLimit = await db
            .selectFrom('rate_limits')
            .select('max_requests')
            .where('app_id', '=', authReq.app_data.app_id)
            .executeTakeFirst();

          if (appLimit) {
            return appLimit.max_requests;
          }
        } catch {
          // Table may not exist yet, use default
        }
      }
      return DEFAULT_MAX_REQUESTS;
    },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req: Request) => {
      const authReq = req as AuthenticatedRequest;
      if (authReq.app_data?.app_id) {
        return authReq.app_data.app_id;
      }
      return ipKeyGenerator(req.ip ?? 'unknown');
    },
    handler: (req: Request, res: Response) => {
      res.status(429).json({
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.ceil(DEFAULT_WINDOW_MS / 1000),
      });
    },
  });
}

// Stricter rate limit for auth endpoints
export const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // 20 attempts per 15 minutes
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    res.status(429).json({
      error: 'Too many authentication attempts',
      message: 'Please try again later.',
      retryAfter: 900,
    });
  },
});
