import type { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';

const CSRF_COOKIE = 'csrf-token';
const CSRF_HEADER = 'x-csrf-token';

/**
 * CSRF protection using double-submit cookie pattern.
 * 
 * For state-changing requests (POST/PUT/DELETE) with session cookies,
 * the client must include a matching CSRF token in both a cookie and header.
 * 
 * API Key authenticated requests are exempt (no session = no CSRF risk).
 * Login/OAuth routes are exempt (form-submitted, no way to attach headers).
 */

const CSRF_EXEMPT_PATHS = ['/login', '/oauth/callback'];

export function csrfProtection(req: Request, res: Response, next: NextFunction) {
  // Skip CSRF for API Key authenticated requests
  if (req.headers['x-api-key']) {
    return next();
  }

  // Skip CSRF for login/OAuth routes (form submissions that can't attach headers)
  if (CSRF_EXEMPT_PATHS.some(path => req.path === path)) {
    return next();
  }

  // Skip CSRF for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    // Set CSRF token cookie on GET requests so clients can read it
    if (req.method === 'GET' && !req.cookies?.[CSRF_COOKIE]) {
      const token = crypto.randomBytes(32).toString('hex');
      res.cookie(CSRF_COOKIE, token, {
        httpOnly: false, // Client needs to read this
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
        maxAge: 24 * 60 * 60 * 1000,
      });
    }
    return next();
  }

  // For state-changing requests with a session cookie, verify CSRF token
  if (req.cookies?.sid) {
    const cookieToken = req.cookies?.[CSRF_COOKIE];
    const headerToken = req.headers[CSRF_HEADER] as string;

    if (!cookieToken || !headerToken || cookieToken !== headerToken) {
      return res.status(403).json({ error: 'Invalid CSRF token' });
    }
  }

  next();
}

/**
 * Generate a fresh CSRF token and set it as a cookie.
 * Call this after login to ensure the client has a token.
 */
export function setCsrfToken(res: Response): string {
  const token = crypto.randomBytes(32).toString('hex');
  res.cookie(CSRF_COOKIE, token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 24 * 60 * 60 * 1000,
  });
  return token;
}
