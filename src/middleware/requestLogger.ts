import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { logger } from '../lib/logger';

declare global {
  namespace Express {
    interface Request {
      correlationId?: string;
      startTime?: number;
    }
  }
}

/**
 * Request logging middleware with correlation IDs and performance metrics.
 * 
 * Features:
 * - Generates unique correlation ID for each request
 * - Logs request start with method, path, and correlation ID
 * - Logs request completion with status code, duration, and performance warnings
 * - Attaches correlation ID to request object for use in route handlers
 */
export function requestLogger(req: Request, res: Response, next: NextFunction) {
  // Generate unique correlation ID for request tracing
  const correlationId = uuidv4();
  req.correlationId = correlationId;
  req.startTime = Date.now();

  // Log incoming request
  logger.info({
    correlationId,
    method: req.method,
    path: req.path,
    query: req.query,
    userAgent: req.get('user-agent'),
  }, 'Incoming request');

  // Log response on finish
  res.on('finish', () => {
    const duration = Date.now() - (req.startTime || 0);
    const logData = {
      correlationId,
      method: req.method,
      path: req.path,
      statusCode: res.statusCode,
      duration,
    };

    // Log slow operations as warnings
    if (duration > 1000) {
      logger.warn(logData, `Slow request (${duration}ms)`);
    } else if (res.statusCode >= 500) {
      logger.error(logData, 'Request failed with server error');
    } else if (res.statusCode >= 400) {
      logger.warn(logData, 'Request failed with client error');
    } else {
      logger.info(logData, 'Request completed');
    }
  });

  next();
}
