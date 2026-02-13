import pino from 'pino';
import { config } from '../config';

/**
 * Centralized Pino logger instance.
 * 
 * Configuration:
 * - Development: Human-readable logs with colors via pino-pretty
 * - Production: Structured JSON logs for log aggregation
 * - Log level: Configurable via LOG_LEVEL env var (default: 'info')
 */
export const logger = pino({
  level: config.logLevel,
  transport: config.nodeEnv === 'development' 
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'HH:MM:ss Z',
          ignore: 'pid,hostname',
        },
      }
    : undefined,
});

/**
 * Create a child logger with additional context.
 * Useful for adding service/module-specific metadata to all logs.
 * 
 * @param context - Additional context to include in all logs
 * @returns A new logger instance with the provided context
 */
export function createLogger(context: Record<string, any>) {
  return logger.child(context);
}
