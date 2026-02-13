import { Pool } from 'pg';
import { logger } from '../lib/logger';

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

// Test connection
pool.on('connect', () => {
  logger.info('Connected to PostgreSQL');
});

pool.on('error', (err) => {
  logger.error({ error: err }, 'PostgreSQL error');
});

export default pool;
