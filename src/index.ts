import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import { sql } from 'kysely';
import { config } from './config';
import { createDb } from './db';
import { createOAuthClient } from './auth/client';
import { createAuthRouter } from './routes/auth';
import { createAppRouter } from './routes/apps';
import { createCommunityRouter } from './routes/communities';
import { createMemberRouter } from './routes/members';
import { createRecordsRouter } from './routes/records';
import { createWebhookRouter } from './routes/webhooks';
import { createRateLimiter } from './middleware/rateLimit';
import { csrfProtection } from './middleware/csrf';

dotenv.config();

const app = express();
const PORT = config.port;

// Middleware
app.use(cors({
  origin: config.nodeEnv === 'production' 
    ? [config.serviceUrl || ''] 
    : ['http://127.0.0.1:5174', 'http://localhost:5174'],
  credentials: true,
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// Start server
async function start() {
  try {
    // Initialize database
    const db = createDb(config.databaseUrl);
    console.log('✅ Database connected');

    // Create OAuth tables if they don't exist
    await db.schema
      .createTable('auth_state')
      .ifNotExists()
      .addColumn('key', 'varchar(255)', (col) => col.primaryKey())
      .addColumn('state', 'text', (col) => col.notNull())
      .execute();

    await db.schema
      .createTable('auth_session')
      .ifNotExists()
      .addColumn('key', 'varchar(255)', (col) => col.primaryKey())
      .addColumn('session', 'text', (col) => col.notNull())
      .execute();

    // Create communities table if it doesn't exist
    await db.schema
      .createTable('communities')
      .ifNotExists()
      .addColumn('did', 'varchar(255)', (col) => col.primaryKey())
      .addColumn('handle', 'varchar(255)', (col) => col.notNull().unique())
      .addColumn('display_name', 'varchar(255)', (col) => col.notNull().defaultTo(''))
      .addColumn('pds_host', 'varchar(255)', (col) => col.notNull())
      .addColumn('app_password', 'text', (col) => col.notNull())
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    // Migrate: add display_name column if it doesn't exist yet
    try {
      await sql`ALTER TABLE communities ADD COLUMN IF NOT EXISTS display_name varchar(255) NOT NULL DEFAULT ''`.execute(db);
    } catch (e) { /* column already exists */ }

    // Migrate: drop legacy api_secret_hash column if it still exists
    try {
      await sql`ALTER TABLE apps DROP COLUMN IF EXISTS api_secret_hash`.execute(db);
    } catch (e) { /* column already gone */ }

    // Create apps table if it doesn't exist
    await db.schema
      .createTable('apps')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('app_id', 'varchar(255)', (col) => col.notNull().unique())
      .addColumn('name', 'varchar(255)', (col) => col.notNull())
      .addColumn('domain', 'varchar(255)', (col) => col.notNull())
      .addColumn('creator_did', 'varchar(255)', (col) => col.notNull())
      .addColumn('api_key', 'varchar(255)', (col) => col.notNull().unique())
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .addColumn('updated_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .addColumn('status', 'varchar(50)', (col) => col.notNull().defaultTo('active'))
      .execute();

    console.log('✅ Database tables ready');

    // Create new tables for v2 features
    await db.schema
      .createTable('rate_limits')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('app_id', 'varchar(255)', (col) => col.notNull().unique())
      .addColumn('max_requests', 'integer', (col) => col.notNull().defaultTo(100))
      .addColumn('window_ms', 'integer', (col) => col.notNull().defaultTo(60000))
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .addColumn('updated_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    await db.schema
      .createTable('webhooks')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('app_id', 'varchar(255)', (col) => col.notNull())
      .addColumn('url', 'text', (col) => col.notNull())
      .addColumn('events', 'text', (col) => col.notNull()) // JSON array
      .addColumn('secret', 'varchar(255)')
      .addColumn('community_did', 'varchar(255)')
      .addColumn('active', 'boolean', (col) => col.notNull().defaultTo(true))
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .addColumn('updated_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    await db.schema
      .createTable('audit_log')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('community_did', 'varchar(255)', (col) => col.notNull())
      .addColumn('admin_did', 'varchar(255)', (col) => col.notNull())
      .addColumn('action', 'varchar(100)', (col) => col.notNull())
      .addColumn('target_did', 'varchar(255)')
      .addColumn('reason', 'text')
      .addColumn('metadata', 'text') // JSON
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    await db.schema
      .createTable('pending_members')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('community_did', 'varchar(255)', (col) => col.notNull())
      .addColumn('user_did', 'varchar(255)', (col) => col.notNull())
      .addColumn('status', 'varchar(50)', (col) => col.notNull().defaultTo('pending'))
      .addColumn('reason', 'text')
      .addColumn('reviewed_by', 'varchar(255)')
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .addColumn('updated_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    console.log('✅ V2 tables ready');

    // Initialize OAuth client
    const oauthClient = await createOAuthClient(db);
    console.log('✅ OAuth client initialized');

    // Apply global middleware
    const rateLimiter = createRateLimiter(db);
    app.use('/api/', rateLimiter);
    app.use(csrfProtection);

    // Auth routes (OAuth)
    app.use(createAuthRouter(oauthClient, db));

    // API routes
    app.get('/health', (req, res) => {
      res.json({ 
        status: 'ok',
        timestamp: new Date().toISOString(),
        service: 'opensocial-api'
      });
    });

    app.use('/api/v1/apps', createAppRouter(oauthClient, db));
    app.use('/api/v1/communities', createCommunityRouter(db));
    app.use('/api/v1/communities', createMemberRouter(db));
    app.use('/api/v1/communities', createRecordsRouter(db));
    app.use('/api/v1/webhooks', createWebhookRouter(db));

    // Error handling
    app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
      console.error('Unhandled error:', err);
      res.status(500).json({ error: 'Internal server error' });
    });
    
    app.listen(PORT, () => {
      console.log(`✅ OpenSocial API running on port ${PORT}`);
      console.log(`   Health check: http://localhost:${PORT}/health`);
      console.log(`   Mode: ${config.nodeEnv}`);
      if (config.nodeEnv === 'development') {
        console.log(`   OAuth callback: http://127.0.0.1:${PORT}/oauth/callback`);
      }
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

start();
