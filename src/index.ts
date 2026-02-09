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
import { createPermissionsRouter } from './routes/permissions';
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

    // ─── Search: enable pg_trgm and add trigram indexes ─────────────
    try {
      await sql`CREATE EXTENSION IF NOT EXISTS pg_trgm`.execute(db);
    } catch (e) { console.warn('Could not create pg_trgm extension:', e); }

    // Migrate: add cached metadata columns for community search results
    try {
      await sql`ALTER TABLE communities ADD COLUMN IF NOT EXISTS description text`.execute(db);
      await sql`ALTER TABLE communities ADD COLUMN IF NOT EXISTS avatar_url text`.execute(db);
      await sql`ALTER TABLE communities ADD COLUMN IF NOT EXISTS community_type varchar(50)`.execute(db);
      await sql`ALTER TABLE communities ADD COLUMN IF NOT EXISTS member_count integer`.execute(db);
      await sql`ALTER TABLE communities ADD COLUMN IF NOT EXISTS metadata_fetched_at timestamp`.execute(db);
    } catch (e) { /* columns already exist */ }

    // GIN trigram indexes for fuzzy search
    try {
      await sql`CREATE INDEX IF NOT EXISTS idx_communities_handle_trgm ON communities USING gin (handle gin_trgm_ops)`.execute(db);
      await sql`CREATE INDEX IF NOT EXISTS idx_communities_display_name_trgm ON communities USING gin (display_name gin_trgm_ops)`.execute(db);
    } catch (e) { console.warn('Could not create trigram indexes:', e); }

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

    // ─── Permissions & moderation tables ─────────────────────────────

    await db.schema
      .createTable('community_settings')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('community_did', 'varchar(255)', (col) => col.notNull().unique())
      .addColumn('app_visibility_default', 'varchar(50)', (col) => col.notNull().defaultTo('open'))
      .addColumn('blocked_app_ids', 'text', (col) => col.notNull().defaultTo('[]'))
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .addColumn('updated_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    await db.schema
      .createTable('community_app_visibility')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('community_did', 'varchar(255)', (col) => col.notNull())
      .addColumn('app_id', 'varchar(255)', (col) => col.notNull())
      .addColumn('status', 'varchar(50)', (col) => col.notNull().defaultTo('enabled'))
      .addColumn('requested_by', 'varchar(255)')
      .addColumn('reviewed_by', 'varchar(255)')
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .addColumn('updated_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    // Unique constraint: one visibility row per (community, app)
    try {
      await sql`CREATE UNIQUE INDEX IF NOT EXISTS idx_community_app_visibility_unique ON community_app_visibility (community_did, app_id)`.execute(db);
    } catch (e) { /* index already exists */ }

    await db.schema
      .createTable('community_roles')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('community_did', 'varchar(255)', (col) => col.notNull())
      .addColumn('name', 'varchar(100)', (col) => col.notNull())
      .addColumn('display_name', 'varchar(255)', (col) => col.notNull())
      .addColumn('description', 'text')
      .addColumn('visible', 'boolean', (col) => col.notNull().defaultTo(false))
      .addColumn('can_view_audit_log', 'boolean', (col) => col.notNull().defaultTo(false))
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .addColumn('updated_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    // Add can_view_audit_log column if it doesn't exist (migration for existing DBs)
    try {
      await sql`ALTER TABLE community_roles ADD COLUMN IF NOT EXISTS can_view_audit_log boolean NOT NULL DEFAULT false`.execute(db);
    } catch (e) { /* column already exists */ }

    // Unique constraint: role names are unique per community
    try {
      await sql`CREATE UNIQUE INDEX IF NOT EXISTS idx_community_roles_unique ON community_roles (community_did, name)`.execute(db);
    } catch (e) { /* index already exists */ }

    await db.schema
      .createTable('community_member_roles')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('community_did', 'varchar(255)', (col) => col.notNull())
      .addColumn('member_did', 'varchar(255)', (col) => col.notNull())
      .addColumn('role_name', 'varchar(100)', (col) => col.notNull())
      .addColumn('assigned_by', 'varchar(255)', (col) => col.notNull())
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    // Unique constraint: a member can hold a given role only once per community
    try {
      await sql`CREATE UNIQUE INDEX IF NOT EXISTS idx_community_member_roles_unique ON community_member_roles (community_did, member_did, role_name)`.execute(db);
    } catch (e) { /* index already exists */ }

    await db.schema
      .createTable('app_default_permissions')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('app_id', 'varchar(255)', (col) => col.notNull())
      .addColumn('collection', 'varchar(255)', (col) => col.notNull())
      .addColumn('default_can_create', 'varchar(100)', (col) => col.notNull().defaultTo('member'))
      .addColumn('default_can_read', 'varchar(100)', (col) => col.notNull().defaultTo('member'))
      .addColumn('default_can_update', 'varchar(100)', (col) => col.notNull().defaultTo('member'))
      .addColumn('default_can_delete', 'varchar(100)', (col) => col.notNull().defaultTo('admin'))
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    // Unique constraint: one default permission row per (app, collection)
    try {
      await sql`CREATE UNIQUE INDEX IF NOT EXISTS idx_app_default_permissions_unique ON app_default_permissions (app_id, collection)`.execute(db);
    } catch (e) { /* index already exists */ }

    await db.schema
      .createTable('community_app_collection_permissions')
      .ifNotExists()
      .addColumn('id', 'serial', (col) => col.primaryKey())
      .addColumn('community_did', 'varchar(255)', (col) => col.notNull())
      .addColumn('app_id', 'varchar(255)', (col) => col.notNull())
      .addColumn('collection', 'varchar(255)', (col) => col.notNull())
      .addColumn('can_create', 'varchar(100)', (col) => col.notNull().defaultTo('member'))
      .addColumn('can_read', 'varchar(100)', (col) => col.notNull().defaultTo('member'))
      .addColumn('can_update', 'varchar(100)', (col) => col.notNull().defaultTo('member'))
      .addColumn('can_delete', 'varchar(100)', (col) => col.notNull().defaultTo('admin'))
      .addColumn('created_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .addColumn('updated_at', 'timestamp', (col) => col.notNull().defaultTo(sql`now()`))
      .execute();

    // Unique constraint: one permission row per (community, app, collection)
    try {
      await sql`CREATE UNIQUE INDEX IF NOT EXISTS idx_community_app_collection_perms_unique ON community_app_collection_permissions (community_did, app_id, collection)`.execute(db);
    } catch (e) { /* index already exists */ }

    console.log('✅ Permissions tables ready');

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
    app.use('/api/v1/communities', createPermissionsRouter(db));
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
