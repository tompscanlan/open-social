import { Generated, Kysely, PostgresDialect, sql } from 'kysely';
import { Pool } from 'pg';
import type { AuthState, AuthSession } from './models/auth';

export interface Community {
  did: string;
  handle: string;
  display_name: string;
  pds_host: string;
  app_password: string;
  created_at: Generated<Date>;
}

export interface App {
  id: Generated<number>;
  app_id: string;
  name: string;
  domain: string;
  creator_did: string;
  api_key: string;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
  status: string;
}

export interface RateLimit {
  id: Generated<number>;
  app_id: string;
  max_requests: number;
  window_ms: number;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface Webhook {
  id: Generated<number>;
  app_id: string;
  url: string;
  events: string; // JSON array of event names
  secret: string | null;
  community_did: string | null;
  active: boolean;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface AuditLogEntry {
  id: Generated<number>;
  community_did: string;
  admin_did: string;
  action: string;
  target_did: string | null;
  reason: string | null;
  metadata: string | null; // JSON
  created_at: Generated<Date>;
}

export interface PendingMember {
  id: Generated<number>;
  community_did: string;
  user_did: string;
  status: string; // 'pending' | 'approved' | 'rejected'
  reason: string | null;
  reviewed_by: string | null;
  created_at: Generated<Date>;
  updated_at: Generated<Date>;
}

export interface Database {
  auth_state: AuthState;
  auth_session: AuthSession;
  communities: Community;
  apps: App;
  rate_limits: RateLimit;
  webhooks: Webhook;
  audit_log: AuditLogEntry;
  pending_members: PendingMember;
}

export function createDb(connectionString: string): Kysely<Database> {
  return new Kysely<Database>({
    dialect: new PostgresDialect({
      pool: new Pool({
        connectionString,
      }),
    }),
  });
}
