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

export interface Database {
  auth_state: AuthState;
  auth_session: AuthSession;
  communities: Community;
  apps: App;
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
