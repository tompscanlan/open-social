#!/usr/bin/env bash
#
# reset-db.sh — Drop all open-social tables and let the app recreate them on next start.
#
# Usage:
#   ./scripts/reset-db.sh              # uses DATABASE_URL from .env
#   DATABASE_URL=postgres://... ./scripts/reset-db.sh   # explicit URL
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Load .env if present
if [[ -f "$PROJECT_DIR/.env" ]]; then
  set -a
  source "$PROJECT_DIR/.env"
  set +a
fi

if [[ -z "${DATABASE_URL:-}" ]]; then
  echo "❌ DATABASE_URL is not set. Add it to .env or pass it as an env var."
  exit 1
fi

echo "⚠️  This will DROP all open-social tables and delete all data."
read -r -p "Are you sure? (y/N) " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

echo "🗑  Dropping tables..."
psql "$DATABASE_URL" <<SQL
-- Drop in dependency order
DROP TABLE IF EXISTS apps        CASCADE;
DROP TABLE IF EXISTS communities CASCADE;
DROP TABLE IF EXISTS auth_session CASCADE;
DROP TABLE IF EXISTS auth_state  CASCADE;
SQL

echo "✅ All tables dropped. Restart the server to recreate them."
