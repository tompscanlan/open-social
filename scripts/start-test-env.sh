#!/bin/bash
# Start the devnet environment for open-social development.
#
# Raises atproto-devnet (PDS, PLC, Jetstream, TAP) plus shared
# postgres and maildev via docker-compose.devnet.yml.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEVNET_DIR="$(cd "$PROJECT_DIR/../atproto-devnet" && pwd)"

echo "==> Starting devnet environment..."
export OPENSOCIAL_DIR="$PROJECT_DIR"
docker compose \
  --env-file "$DEVNET_DIR/.env" \
  -f "$DEVNET_DIR/docker-compose.yml" \
  -f "$PROJECT_DIR/docker-compose.devnet.yml" \
  up -d --wait

echo "==> Waiting for init container to seed accounts..."
TIMEOUT=60
ELAPSED=0
while [ ! -f "$DEVNET_DIR/data/accounts.json" ] || [ "$(cat "$DEVNET_DIR/data/accounts.json" 2>/dev/null)" = "{}" ]; do
  if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    echo "ERROR: Timed out waiting for devnet init to complete."
    echo "Check: docker logs devnet-init"
    exit 1
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done
echo "==> Devnet accounts seeded."

# Read port config
DEVNET_POSTGRES_PORT="${DEVNET_POSTGRES_PORT:-5433}"
DEVNET_PDS_PORT="${DEVNET_PDS_PORT:-4000}"
DEVNET_PLC_PORT="${DEVNET_PLC_PORT:-4001}"
if [ -f "$DEVNET_DIR/.env" ]; then
  eval "$(grep -E '^DEVNET_(POSTGRES|PDS|PLC)_PORT=' "$DEVNET_DIR/.env")"
fi

echo ""
echo "Devnet is ready. Start the app with:"
echo ""
echo "  DATABASE_URL=postgresql://postgres:postgres@localhost:${DEVNET_POSTGRES_PORT}/opensocial \\"
echo "  PDS_URL=http://localhost:${DEVNET_PDS_PORT} \\"
echo "  PLC_URL=http://localhost:${DEVNET_PLC_PORT} \\"
echo "  ENCRYPTION_KEY=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \\"
echo "  COOKIE_SECRET=dev-cookie-secret \\"
echo "  npx tsx src/index.ts"
