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
# Wait until accounts.json exists and has at least one account
while ! jq -e 'length > 0' "$DEVNET_DIR/data/accounts.json" >/dev/null 2>&1; do
  if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    echo "ERROR: Timed out waiting for devnet init to complete."
    echo "Check: docker logs devnet-init"
    exit 1
  fi
  sleep 2
  ELAPSED=$((ELAPSED + 2))
done
echo "==> Devnet accounts seeded."
echo ""
echo "Devnet is ready. Run the app or tests with:"
echo ""
echo "  npm run dev:devnet     # start the app"
echo "  npm run test:devnet    # run smoke tests"
