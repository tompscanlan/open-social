#!/bin/bash
# Stop the devnet environment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DEVNET_DIR="$(cd "$PROJECT_DIR/../atproto-devnet" && pwd)"

echo "==> Stopping devnet environment..."
export OPENSOCIAL_DIR="$PROJECT_DIR"
docker compose \
  --env-file "$DEVNET_DIR/.env" \
  -f "$DEVNET_DIR/docker-compose.yml" \
  -f "$PROJECT_DIR/docker-compose.devnet.yml" \
  down -v

# Clean up host-side state so next start seeds fresh accounts
rm -f "$DEVNET_DIR/data/accounts.json" "$DEVNET_DIR/data/accounts.env"
echo "==> Done."
