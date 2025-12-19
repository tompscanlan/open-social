#!/bin/bash
# Deploy OpenSocial API

set -e

echo "Ì∫Ä Deploying OpenSocial API..."

# Pull latest changes
echo "Ì≥• Pulling latest code..."
git pull origin main

# Install dependencies
echo "Ì≥¶ Installing dependencies..."
npm install

# Build TypeScript
echo "Ì¥® Building..."
npm run build

# Restart service
echo "‚ôªÔ∏è  Restarting service..."
sudo systemctl restart open-social

# Wait for service to start
sleep 3

# Check health
echo "Ìø• Checking health..."
if curl -f http://localhost:3000/health > /dev/null 2>&1; then
    echo "‚úÖ Deployment successful!"
    sudo systemctl status open-social --no-pager -l
else
    echo "‚ùå Health check failed!"
    echo "Recent logs:"
    sudo journalctl -u open-social -n 50 --no-pager
    exit 1
fi
