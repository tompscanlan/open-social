#!/bin/bash
# Initial setup for OpenSocial API on VM

set -e

echo "Ì∫Ä Setting up OpenSocial API..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "‚ùå .env file not found!"
    echo "Please create .env from .env.example and fill in values."
    exit 1
fi

# Install dependencies
echo "Ì≥¶ Installing dependencies..."
npm install

# Build TypeScript
echo "Ì¥® Building TypeScript..."
npm run build

# Create log directory
echo "Ì≥Å Creating log directory..."
sudo mkdir -p /var/log/open-social
sudo chown azureuser:azureuser /var/log/open-social

# Set up systemd service
echo "‚öôÔ∏è  Setting up systemd service..."
sudo cp systemd/open-social.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable open-social
sudo systemctl start open-social

# Wait for service to start
sleep 3

# Check status
echo "Ìø• Checking service status..."
if curl -f http://localhost:3000/health > /dev/null 2>&1; then
    echo "‚úÖ Setup complete!"
    echo ""
    echo "Service status:"
    sudo systemctl status open-social --no-pager
    echo ""
    echo "Useful commands:"
    echo "  View logs:    sudo journalctl -u open-social -f"
    echo "  Check status: sudo systemctl status open-social"
    echo "  Restart:      sudo systemctl restart open-social"
    echo "  Deploy:       ./scripts/deploy.sh"
else
    echo "‚ùå Setup failed - service not responding"
    sudo journalctl -u open-social -n 50 --no-pager
    exit 1
fi
