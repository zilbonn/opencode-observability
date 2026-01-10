#!/bin/bash
#
# Setup script for OpenCode observability integration
# This script sets up the observability plugin for OpenCode
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== OpenCode Observability Setup ==="
echo ""

# Check if OpenCode is installed
if ! command -v opencode &> /dev/null; then
    echo "OpenCode is not installed. Installing..."
    curl -fsSL https://opencode.ai/install | bash
    source ~/.bashrc 2>/dev/null || source ~/.zshrc 2>/dev/null || true
fi

# Create global plugin directory
echo "[1/4] Creating OpenCode plugin directory..."
mkdir -p ~/.config/opencode/plugin

# Copy the observability plugin
echo "[2/4] Installing observability plugin..."
cp "$PROJECT_DIR/.opencode/plugin/observability.js" ~/.config/opencode/plugin/

# Create/update global opencode config if it doesn't exist
if [ ! -f ~/.config/opencode/opencode.json ]; then
    echo "[3/4] Creating global OpenCode config..."
    cat > ~/.config/opencode/opencode.json << 'EOF'
{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-opus-4-5",
  "permission": {
    "*": "allow"
  },
  "autoupdate": false
}
EOF
else
    echo "[3/4] Global OpenCode config already exists (skipping)"
fi

# Add environment variables to env.sh if using Wardenn
echo "[4/4] Setting up environment variables..."
if [ -f /opt/env.sh ]; then
    if ! grep -q "OBSERVABILITY_SERVER_URL" /opt/env.sh; then
        echo "" >> /opt/env.sh
        echo "# OpenCode Observability" >> /opt/env.sh
        echo 'export OBSERVABILITY_SERVER_URL="http://localhost:4000/events"' >> /opt/env.sh
        echo 'export OBSERVABILITY_SOURCE_APP="wardenn"' >> /opt/env.sh
        echo 'export OPENCODE_CONFIG="/opt/opencode.jsonc"' >> /opt/env.sh
        echo "Added observability variables to /opt/env.sh"
    else
        echo "Observability variables already in /opt/env.sh (skipping)"
    fi
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Next steps:"
echo "1. Start the observability server:"
echo "   cd $PROJECT_DIR && ./scripts/start-system.sh"
echo ""
echo "2. Open the dashboard at: http://localhost:5173"
echo ""
echo "3. Test with OpenCode:"
echo "   source /opt/env.sh && opencode run 'Hello, test observability'"
echo ""
