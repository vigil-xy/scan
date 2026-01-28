#!/bin/sh
# Vigil v0.2.0 - Clean Install & Test Blueprint
# Run this from any directory: curl -sSL https://raw.githubusercontent.com/vigil-xy/scan/main/scripts/install-and-test.sh | sh

# --- CLEAN EVERYTHING ---
echo "🧹 Cleaning old installations..."
rm -rf ~/.local/bin/vigil-scan ~/.local/bin/vigil ~/.vigil* /tmp/vigil* /tmp/scan* ~/.vigil-keys 2>/dev/null

# --- FRESH INSTALL ---
echo "📦 Installing Vigil v0.2.0..."
curl -sSL https://raw.githubusercontent.com/vigil-xy/scan/main/scripts/vigil.sh | sh

# --- VERIFY INSTALL ---
echo "✅ Verifying installation..."
if command -v vigil-scan >/dev/null 2>&1; then
  echo "✅ vigil-scan installed successfully"
  vigil-scan --version
else
  echo "❌ Installation failed - binary not in PATH"
  exit 1
fi

# --- TEST SCAN ---
echo ""
echo "🔍 Running quick scan..."
vigil-scan --dry-run

# --- TEST DASHBOARD (Background) ---
echo ""
echo "🚀 Launching dashboard (background)..."
vigil-scan dashboard &
DASHBOARD_PID=$!

# Wait for server to start
sleep 3

# Test API endpoint
echo "📊 Testing dashboard API..."
if curl -s http://localhost:8080/api/scan | grep -q "ports"; then
  echo "✅ Dashboard API working"
else
  echo "⚠️ Dashboard API not responding"
fi

# Kill dashboard
kill $DASHBOARD_PID 2>/dev/null
wait $DASHBOARD_PID 2>/dev/null
echo "✅ Dashboard stopped"

# --- FINAL STATUS ---
echo ""
echo "🎉 INSTALLATION COMPLETE!"
echo ""
echo "Your Vigil Security Scanner v0.2.0 is ready:"
echo "  • Binary: ~/.local/bin/vigil-scan"
echo "  • Command: vigil-scan --help"
echo "  • Dashboard: vigil-scan dashboard"
echo "  • Discord: https://discord.gg/7Mzcc2EY"
