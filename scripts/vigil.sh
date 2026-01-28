#!/bin/bash
# vigil.sh - Install and run vigil security scanner
# Usage: curl -sSL https://vigil.sh | sh

set -e

VERSION="0.1.0"
REPO="vigil-sec/vigil"
RELEASE_URL="https://github.com/$REPO/releases/latest/download"
INSTALL_DIR="${VIGIL_INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Linux*)
    OS_TYPE="linux"
    ;;
  Darwin*)
    OS_TYPE="darwin"
    ;;
  *)
    echo "❌ Unsupported OS: $OS"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64)
    ARCH_TYPE="amd64"
    ;;
  aarch64|arm64)  # Add |arm64 here
    ARCH_TYPE="arm64"
    ;;
  *)
    echo "❌ Unsupported architecture: $ARCH"
    exit 1
    ;;
esac
BINARY_NAME="vigil-${OS_TYPE}-${ARCH_TYPE}"
DOWNLOAD_URL="${RELEASE_URL}/${BINARY_NAME}"

echo "🔍 Vigil Security Scanner v${VERSION}"
echo "📦 Downloading $BINARY_NAME..."

# Download the binary
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

BINARY_PATH="$TEMP_DIR/$BINARY_NAME"
if ! curl -sSL -o "$BINARY_PATH" "$DOWNLOAD_URL"; then
  echo "❌ Failed to download from $DOWNLOAD_URL"
  echo "   Falling back to local build..."
  
  # Fallback: build from source if available
  if command -v go &> /dev/null; then
    echo "🔨 Building from source..."
    TEMP_BUILD=$(mktemp -d)
    cd "$TEMP_BUILD"
    git clone https://github.com/vigil-sec/vigil.git .
    go build -o "$BINARY_PATH" ./cmd/vigil
    cd -
  else
    echo "❌ curl failed and Go not installed. Please install Go or check network."
    exit 1
  fi
fi

chmod +x "$BINARY_PATH"

# Try to install system-wide (may require sudo)
if [ -w "$INSTALL_DIR" ]; then
  cp "$BINARY_PATH" "$INSTALL_DIR/vigil"
  echo "✅ Installed to $INSTALL_DIR/vigil"
elif sudo -n true 2>/dev/null; then
  sudo cp "$BINARY_PATH" "$INSTALL_DIR/vigil"
  echo "✅ Installed to $INSTALL_DIR/vigil"
else
  # Install to user bin
  mkdir -p ~/.local/bin
  cp "$BINARY_PATH" ~/.local/bin/vigil
  echo "✅ Installed to ~/.local/bin/vigil"
  echo "   (add ~/.local/bin to your PATH)"
fi

# Run the scan
echo ""
echo "🚀 Running security scan..."
echo ""

# Determine which attachment method to use
if command -v docker &> /dev/null && docker ps &> /dev/null; then
  exec vigil --attach-docker "$@"
elif [ -S "$XDG_RUNTIME_DIR/docker.sock" ] 2>/dev/null; then
  exec vigil --attach-docker "$@"
else
  exec vigil "$@"
fi
