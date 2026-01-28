#!/bin/sh
# vigil-scan.sh - Install and run vigil security scanner

set -eu

VERSION="0.2.0"
REPO="vigil-xy/scan"
RELEASE_URL="https://github.com/${REPO}/releases/latest/download"
INSTALL_DIR="${VIGIL_INSTALL_DIR:-$HOME/.local/bin}"

# Detect OS and architecture
OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
  Linux*)  OS_TYPE="linux" ;;
  Darwin*) OS_TYPE="darwin" ;;
  *) echo "❌ Unsupported OS: $OS"; exit 1 ;;
esac

case "$ARCH" in
  x86_64)    ARCH_TYPE="amd64" ;;
  aarch64|arm64) ARCH_TYPE="arm64" ;;
  *) echo "❌ Unsupported architecture: $ARCH"; exit 1 ;;
esac

BINARY_NAME="vigil-scan-${OS_TYPE}-${ARCH_TYPE}"
FINAL_BINARY_NAME="vigil-scan"

echo "🔍 Vigil Security Scanner v${VERSION}"
echo "📦 Downloading ${BINARY_NAME}..."

# Create temp dir
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

BINARY_PATH="${TEMP_DIR}/${BINARY_NAME}"
DOWNLOAD_URL="${RELEASE_URL}/${BINARY_NAME}"

# Download with fallback
if ! curl -sSL --fail -o "$BINARY_PATH" "$DOWNLOAD_URL" 2>/dev/null; then
  echo "❌ Failed to download from $DOWNLOAD_URL"
  echo "   Attempting to build from source..."
  
  if command -v go >/dev/null 2>&1; then
    TEMP_BUILD=$(mktemp -d)
    git clone -q "https://github.com/${REPO}.git" "$TEMP_BUILD" 2>/dev/null
    cd "$TEMP_BUILD"
    GOOS="${OS_TYPE}" GOARCH="${ARCH_TYPE}" go build -o "$BINARY_PATH" ./cmd/vigil 2>/dev/null
    cd - >/dev/null
    rm -rf "$TEMP_BUILD"
  else
    echo "❌ Go not installed and binary unavailable for ${OS_TYPE}-${ARCH_TYPE}"
    exit 1
  fi
fi

chmod +x "$BINARY_PATH"

# Install
mkdir -p "$INSTALL_DIR"
cp "$BINARY_PATH" "${INSTALL_DIR}/${FINAL_BINARY_NAME}"
echo "✅ Installed to ${INSTALL_DIR}/${FINAL_BINARY_NAME}"

# Add to PATH if needed
case ":$PATH:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    SHELL_RC="$HOME/.$(basename $SHELL)rc"
    echo "export PATH=\"${INSTALL_DIR}:\$PATH\"" >> "$SHELL_RC"
    echo "   Added ${INSTALL_DIR} to PATH (restart terminal or: source $SHELL_RC)"
    ;;
esac

# Non-blocking Docker detection
BINARY_EXEC="${INSTALL_DIR}/${FINAL_BINARY_NAME}"
DOCKER_AVAILABLE=0

if command -v docker >/dev/null 2>&1; then
  timeout 1 docker info >/dev/null 2>&1 && DOCKER_AVAILABLE=1
fi

# Run scan
echo ""
echo "🚀 Running security scan..."
echo ""

if [ $DOCKER_AVAILABLE -eq 1 ]; then
  exec "$BINARY_EXEC" --attach-docker "$@"
else
  exec "$BINARY_EXEC" "$@"
fi
