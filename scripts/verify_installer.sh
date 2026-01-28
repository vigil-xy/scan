#!/bin/bash
# scripts/verify_installer.sh – ULTRA-ROBUST macOS/Linux version

set -euo pipefail

# Colors
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# URLs
INSTALLER_URL="https://github.com/vigil-xy/scan/releases/download/v0.1.0/vigil.sh"
SIG_URL="https://github.com/vigil-xy/scan/releases/download/v0.1.0/vigil.sh.sig"
PUBKEY_URL="https://github.com/vigil-xy/scan/releases/download/v0.1.0/vigil_ed25519_pub.pem"
CHECKSUM_URL="https://github.com/vigil-xy/scan/releases/download/v0.1.0/vigil.sh.sha256"
FINGERPRINT_URL="https://raw.githubusercontent.com/vigil-xy/scan/main/build/release_assets/vigil_ed25519_pub_fingerprint.txt"

# Temp dir
TMP_DIR=$(mktemp -d -t vigil_verify_XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

# File paths
installer="$TMP_DIR/vigil.sh"
sigfile="$TMP_DIR/vigil.sh.sig"
pubkey="$TMP_DIR/vigil_ed25519_pub.pem"
checksum="$TMP_DIR/vigil.sh.sha256"
fingerprint_file="$TMP_DIR/fingerprint.txt"

# Check prerequisites
for cmd in curl openssl awk; do
  if ! command -v "$cmd" &>/dev/null; then
    echo -e "${RED}[!] Required command not found: $cmd${NC}"
    exit 1
  fi
done

echo -e "${YELLOW}[*] Downloading release assets to $TMP_DIR${NC}"
curl -sSL -o "$installer" "$INSTALLER_URL"
curl -sSL -o "$sigfile" "$SIG_URL"
curl -sSL -o "$pubkey" "$PUBKEY_URL"
curl -sSL -o "$checksum" "$CHECKSUM_URL"
curl -sSL -o "$fingerprint_file" "$FINGERPRINT_URL"

# Verify all files exist
for file in "$installer" "$sigfile" "$pubkey" "$checksum" "$fingerprint_file"; do
  if [ ! -f "$file" ]; then
    echo -e "${RED}[!] Download failed: $file not found${NC}"
    exit 1
  fi
done

echo -e "${YELLOW}[*] Verifying checksum${NC}"
expected=$(awk '{print $1}' "$checksum")
if command -v sha256sum &>/dev/null; then
  actual=$(sha256sum "$installer" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$installer" | awk '{print $1}')
fi
if [ "$actual" = "$expected" ]; then
  echo -e "${GREEN}✅ Checksum verified${NC}"
else
  echo -e "${RED}[!] Checksum FAILED${NC}"
  echo "Expected: $expected"
  echo "Got:      $actual"
  exit 1
fi

echo -e "${YELLOW}[*] Verifying signature${NC}"
if openssl dgst -sha256 -verify "$pubkey" -signature "$sigfile" "$installer" 2>/dev/null; then
  echo -e "${GREEN}✅ Signature verified${NC}"
else
  echo -e "${RED}[!] Signature verification FAILED${NC}"
  echo "Debug: Running with verbose output..."
  openssl dgst -sha256 -verify "$pubkey" -signature "$sigfile" "$installer"
  exit 1
fi

echo -e "${YELLOW}[*] Verifying public key fingerprint${NC}"
pubkey_fingerprint=$(openssl pkey -pubin -in "$pubkey" -outform DER 2>/dev/null | shasum -a 256 | awk '{print $1}')
expected_fingerprint=$(cat "$fingerprint_file" | tr -d '\n')
if [ "$pubkey_fingerprint" = "$expected_fingerprint" ]; then
  echo -e "${GREEN}✅ Fingerprint verified${NC}"
else
  echo -e "${RED}[!] Fingerprint mismatch${NC}"
  exit 1
fi

echo -e "${GREEN}[✅] Installer verified successfully!${NC}"
echo ""
echo -e "${YELLOW}You can now run:${NC} sh $installer"
