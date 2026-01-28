#!/bin/bash
# scripts/verify_installer.sh – FINAL macOS/Linux version

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

echo -e "${YELLOW}[*] Downloading release assets${NC}"
curl -sSL -o "$installer" "$INSTALLER_URL"
curl -sSL -o "$sigfile" "$SIG_URL"
curl -sSL -o "$pubkey" "$PUBKEY_URL"
curl -sSL -o "$checksum" "$CHECKSUM_URL"
curl -sSL -o "$fingerprint_file" "$FINGERPRINT_URL"

echo -e "${YELLOW}[*] Verifying checksum${NC}"
expected=$(awk '{print $1}' "$checksum")
if command -v sha256sum &>/dev/null; then
  actual=$(sha256sum "$installer" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$installer" | awk '{print $1}')
fi
[ "$actual" = "$expected" ] && echo -e "${GREEN}✅ Checksum verified${NC}" || { echo -e "${RED}[!] Checksum FAILED${NC}"; exit 1; }

echo -e "${YELLOW}[*] Verifying signature${NC}"
# CRITICAL: Ed25519 requires -rawin (no external digest)
if openssl pkeyutl -verify -pubin -inkey "$pubkey" -rawin -in "$installer" -sigfile "$sigfile" 2>/dev/null; then
  echo -e "${GREEN}✅ Signature verified${NC}"
else
  echo -e "${RED}[!] Signature verification FAILED${NC}"
  echo "Debug: Full output:"
  openssl pkeyutl -verify -pubin -inkey "$pubkey" -rawin -in "$installer" -sigfile "$sigfile"
  exit 1
fi

echo -e "${YELLOW}[*] Verifying public key fingerprint${NC}"
pubkey_fingerprint=$(openssl pkey -pubin -in "$pubkey" -outform DER 2>/dev/null | shasum -a 256 | awk '{print $1}')
expected_fingerprint=$(cat "$fingerprint_file" | tr -d '\n')
[ "$pubkey_fingerprint" = "$expected_fingerprint" ] && echo -e "${GREEN}✅ Fingerprint verified${NC}" || { echo -e "${RED}[!] Fingerprint mismatch${NC}"; exit 1; }

echo -e "${GREEN}[✅] Installer verified successfully!${NC}"
echo ""
echo -e "${YELLOW}You can now run:${NC} sh $installer"
