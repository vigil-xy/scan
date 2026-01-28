#!/usr/bin/env bash
set -euo pipefail

RELEASE_BASE="https://github.com/vigil-xy/scan/releases/download/v0.1.0"
RAW_BASE="https://raw.githubusercontent.com/vigil-xy/scan/main/build/release_assets"
TMPDIR=$(mktemp -d)
cleanup(){ rm -rf "$TMPDIR"; }
trap cleanup EXIT

echo "[*] Downloading release assets to $TMPDIR"
curl -sSL -o "$TMPDIR/vigil.sh" "$RELEASE_BASE/vigil.sh"
curl -sSL -o "$TMPDIR/vigil.sh.sha256" "$RELEASE_BASE/vigil.sh.sha256"
curl -sSL -o "$TMPDIR/vigil.sh.sig" "$RELEASE_BASE/vigil.sh.sig" || true
curl -sSL -o "$TMPDIR/vigil_ed25519_pub.pem" "$RELEASE_BASE/vigil_ed25519_pub.pem"
curl -sSL -o "$TMPDIR/expected_fingerprint.txt" "$RAW_BASE/vigil_ed25519_pub_fingerprint.txt"

echo "[*] Verifying checksum"
sha256sum -c "$TMPDIR/vigil.sh.sha256"

if [ -f "$TMPDIR/vigil.sh.sig" ]; then
  echo "[*] Verifying signature with OpenSSL (Ed25519)"
  if openssl pkeyutl -verify -pubin -inkey "$TMPDIR/vigil_ed25519_pub.pem" -in "$TMPDIR/vigil.sh" -sigfile "$TMPDIR/vigil.sh.sig"; then
    echo "[*] Signature verification: OK"
  else
    echo "[!] Signature verification FAILED" >&2
    exit 2
  fi
else
  echo "[!] Signature file not found; aborting" >&2
  exit 2
fi

echo "[*] Checking public-key fingerprint against repository canonical value"
fp=$(openssl pkey -pubin -in "$TMPDIR/vigil_ed25519_pub.pem" -outform DER | sha256sum | awk '{print $1}')
expected=$(grep -oE '[0-9a-f]{64}' "$TMPDIR/expected_fingerprint.txt" | head -n1 || true)
if [ "$fp" = "$expected" ]; then
  echo "[*] Public-key fingerprint matches expected: $fp"
else
  echo "[!] Public-key fingerprint mismatch" >&2
  echo "    expected: $expected" >&2
  echo "    actual:   $fp" >&2
  exit 3
fi

echo "[*] Installer verified successfully. To run: sh $TMPDIR/vigil.sh"
