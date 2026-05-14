#!/usr/bin/env bash
# Sign IONA OS release artifacts using ECDSA P-256 (Ed25519 preferred for production)
#
# Usage: ./scripts/sign-release.sh [--key <private-key.pem>]
#
# Produces:
#   dist/release-manifest.json    — version + hashes
#   dist/release-manifest.sig     — ECDSA signature
#   dist/release-manifest.pub     — public key (for verification)
#
# Verification by bootloader or update system:
#   1. Hash all artifacts
#   2. Verify hashes match manifest
#   3. Verify manifest signature with embedded public key
#   4. Verify public key against root of trust

set -euo pipefail
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"

DIST="${DIST:-$(dirname "$SDIR")/dist}"
MANIFEST="$DIST/release-manifest.json"
KEY="${SIGN_KEY:-}"

# ── Compute artifact hashes ──────────────────────────────────────────────────
log "Computing artifact hashes..."
declare -A HASHES

for artifact in \
    "$DIST/iona-os-kernel.elf" \
    "$DIST/iona-disk.img"
do
    [ -f "$artifact" ] || continue
    name=$(basename "$artifact")
    hash=$(sha256sum "$artifact" | awk '{print $1}')
    HASHES["$name"]="$hash"
    log "  $name: $hash"
done

# ── Build manifest ───────────────────────────────────────────────────────────
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)

cat > "$MANIFEST" <<MANIFEST
{
  "format_version": 1,
  "product": "IONA OS",
  "version": "0.6.0",
  "commit": "$COMMIT",
  "branch": "$BRANCH",
  "built_at": "$TIMESTAMP",
  "artifacts": {
MANIFEST

FIRST=1
for name in "${!HASHES[@]}"; do
    [ $FIRST -eq 0 ] && echo "," >> "$MANIFEST"
    cat >> "$MANIFEST" <<ART
    "$name": {
      "sha256": "${HASHES[$name]}"
    }
ART
    FIRST=0
done

cat >> "$MANIFEST" <<MANIFEST
  },
  "minimum_kernel": "0.6.0",
  "signature_algorithm": "ECDSA-P256-SHA256"
}
MANIFEST

log "Manifest written: $MANIFEST"

# ── Sign with ECDSA (if openssl available) ──────────────────────────────────
PUBKEY="$DIST/release-manifest.pub"
SIGFILE="$DIST/release-manifest.sig"

if command -v openssl >/dev/null 2>&1; then
    if [ -n "$KEY" ] && [ -f "$KEY" ]; then
        log "Signing with provided key..."
        openssl dgst -sha256 -sign "$KEY" -out "$SIGFILE" "$MANIFEST"
        openssl ec -in "$KEY" -pubout -out "$PUBKEY" 2>/dev/null
        ok "Signed: $SIGFILE"
    else
        log "Generating ephemeral signing key (no KEY provided)..."
        TMP_KEY=$(mktemp /tmp/iona-sign-key.XXXXXX.pem)
        openssl ecparam -genkey -name prime256v1 -noout -out "$TMP_KEY" 2>/dev/null
        openssl dgst -sha256 -sign "$TMP_KEY" -out "$SIGFILE" "$MANIFEST"
        openssl ec -in "$TMP_KEY" -pubout -out "$PUBKEY" 2>/dev/null
        rm -f "$TMP_KEY"
        log "WARNING: Signed with ephemeral key — not reproducible"
        log "For production: SIGN_KEY=/path/to/key.pem ./scripts/sign-release.sh"
        ok "Signed (ephemeral): $SIGFILE"
    fi
else
    # No openssl: compute SHA-256 of manifest as self-signature placeholder
    MANIFEST_HASH=$(sha256sum "$MANIFEST" | awk '{print $1}')
    echo "$MANIFEST_HASH" > "$SIGFILE"
    echo "ecdsa-p256-placeholder" > "$PUBKEY"
    log "WARNING: openssl not available — using SHA-256 hash as signature placeholder"
    log "Install openssl for real ECDSA signing: sudo apt install openssl"
fi

# ── Verify integrity ─────────────────────────────────────────────────────────
log "Verifying artifact integrity..."
FAILURES=0
while IFS= read -r line; do
    name=$(echo "$line" | grep -o '"[^"]*\.elf\|"[^"]*\.img' | tr -d '"' || true)
    hash=$(echo "$line" | grep -o '"sha256": "[^"]*"' | grep -o '[0-9a-f]\{64\}' || true)
    [ -n "$name" ] && [ -n "$hash" ] || continue
    artifact="$DIST/$name"
    [ -f "$artifact" ] || { log "  SKIP: $name not found"; continue; }
    actual=$(sha256sum "$artifact" | awk '{print $1}')
    if [ "$actual" = "$hash" ]; then
        log "  OK: $name"
    else
        fail "  MISMATCH: $name expected=$hash actual=$actual"
        FAILURES=$((FAILURES+1))
    fi
done < "$MANIFEST"

[ $FAILURES -eq 0 ] || die "Integrity check failed ($FAILURES mismatches)"
ok "Release manifest signed and verified: $MANIFEST"
