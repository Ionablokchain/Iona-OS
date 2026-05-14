#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source scripts/lib.sh

mkdir -p "$DIST"

USPACE_TARGET="${USPACE_TARGET:-x86_64-unknown-none}"
ARTIFACT_MANIFEST="$DIST/release-manifest.json"

need() { command -v "$1" >/dev/null 2>&1 || die "Missing dependency: $1"; }
need cargo
need rustc
need python3
need sha256sum

if command -v rustup >/dev/null 2>&1; then
  rustup target add x86_64-unknown-none >/dev/null 2>&1 || true
fi

log "Building kernel (x86_64-unknown-none)..."
RUSTFLAGS="-C force-frame-pointers=yes" cargo build --release --target x86_64-unknown-none ${CARGO_EXTRA_FLAGS:-}
ok "Kernel built"

STRICT="${STRICT:-0}"
log "Building userspace (STRICT=$STRICT)..."
USPACE_FAIL=0
for pkg in userspace/iona-node userspace/iona-shell userspace/iona-utils; do
  [ -f "$pkg/Cargo.toml" ] || continue
  log "  Building $pkg..."
  if (cd "$pkg" && cargo build --release --target "$USPACE_TARGET" ${CARGO_EXTRA_FLAGS:-}) || (cd "$pkg" && cargo build --release ${CARGO_EXTRA_FLAGS:-}); then
    ok "  $pkg built"
  else
    fail "  $pkg FAILED to build"
    USPACE_FAIL=$((USPACE_FAIL+1))
    if [ "$STRICT" = "1" ]; then
      die "Userspace build failed (STRICT=1). Fix $pkg or set STRICT=0 to continue."
    fi
  fi
done
if [ $USPACE_FAIL -gt 0 ]; then
  fail "Userspace: $USPACE_FAIL package(s) failed (non-strict mode — continuing)"
else
  ok "Userspace built successfully"
fi

cp "target/x86_64-unknown-none/release/iona-os-kernel" "$DIST/iona-os-kernel.elf"
ok "Kernel ELF copied"

log "Building IONAFS image..."
./scripts/build-ionafs.sh

log "Building UEFI image..."
./scripts/build-uefi.sh || fail "UEFI image build skipped/failed"

log "Building ISO (if xorriso available)..."
./scripts/build-iso.sh || true

GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
cat > "$DIST/iona-os-version.json" <<EOF
{
  "version": "0.6.0",
  "git_sha": "$GIT_SHA",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel_size_bytes": $(stat -c%s "$DIST/iona-os-kernel.elf" 2>/dev/null || echo 0)
}
EOF
ok "Version metadata written"

echo
echo "Artifacts in $DIST:"
ls -1 "$DIST" | sed 's#^#  - #' || true


# Report userspace binaries discovered for packaging
for name in iona-node iona-shell iona-utils; do
  found=0
  for cand in \
    "target/x86_64-unknown-none/release/$name" \
    "userspace/$name/target/x86_64-unknown-none/release/$name" \
    "userspace/$name/target/release/$name"; do
    if [ -f "$cand" ]; then
      ok "Packager sees $cand"
      found=1
      break
    fi
  done
  [ $found -eq 1 ] || fail "Packager did not find userspace binary: $name"
done


# Generate manifest for packaged artifacts
KERNEL_SHA=$(sha256sum "$DIST/iona-os-kernel.elf" | awk '{print $1}')
cat > "$ARTIFACT_MANIFEST" <<EOF
{
  "version": "0.6.0",
  "git_sha": "$GIT_SHA",
  "built_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "kernel": {
    "path": "iona-os-kernel.elf",
    "sha256": "$KERNEL_SHA"
  },
  "userspace": [
EOF
first=1
for name in iona-node iona-shell iona-utils; do
  for cand in \
    "target/$USPACE_TARGET/release/$name" \
    "userspace/$name/target/$USPACE_TARGET/release/$name" \
    "userspace/$name/target/release/$name"; do
    if [ -f "$cand" ]; then
      SHA=$(sha256sum "$cand" | awk '{print $1}')
      [ $first -eq 0 ] && printf ',\n' >> "$ARTIFACT_MANIFEST"
      printf '    {"name":"%s","source":"%s","sha256":"%s"}' "$name" "$cand" "$SHA" >> "$ARTIFACT_MANIFEST"
      first=0
      break
    fi
  done
done
cat >> "$ARTIFACT_MANIFEST" <<EOF

  ]
}
EOF
ok "Release manifest written"
