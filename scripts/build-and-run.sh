#!/usr/bin/env bash
# Build + run în QEMU cu un singur comandă
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PROFILE="${PROFILE:-debug}"
TARGET="x86_64-unknown-none"

echo "Building IONA OS Kernel..."
if [ "$PROFILE" = "release" ]; then
    cargo build --release 2>&1
else
    cargo build 2>&1
fi

KERNEL_ELF="target/$TARGET/$PROFILE/iona-os-kernel"
[ -f "$KERNEL_ELF" ] || { echo "✗ Kernel ELF not found: $KERNEL_ELF"; exit 1; }

# Generate disk images post-build
BUILD_IMG_DIR="target/$TARGET/$PROFILE/build"
mkdir -p "$BUILD_IMG_DIR"
echo "Generating disk images..."
"$(dirname "${BASH_SOURCE[0]}")/gen-disk-images.sh" "$KERNEL_ELF" "$BUILD_IMG_DIR" 2>&1
echo ""
echo "Launching QEMU..."
exec ./scripts/qemu.sh "$@"
