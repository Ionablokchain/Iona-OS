#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build-uefi.sh — UEFI image builder for IONA OS.
#
# IMPORTANT: IONA OS kernel uses the "bootloader" crate (bootloader_api),
# NOT multiboot2/GRUB. The RECOMMENDED boot path is:
#
#   ./scripts/gen-disk-images.sh <kernel-elf> dist/
#
# This script (build-uefi.sh) attempts to create a UEFI image using GRUB
# as the EFI loader, which is a SECONDARY method. The GRUB grub.cfg here
# does NOT work with the kernel (wrong boot protocol). This script is kept
# for reference and for machines that need GRUB's EFI stub specifically.
#
# For standard QEMU testing:
#   make run  OR  ./scripts/qemu.sh  (uses gen-disk-images.sh output)
#
# Strategy for BOOTX64.EFI (in priority order):
#   1. Use gen-disk-images.sh (bootloader crate v0.11) — fully self-contained,
#      no host dependencies. This is the RECOMMENDED path.
#   2. Build a standalone GRUB EFI binary via grub-mkstandalone (if installed).
#   3. Fall back to a pre-placed dist/BOOTX64.EFI.
#   4. Search common host paths (last resort, with a warning).
#
# If none of the above succeed, the script exits with an error and a helpful
# message explaining how to install the required tools.
# ---------------------------------------------------------------------------
set -euo pipefail
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"

KERNEL="$DIST/iona-os-kernel.elf"
OUTPUT="$DIST/iona-uefi.img"
[ -f "$KERNEL" ] || die "Kernel ELF not found: $KERNEL"

# ---- Method 1: bootloader crate (fully self-contained) --------------------
# gen-disk-images.sh already produces a proper UEFI image using the bootloader
# crate. If that image exists and is newer than the kernel, just use it.
GEN_UEFI="$ROOT_DIR/target/x86_64-unknown-none/release/build/iona-uefi.img"
if [ -f "$GEN_UEFI" ] && [ "$GEN_UEFI" -nt "$KERNEL" ]; then
  log "Using UEFI image from gen-disk-images.sh (bootloader crate — self-contained)"
  cp "$GEN_UEFI" "$OUTPUT"
  ok "UEFI image created: $OUTPUT (via bootloader crate)"
  exit 0
fi

# ---- Method 2: build GRUB standalone EFI binary ----------------------------
BOOTEFI="$DIST/BOOTX64.EFI"
if [ ! -f "$BOOTEFI" ] && command -v grub-mkstandalone >/dev/null 2>&1; then
  log "Building BOOTX64.EFI via grub-mkstandalone (self-contained)..."
  GRUB_CFG_TMP=$(mktemp /tmp/grub-early.XXXXXX)
  cat > "$GRUB_CFG_TMP" <<'GCFG'
search --no-floppy --set=root --label IONA_EFI
set prefix=($root)/EFI/IONA
configfile $prefix/grub.cfg
GCFG
  grub-mkstandalone \
    --format=x86_64-efi \
    --output="$BOOTEFI" \
    --locales="" \
    --fonts="" \
    "boot/grub/grub.cfg=$GRUB_CFG_TMP" 2>/dev/null \
    && ok "Built BOOTX64.EFI via grub-mkstandalone" \
    || fail "grub-mkstandalone failed; trying fallbacks"
  rm -f "$GRUB_CFG_TMP"
fi

# ---- Method 3: pre-placed dist/BOOTX64.EFI --------------------------------
# (already checked above — if it exists we skip to image creation)

# ---- Method 4: host fallback (last resort, with warning) -------------------
if [ ! -f "$BOOTEFI" ]; then
  HOST_CANDIDATES=(
    /usr/lib/grub/x86_64-efi/monolithic/grubx64.efi
    /boot/efi/EFI/BOOT/BOOTX64.EFI
    /usr/share/OVMF/BOOTX64.EFI
    /usr/share/edk2/ovmf/BOOTX64.EFI
  )
  for cand in "${HOST_CANDIDATES[@]}"; do
    if [ -f "$cand" ]; then
      fail "WARNING: Using host EFI binary ($cand) — build is NOT self-contained."
      fail "  Install grub-efi-amd64-bin for a self-contained build:"
      fail "    sudo apt install grub-efi-amd64-bin"
      cp "$cand" "$BOOTEFI"
      break
    fi
  done
fi

# ---- Give up with a helpful error -----------------------------------------
if [ ! -f "$BOOTEFI" ]; then
  die "BOOTX64.EFI not found and cannot be built.
  To fix, do ONE of:
    1. Run gen-disk-images.sh first (uses bootloader crate — no host deps)
    2. Install grub: sudo apt install grub-efi-amd64-bin
    3. Place a BOOTX64.EFI manually in dist/"
fi

# ---- Build the GPT UEFI disk image ----------------------------------------
IMG_MB=256; ESP_MB=64

# Require tools for manual image creation
for tool in dd mkdosfs mmd mcopy; do
  command -v "$tool" >/dev/null 2>&1 || die "Required tool '$tool' not found. Install: sudo apt install mtools dosfstools"
done

log "Building UEFI disk image ${IMG_MB}MB..."
dd if=/dev/zero of="$OUTPUT" bs=1M count=$IMG_MB status=none

if command -v sgdisk >/dev/null 2>&1; then
  sgdisk -Z "$OUTPUT" >/dev/null 2>&1 || true
  sgdisk -n 1:2048:$((ESP_MB*2048+2047)) -t 1:ef00 -c 1:"EFI" \
         -n 2:0:0 -t 2:8300 -c 2:"IONA" "$OUTPUT" >/dev/null
fi

FATIMG=$(mktemp /tmp/esp.XXXXXX)
dd if=/dev/zero of="$FATIMG" bs=1M count=$ESP_MB status=none
mkdosfs -F 32 -n IONA_EFI "$FATIMG" >/dev/null
export MTOOLS_SKIP_CHECK=1
mmd -i "$FATIMG" ::/EFI ::/EFI/BOOT ::/EFI/IONA >/dev/null 2>&1 || true
mcopy -i "$FATIMG" "$KERNEL" ::/EFI/IONA/kernel.elf >/dev/null

# Embed a grub.cfg for the UEFI loader
# NOTE: IONA OS kernel uses the bootloader crate API, NOT multiboot2.
# This grub.cfg is a legacy fallback — the correct boot path is:
#   gen-disk-images.sh → bootloader crate → iona-uefi.img
# If you see "Error 60" or "invalid signature", use gen-disk-images.sh instead.
cat > /tmp/iona-boot.conf <<EOF
set timeout=3
menuentry "IONA OS v0.6.0 (legacy — use gen-disk-images.sh)" {
    # WARNING: multiboot2 is NOT compatible with this kernel.
    # The kernel expects bootloader_api (x86_64-unknown-none, bootloader crate).
    # This entry is kept for documentation only.
    echo "ERROR: Use gen-disk-images.sh to create a compatible boot image."
    sleep 5
}
EOF
mcopy -i "$FATIMG" /tmp/iona-boot.conf ::/EFI/IONA/grub.cfg >/dev/null

# Also write a simple boot.conf for custom loaders
cat > /tmp/iona-boot.conf <<EOF
kernel=EFI/IONA/kernel.elf
root=ionafs
EOF
mcopy -i "$FATIMG" /tmp/iona-boot.conf ::/EFI/IONA/boot.conf >/dev/null

mcopy -i "$FATIMG" "$BOOTEFI" ::/EFI/BOOT/BOOTX64.EFI >/dev/null
dd if="$FATIMG" of="$OUTPUT" bs=512 seek=2048 conv=notrunc status=none
rm -f "$FATIMG" /tmp/iona-boot.conf
ok "UEFI image created: $OUTPUT"
