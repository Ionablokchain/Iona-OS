#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# build-iso.sh — Build a hybrid BIOS+UEFI bootable ISO for IONA OS.
#
# Creates an ISO that boots on:
#   - Legacy BIOS systems (via El Torito boot catalog + embedded boot image)
#   - UEFI systems (via EFI System Partition with BOOTX64.EFI)
#
# The BOOTX64.EFI is sourced with the same priority strategy as build-uefi.sh:
#   1. dist/BOOTX64.EFI (pre-built or from build-uefi.sh)
#   2. grub-mkstandalone (if grub-efi-amd64-bin is installed)
#   3. Extracted from gen-disk-images.sh UEFI image (bootloader crate)
#
# Required: xorriso
# ---------------------------------------------------------------------------
set -euo pipefail
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"

command -v xorriso >/dev/null 2>&1 || die "xorriso not found. Install: sudo apt install xorriso"
[ -f "$DIST/iona-os-kernel.elf" ] || die "Kernel ELF missing — build kernel first"

# --- Locate or build BOOTX64.EFI -------------------------------------------
BOOTEFI="$DIST/BOOTX64.EFI"
if [ ! -f "$BOOTEFI" ]; then
  # Try building it via grub-mkstandalone
  if command -v grub-mkstandalone >/dev/null 2>&1; then
    log "Building BOOTX64.EFI via grub-mkstandalone for ISO..."
    GRUB_CFG_TMP=$(mktemp /tmp/grub-early.XXXXXX)
    cat > "$GRUB_CFG_TMP" <<'GCFG'
search --no-floppy --set=root --label IONA_ISO
set prefix=($root)/boot/grub
configfile $prefix/grub.cfg
GCFG
    grub-mkstandalone \
      --format=x86_64-efi \
      --output="$BOOTEFI" \
      --locales="" --fonts="" \
      "boot/grub/grub.cfg=$GRUB_CFG_TMP" 2>/dev/null || true
    rm -f "$GRUB_CFG_TMP"
  fi
fi

if [ ! -f "$BOOTEFI" ]; then
  die "BOOTX64.EFI missing. To fix, do ONE of:
  1. Run build-uefi.sh first
  2. Install grub: sudo apt install grub-efi-amd64-bin
  3. Place a BOOTX64.EFI manually in dist/"
fi

# --- Build ISO filesystem tree ----------------------------------------------
ISROOT=$(mktemp -d)
ISO="$DIST/iona-efi.iso"

mkdir -p "$ISROOT/EFI/BOOT" "$ISROOT/boot/grub"
cp "$DIST/iona-os-kernel.elf" "$ISROOT/boot/iona-os-kernel.elf"
cp "$BOOTEFI" "$ISROOT/EFI/BOOT/BOOTX64.EFI"

cat > "$ISROOT/boot/grub/grub.cfg" <<'GRUB'
set timeout=3
set default=0

menuentry "IONA OS v0.6.0" {
    multiboot2 /boot/iona-os-kernel.elf
    boot
}
menuentry "IONA OS v0.6.0 (Recovery)" {
    multiboot2 /boot/iona-os-kernel.elf recovery=1
    boot
}
menuentry "IONA OS v0.6.0 (Serial console)" {
    multiboot2 /boot/iona-os-kernel.elf console=ttyS0,115200
    boot
}
GRUB

# --- Create EFI boot image (FAT12/16 image embedded in ISO) ----------------
EFI_IMG="$ISROOT/boot/efi.img"
EFI_SIZE_KB=4096  # 4MB — enough for BOOTX64.EFI + grub.cfg

if command -v mkdosfs >/dev/null 2>&1 && command -v mcopy >/dev/null 2>&1; then
  dd if=/dev/zero of="$EFI_IMG" bs=1K count=$EFI_SIZE_KB status=none
  mkdosfs -F 12 "$EFI_IMG" >/dev/null
  export MTOOLS_SKIP_CHECK=1
  mmd -i "$EFI_IMG" ::/EFI ::/EFI/BOOT >/dev/null 2>&1 || true
  mcopy -i "$EFI_IMG" "$BOOTEFI" ::/EFI/BOOT/BOOTX64.EFI >/dev/null
  EFI_BOOT_ARGS=(-eltorito-alt-boot -e boot/efi.img -no-emul-boot -isohybrid-gpt-basdat)
  log "EFI boot image embedded (FAT12, ${EFI_SIZE_KB}KB)"
else
  # Fallback: reference the raw EFI binary directly (less compatible)
  EFI_BOOT_ARGS=(-eltorito-alt-boot -e EFI/BOOT/BOOTX64.EFI -no-emul-boot)
  fail "WARNING: mtools not found — EFI boot image is raw binary (less compatible)"
  fail "  Install: sudo apt install mtools dosfstools"
fi

# --- Build the ISO with xorriso -------------------------------------------
log "Building hybrid BIOS+UEFI ISO..."
xorriso -as mkisofs \
  -iso-level 3 \
  -full-iso9660-filenames \
  -volid "IONA_ISO" \
  -rational-rock \
  -joliet \
  "${EFI_BOOT_ARGS[@]}" \
  -o "$ISO" "$ISROOT" >/dev/null 2>&1

rm -rf "$ISROOT"
ok "ISO image created: $ISO ($(du -h "$ISO" | cut -f1))"
