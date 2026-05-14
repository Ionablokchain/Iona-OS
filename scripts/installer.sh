#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# installer.sh — Install or update IONA OS
#
# Modes:
#   installer.sh /dev/sdX              Fresh install to block device (wipes disk)
#   installer.sh --apply file.zip      Update build artifact (dist/iona-disk.img)
#   installer.sh --live /dev/sdX       Update kernel+userspace on installed system
#                                      (preserves user data, config, IONAFS)
# ---------------------------------------------------------------------------
set -euo pipefail
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"

usage() {
  cat <<EOF
Usage:
  $0 /dev/sdX                  Fresh install to block device (DESTRUCTIVE)
  $0 --apply file.zip          Update dist/iona-disk.img with new binaries
  $0 --live /dev/sdX [file.zip] Update installed system (preserves user data)

Options:
  --apply   Update the build artifact image with ELF binaries from a zip
  --live    Update an already-installed system's kernel and userspace
            without erasing user data or IONAFS configuration
EOF
  exit 1
}

part_path() {
  local dev="$1" n="$2"
  if [[ "$dev" =~ nvme|mmcblk|loop ]]; then echo "${dev}p${n}"; else echo "${dev}${n}"; fi
}

find_userspace_bins() {
  local root="$1"
  find "$root" \( -path '*/target/release/*' -o -path '*/target/x86_64-unknown-none/release/*' \) -type f 2>/dev/null | while read -r f; do
    file "$f" 2>/dev/null | grep -q ELF && printf '%s\n' "$f"
  done
}



find_update_payloads() {
  local root="$1"
  find "$root" \( -name '*.elf' -o -name '*.wasm' -o -name 'release-manifest.json' -o -name '*.json' \) -type f 2>/dev/null
}

install_payload_to_ionafs() {
  local disk="$1" payload="$2"
  local base; base=$(basename "$payload")
  local dest="/bin/$base"
  case "$base" in
    *.wasm) dest="/wasm/$base" ;;
    release-manifest.json) dest="/etc/iona-artifacts.json" ;;
    *.json) dest="/etc/$base" ;;
  esac
  python3 "$SDIR/install-to-ionafs.py" --disk "$disk" --file "$payload" --path "$dest"
}

# === --apply: update build artifact (dist/iona-disk.img) ====================
if [ "${1:-}" = "--apply" ]; then
  ZIP="${2:-}"; [ -f "$ZIP" ] || die "Zip not found: $ZIP"
  log "Applying update into dist/iona-disk.img from $ZIP..."
  [ -f "$DIST/iona-disk.img" ] || die "dist/iona-disk.img missing"
  TMP=$(mktemp -d)
  unzip -q "$ZIP" -d "$TMP"
  APPLIED=0
  while IFS= read -r payload; do
    [ -n "$payload" ] || continue
    log "  Installing $(basename "$payload") into artifact image..."
    install_payload_to_ionafs "$DIST/iona-disk.img" "$payload"
    APPLIED=$((APPLIED+1))
  done < <(find_update_payloads "$TMP")
  rm -rf "$TMP"
  ok "Update payload applied to dist/iona-disk.img ($APPLIED binaries)"
  exit 0
fi

# === --live: update installed system (preserves user data) ==================
if [ "${1:-}" = "--live" ]; then
  TARGET="${2:-}"; [ -n "$TARGET" ] || usage
  [ -b "$TARGET" ] || die "$TARGET is not a block device"
  ZIP="${3:-}"  # optional zip with userspace binaries

  ESP_PART=$(part_path "$TARGET" 1)
  DATA_PART=$(part_path "$TARGET" 2)

  [ -b "$ESP_PART" ] || die "ESP partition not found: $ESP_PART"

  log "Live update on $TARGET..."
  lsblk "$TARGET" || true
  read -r -p "This will update kernel and binaries on $TARGET. User data is preserved. Continue? [y/N] " yn
  [ "$yn" = "y" ] || { log "Aborted."; exit 0; }

  # Step 1: Update kernel on ESP
  log "[1/3] Updating kernel on ESP ($ESP_PART)..."
  ESP_MNT=$(mktemp -d)
  mount "$ESP_PART" "$ESP_MNT" || die "Cannot mount ESP: $ESP_PART"
  trap "umount '$ESP_MNT' 2>/dev/null; rmdir '$ESP_MNT' 2>/dev/null" EXIT

  if [ -f "$DIST/iona-os-kernel.elf" ]; then
    # Backup old kernel
    if [ -f "$ESP_MNT/EFI/IONA/kernel.elf" ]; then
      cp "$ESP_MNT/EFI/IONA/kernel.elf" "$ESP_MNT/EFI/IONA/kernel.elf.bak"
      log "  Backed up old kernel to kernel.elf.bak"
    fi
    cp "$DIST/iona-os-kernel.elf" "$ESP_MNT/EFI/IONA/kernel.elf"
    ok "  Kernel updated"
  else
    fail "  Kernel ELF not found in dist/ — skipping kernel update"
  fi

  # Update BOOTX64.EFI if available
  if [ -f "$DIST/BOOTX64.EFI" ]; then
    cp "$DIST/BOOTX64.EFI" "$ESP_MNT/EFI/BOOT/BOOTX64.EFI"
    ok "  BOOTX64.EFI updated"
  fi

  umount "$ESP_MNT"
  rmdir "$ESP_MNT" 2>/dev/null || true
  trap - EXIT

  # Step 2: Update userspace binaries on IONAFS partition
  log "[2/3] Updating userspace binaries on IONAFS ($DATA_PART)..."
  if [ -n "$ZIP" ] && [ -f "$ZIP" ]; then
    TMP=$(mktemp -d)
    unzip -q "$ZIP" -d "$TMP"
    APPLIED=0
    while IFS= read -r payload; do
      [ -n "$payload" ] || continue
      log "  Installing $(basename "$payload") into live IONAFS..."
      install_payload_to_ionafs "$DATA_PART" "$payload"
      APPLIED=$((APPLIED+1))
    done < <(find_update_payloads "$TMP")
    rm -rf "$TMP"
    ok "  $APPLIED userspace binaries updated"
  elif [ -b "$DATA_PART" ]; then
    # Install from build artifacts if available
    FOUND=0
    while IFS= read -r elf; do
      [ -n "$elf" ] || continue
      fname=$(basename "$elf")
      log "  Installing /bin/$fname..."
      python3 "$SDIR/install-to-ionafs.py" --disk "$DATA_PART" --file "$elf" --path "/bin/$fname"
      FOUND=$((FOUND+1))
    done < <(find_userspace_bins "$ROOT_DIR/userspace")
    [ $FOUND -gt 0 ] && ok "  $FOUND binaries installed from build" || log "  No userspace binaries to install"
  else
    fail "  IONAFS partition not found: $DATA_PART — skipping userspace update"
  fi

  # Step 3: Write update metadata
  log "[3/3] Writing update metadata..."
  UPDATE_META=$(mktemp)
  cat > "$UPDATE_META" <<META
{"updated_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","version":"0.6.0","type":"live-update"}
META
  if [ -b "$DATA_PART" ]; then
    python3 "$SDIR/install-to-ionafs.py" --disk "$DATA_PART" --file "$UPDATE_META" --path /etc/last-update.json || true
  fi
  rm -f "$UPDATE_META"

  sync
  ok "Live update complete. Reboot to apply."
  exit 0
fi

# === Fresh install to block device (DESTRUCTIVE) ===========================
TARGET="${1:-}"; [ -n "$TARGET" ] || usage
[ -b "$TARGET" ] || die "$TARGET is not a block device"
mount | grep -q "^$TARGET\| $TARGET" && die "$TARGET is mounted"
[ -f "$DIST/iona-uefi.img" ] || "$ROOT_DIR/build-all.sh"
log "Installing to $TARGET..."
lsblk "$TARGET" || true
read -r -p "ALL data on $TARGET will be erased. Continue? [y/N] " yn
[ "$yn" = "y" ] || { log "Aborted."; exit 0; }
log "[1/4] Writing UEFI image..."
dd if="$DIST/iona-uefi.img" of="$TARGET" bs=4M status=progress oflag=sync
PART2=$(part_path "$TARGET" 2)
log "[2/4] Writing IONAFS image to $PART2..."
if [ -f "$DIST/iona-disk.img" ] && [ -b "$PART2" ]; then
  dd if="$DIST/iona-disk.img" of="$PART2" bs=4M status=progress oflag=sync
else
  fail "Partition 2 not detected; skipping IONAFS write"
fi
log "[3/4] Installing initial config into IONAFS..."
TMP=$(mktemp)
cat > "$TMP" <<CONF
{"validator_id":0,"gossip_port":9000,"admin_port":7777,"peers":[],"first_boot":true,"installed_at":"$(date -u +%Y-%m-%dT%H:%M:%SZ)"}
CONF
if [ -b "$PART2" ]; then
  python3 "$SDIR/install-to-ionafs.py" --disk "$PART2" --file "$TMP" --path /etc/iona-node.json || true
else
  python3 "$SDIR/install-to-ionafs.py" --disk "$DIST/iona-disk.img" --file "$TMP" --path /etc/iona-node.json || true
fi
rm -f "$TMP"
if [ -f "$DIST/release-manifest.json" ]; then
  python3 "$SDIR/install-to-ionafs.py" --disk "$PART2" --file "$DIST/release-manifest.json" --path /etc/iona-artifacts.json || true
fi
log "[4/4] Sync..."
sync
ok "Installation complete. Remove install media and reboot."
