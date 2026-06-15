#!/usr/bin/env bash
# =============================================================================
# build-uefi.sh — UEFI image builder for IONA OS
#
# IMPORTANT: IONA OS kernel uses the "bootloader" crate (bootloader_api),
# NOT multiboot2/GRUB. The RECOMMENDED boot path is:
#
#   ./scripts/gen-disk-images.sh <kernel-elf> dist/
#
# This script (build-uefi.sh) attempts to create a UEFI image using the
# bootloader crate output first, then falls back to GRUB as the EFI loader.
# The GRUB grub.cfg here does NOT work with the kernel (wrong boot protocol).
# This script is kept for reference and for machines that need GRUB's EFI stub.
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
#
# Usage:
#   ./scripts/build-uefi.sh [OPTIONS]
#
# Options:
#   --output FILE       Output image path (default: dist/iona-uefi.img)
#   --kernel FILE       Kernel ELF path (default: dist/iona-os-kernel.elf)
#   --size-mb MB        Total image size in MiB (default: 256)
#   --esp-size-mb MB    ESP partition size in MiB (default: 64)
#   --no-clean          Keep temporary files
#   --verbose           Verbose output
#   --help, -h          Show this help message
#
# Environment variables:
#   IONA_VERBOSE        Set to 1 for verbose output
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# Constants & defaults
# -----------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(dirname "$SCRIPT_DIR")"
readonly DEFAULT_OUTPUT="$ROOT_DIR/dist/iona-uefi.img"
readonly DEFAULT_KERNEL="$ROOT_DIR/dist/iona-os-kernel.elf"
readonly DEFAULT_SIZE_MB=256
readonly DEFAULT_ESP_SIZE_MB=64
readonly ESP_FS_LABEL="IONA_EFI"

# -----------------------------------------------------------------------------
# Colours (only if stdout is a terminal)
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly RED='\033[0;31m'
    readonly NC='\033[0m'
else
    readonly GREEN=''
    readonly YELLOW=''
    readonly RED=''
    readonly NC=''
fi

# -----------------------------------------------------------------------------
# Logging functions
# -----------------------------------------------------------------------------
log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()       { log_error "$*"; exit 1; }

if [[ "${IONA_VERBOSE:-0}" -eq 1 ]]; then
    log_debug() { echo -e "[DEBUG] $*"; }
else
    log_debug() { :; }
fi

# -----------------------------------------------------------------------------
# Help
# -----------------------------------------------------------------------------
show_help() {
    sed -n '2,/^$/p' "$0" | sed 's/^# //'
    exit 0
}

# -----------------------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------------------
OUTPUT="$DEFAULT_OUTPUT"
KERNEL="$DEFAULT_KERNEL"
SIZE_MB="$DEFAULT_SIZE_MB"
ESP_SIZE_MB="$DEFAULT_ESP_SIZE_MB"
NO_CLEAN=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            if [[ -z "${2:-}" ]]; then die "--output requires an argument"; fi
            OUTPUT="$2"
            shift 2
            ;;
        --kernel)
            if [[ -z "${2:-}" ]]; then die "--kernel requires an argument"; fi
            KERNEL="$2"
            shift 2
            ;;
        --size-mb)
            if [[ -z "${2:-}" ]]; then die "--size-mb requires an argument"; fi
            SIZE_MB="$2"
            shift 2
            ;;
        --esp-size-mb)
            if [[ -z "${2:-}" ]]; then die "--esp-size-mb requires an argument"; fi
            ESP_SIZE_MB="$2"
            shift 2
            ;;
        --no-clean)
            NO_CLEAN=1
            shift
            ;;
        --verbose)
            VERBOSE=1
            IONA_VERBOSE=1
            shift
            ;;
        --help|-h)
            show_help
            ;;
        -*)
            die "Unknown option: $1"
            ;;
        *)
            die "Unexpected positional argument: $1"
            ;;
    esac
done

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
check_deps() {
    if [[ ! -f "$KERNEL" ]]; then
        die "Kernel ELF not found: $KERNEL. Build kernel first."
    fi
    for tool in dd mkdosfs mmd mcopy; do
        if ! command -v "$tool" &>/dev/null; then
            die "Required tool '$tool' not found. Install: sudo apt install mtools dosfstools"
        fi
    done
}

# -----------------------------------------------------------------------------
# Method 1: Use bootloader crate output (recommended)
# -----------------------------------------------------------------------------
use_bootloader_crate() {
    local gen_uefi="$ROOT_DIR/target/x86_64-unknown-none/release/build/iona-uefi.img"
    if [[ -f "$gen_uefi" && "$gen_uefi" -nt "$KERNEL" ]]; then
        log_info "Using UEFI image from gen-disk-images.sh (bootloader crate — self-contained)"
        cp "$gen_uefi" "$OUTPUT"
        log_info "UEFI image created: $OUTPUT (via bootloader crate)"
        return 0
    fi
    return 1
}

# -----------------------------------------------------------------------------
# Method 2: Build GRUB standalone EFI binary
# -----------------------------------------------------------------------------
build_grub_standalone() {
    local bootefi="$ROOT_DIR/dist/BOOTX64.EFI"
    if [[ -f "$bootefi" ]]; then
        log_info "Using pre-built BOOTX64.EFI from dist/"
        echo "$bootefi"
        return 0
    fi

    if ! command -v grub-mkstandalone &>/dev/null; then
        log_debug "grub-mkstandalone not installed"
        return 1
    fi

    log_info "Building BOOTX64.EFI via grub-mkstandalone..."
    local grub_cfg_tmp
    grub_cfg_tmp="$(mktemp)"
    cat > "$grub_cfg_tmp" <<'GRUB_CFG'
search --no-floppy --set=root --label IONA_EFI
set prefix=($root)/EFI/IONA
configfile $prefix/grub.cfg
GRUB_CFG
    if grub-mkstandalone \
        --format=x86_64-efi \
        --output="$bootefi" \
        --locales="" --fonts="" \
        "boot/grub/grub.cfg=$grub_cfg_tmp" 2>/dev/null; then
        log_info "GRUB UEFI binary built successfully"
        rm -f "$grub_cfg_tmp"
        echo "$bootefi"
        return 0
    fi
    rm -f "$grub_cfg_tmp"
    return 1
}

# -----------------------------------------------------------------------------
# Method 3: Pre-placed dist/BOOTX64.EFI (already checked in build_grub_standalone)
# Method 4: Host fallback (last resort)
# -----------------------------------------------------------------------------
find_host_efi() {
    local candidates=(
        /usr/lib/grub/x86_64-efi/monolithic/grubx64.efi
        /boot/efi/EFI/BOOT/BOOTX64.EFI
        /usr/share/OVMF/BOOTX64.EFI
        /usr/share/edk2/ovmf/BOOTX64.EFI
    )
    for cand in "${candidates[@]}"; do
        if [[ -f "$cand" ]]; then
            log_warn "Using host EFI binary ($cand) — build is NOT self-contained."
            log_warn "Install grub-efi-amd64-bin for a self-contained build:"
            log_warn "  sudo apt install grub-efi-amd64-bin"
            echo "$cand"
            return 0
        fi
    done
    return 1
}

# -----------------------------------------------------------------------------
# Create GPT UEFI disk image with ESP partition
# -----------------------------------------------------------------------------
create_uefi_image() {
    local output="$1"
    local kernel="$2"
    local bootefi="$3"
    local size_mb="$4"
    local esp_mb="$5"

    log_info "Building UEFI disk image ${size_mb}MiB..."
    dd if=/dev/zero of="$output" bs=1M count="$size_mb" status=progress 2>&1 || die "dd failed"

    # Create GPT partition table (if sgdisk available)
    if command -v sgdisk &>/dev/null; then
        sgdisk -Z "$output" >/dev/null 2>&1 || true
        sgdisk -n "1:2048:$((esp_mb * 2048 + 2047))" -t 1:ef00 -c 1:"EFI" \
               -n "2:0:0" -t 2:8300 -c 2:"IONA" "$output" >/dev/null
    else
        log_warn "sgdisk not found — partition table not created, image may not be bootable"
        log_warn "Install: sudo apt install gdisk"
    fi

    # Create FAT32 ESP image
    local fat_img
    fat_img="$(mktemp)"
    if [[ $NO_CLEAN -eq 0 ]]; then
        trap 'rm -f "$fat_img"' EXIT INT TERM
    else
        log_info "Temporary FAT image kept: $fat_img"
    fi

    dd if=/dev/zero of="$fat_img" bs=1M count="$esp_mb" status=none
    mkdosfs -F 32 -n "$ESP_FS_LABEL" "$fat_img" >/dev/null || die "mkdosfs failed"

    export MTOOLS_SKIP_CHECK=1
    mmd -i "$fat_img" ::/EFI ::/EFI/BOOT ::/EFI/IONA >/dev/null 2>&1 || true

    # Copy kernel
    mcopy -i "$fat_img" "$kernel" ::/EFI/IONA/kernel.elf >/dev/null || die "mcopy kernel failed"

    # Copy bootloader
    mcopy -i "$fat_img" "$bootefi" ::/EFI/BOOT/BOOTX64.EFI >/dev/null || die "mcopy bootloader failed"

    # Write a simple boot.conf (for custom loaders)
    local boot_conf
    boot_conf="$(mktemp)"
    echo "kernel=EFI/IONA/kernel.elf" > "$boot_conf"
    echo "root=ionafs" >> "$boot_conf"
    mcopy -i "$fat_img" "$boot_conf" ::/EFI/IONA/boot.conf >/dev/null
    rm -f "$boot_conf"

    # Write a legacy grub.cfg (warning only)
    local grub_cfg
    grub_cfg="$(mktemp)"
    cat > "$grub_cfg" <<'GRUB_CFG'
set timeout=3
menuentry "IONA OS v0.6.0 (legacy — use gen-disk-images.sh)" {
    echo "ERROR: Use gen-disk-images.sh to create a compatible boot image."
    sleep 5
}
GRUB_CFG
    mcopy -i "$fat_img" "$grub_cfg" ::/EFI/IONA/grub.cfg >/dev/null
    rm -f "$grub_cfg"

    # Write FAT image to output at sector 2048 (if partition table present)
    dd if="$fat_img" of="$output" bs=512 seek=2048 conv=notrunc status=none || die "dd write failed"
    rm -f "$fat_img"

    log_info "UEFI image created: $output"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    check_deps

    # Priority 1: bootloader crate
    if use_bootloader_crate; then
        exit 0
    fi

    # Priority 2 & 3: GRUB standalone or pre-placed
    local bootefi
    if bootefi="$(build_grub_standalone)"; then
        :
    elif [[ -f "$ROOT_DIR/dist/BOOTX64.EFI" ]]; then
        bootefi="$ROOT_DIR/dist/BOOTX64.EFI"
        log_info "Using pre-placed BOOTX64.EFI from dist/"
    elif bootefi="$(find_host_efi)"; then
        :
    else
        die "BOOTX64.EFI not found and cannot be built.
To fix, do ONE of:
  1. Run gen-disk-images.sh first (uses bootloader crate — no host deps)
  2. Install grub: sudo apt install grub-efi-amd64-bin
  3. Place a BOOTX64.EFI manually in dist/"
    fi

    create_uefi_image "$OUTPUT" "$KERNEL" "$bootefi" "$SIZE_MB" "$ESP_SIZE_MB"
}

main "$@"
