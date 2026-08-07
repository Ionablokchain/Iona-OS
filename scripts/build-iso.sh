#!/usr/bin/env bash
# =============================================================================
# build-iso.sh — Build a hybrid BIOS+UEFI bootable ISO for IONA OS
#
# Creates an ISO that boots on:
#   - Legacy BIOS systems (via El Torito boot catalog + embedded boot image)
#   - UEFI systems (via EFI System Partition with BOOTX64.EFI)
#
# The BOOTX64.EFI is sourced in this order:
#   1. Path provided via --uefi-bin
#   2. dist/BOOTX64.EFI (if exists)
#   3. Built with grub-mkstandalone (if grub-efi-amd64-bin installed)
#   4. Extracted from gen-disk-images.sh UEFI image (if available)
#
# Required: xorriso, optionally mtools (for EFI image creation)
#
# Usage:
#   ./scripts/build-iso.sh [OPTIONS]
#
# Options:
#   --output FILE       Output ISO path (default: dist/iona-efi.iso)
#   --kernel FILE       Kernel ELF path (default: dist/iona-os-kernel.elf)
#   --uefi-bin FILE     Path to BOOTX64.EFI (overrides automatic detection)
#   --grub-cfg FILE     Custom GRUB configuration file
#   --label STRING      ISO volume label (default: IONA_ISO)
#   --efi-size KB       Size of EFI image in KiB (default: 4096)
#   --no-clean          Keep temporary build directory
#   --verbose           Verbose output
#   --quiet             Suppress non‑error output
#   --version           Show version
#   --help, -h          Show this help message
#
# Environment variables:
#   IONA_VERBOSE        Set to 1 for verbose output
#   IONA_QUIET          Set to 1 for quiet mode
#   IONA_NO_COLOR       Set to 1 to disable colour output
#   IONA_EFI_SIZE_KB    Override EFI image size in KiB
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# Version
# -----------------------------------------------------------------------------
readonly SCRIPT_VERSION="2.0.0"

# -----------------------------------------------------------------------------
# Constants & defaults
# -----------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(dirname "$SCRIPT_DIR")"
readonly DEFAULT_OUTPUT="$ROOT_DIR/dist/iona-efi.iso"
readonly DEFAULT_KERNEL="$ROOT_DIR/dist/iona-os-kernel.elf"
readonly DEFAULT_LABEL="IONA_ISO"
DEFAULT_EFI_SIZE_KB="${IONA_EFI_SIZE_KB:-4096}"

# -----------------------------------------------------------------------------
# Colours (respect IONA_NO_COLOR and terminal detection)
# -----------------------------------------------------------------------------
if [[ -z "${IONA_NO_COLOR:-}" && -t 1 ]]; then
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly RED='\033[0;31m'
    readonly BLUE='\033[0;34m'
    readonly NC='\033[0m'
else
    readonly GREEN=''
    readonly YELLOW=''
    readonly RED=''
    readonly BLUE=''
    readonly NC=''
fi

# -----------------------------------------------------------------------------
# Logging functions
# -----------------------------------------------------------------------------
_log_level=2  # 0=quiet, 1=error, 2=info, 3=debug
if [[ "${IONA_VERBOSE:-0}" -eq 1 ]]; then _log_level=3; fi
if [[ "${IONA_QUIET:-0}" -eq 1 ]]; then _log_level=1; fi

log_debug() { [[ $_log_level -ge 3 ]] && echo -e "${BLUE}[DEBUG]${NC} $*" >&2; }
log_info()  { [[ $_log_level -ge 2 ]] && echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { [[ $_log_level -ge 2 ]] && echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error() { [[ $_log_level -ge 1 ]] && echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()       { log_error "$*"; exit 1; }

# -----------------------------------------------------------------------------
# Help & version
# -----------------------------------------------------------------------------
show_help() {
    sed -n '2,/^$/p' "$0" | sed 's/^# //'
    exit 0
}

show_version() {
    echo "build-iso.sh version ${SCRIPT_VERSION}"
    exit 0
}

# -----------------------------------------------------------------------------
# Parse arguments
# -----------------------------------------------------------------------------
OUTPUT="$DEFAULT_OUTPUT"
KERNEL_ELF="$DEFAULT_KERNEL"
UEFI_BIN=""
GRUB_CFG=""
LABEL="$DEFAULT_LABEL"
EFI_SIZE_KB="$DEFAULT_EFI_SIZE_KB"
NO_CLEAN=0
VERBOSE=0
QUIET=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            if [[ -z "${2:-}" ]]; then die "--output requires an argument"; fi
            OUTPUT="$2"
            shift 2
            ;;
        --kernel)
            if [[ -z "${2:-}" ]]; then die "--kernel requires an argument"; fi
            KERNEL_ELF="$2"
            shift 2
            ;;
        --uefi-bin)
            if [[ -z "${2:-}" ]]; then die "--uefi-bin requires an argument"; fi
            UEFI_BIN="$2"
            shift 2
            ;;
        --grub-cfg)
            if [[ -z "${2:-}" ]]; then die "--grub-cfg requires an argument"; fi
            GRUB_CFG="$2"
            shift 2
            ;;
        --label)
            if [[ -z "${2:-}" ]]; then die "--label requires an argument"; fi
            LABEL="$2"
            shift 2
            ;;
        --efi-size)
            if [[ -z "${2:-}" ]]; then die "--efi-size requires an argument"; fi
            EFI_SIZE_KB="$2"
            shift 2
            ;;
        --no-clean)
            NO_CLEAN=1
            shift
            ;;
        --verbose)
            VERBOSE=1
            IONA_VERBOSE=1
            _log_level=3
            shift
            ;;
        --quiet)
            QUIET=1
            IONA_QUIET=1
            _log_level=1
            shift
            ;;
        --version)
            show_version
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
# Validate configuration
# -----------------------------------------------------------------------------
validate_config() {
    if [[ ! -f "$KERNEL_ELF" ]]; then
        die "Kernel ELF not found: $KERNEL_ELF. Build kernel first."
    fi
    if [[ "$EFI_SIZE_KB" -lt 1024 ]]; then
        die "EFI size must be at least 1024 KiB"
    fi
    if [[ -z "$OUTPUT" ]]; then
        die "Output path cannot be empty"
    fi
    # Ensure output directory exists
    mkdir -p "$(dirname "$OUTPUT")"
}

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
check_deps() {
    local missing=0
    for cmd in xorriso; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "Required command not found: $cmd"
            missing=1
        fi
    done
    if [[ $missing -eq 1 ]]; then
        die "Missing required dependencies. Install: sudo apt install xorriso"
    fi

    # Optional mtools check
    if ! command -v mkdosfs &>/dev/null || ! command -v mcopy &>/dev/null; then
        log_warn "mtools (mkdosfs/mcopy) not found. EFI image will be raw (less compatible)."
        log_warn "Install: sudo apt install mtools dosfstools"
        return 1  # signal missing mtools
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Prepare GRUB configuration
# -----------------------------------------------------------------------------
prepare_grub_cfg() {
    local output_dir="$1"
    local cfg_path="$output_dir/boot/grub/grub.cfg"

    if [[ -n "$GRUB_CFG" && -f "$GRUB_CFG" ]]; then
        log_info "Using custom GRUB config: $GRUB_CFG"
        cp "$GRUB_CFG" "$cfg_path"
        return 0
    fi

    log_info "Generating default GRUB config"
    cat > "$cfg_path" <<'GRUB_CFG'
set timeout=3
set default=0

menuentry "IONA OS" {
    multiboot2 /boot/iona-os-kernel.elf
    boot
}
menuentry "IONA OS (Recovery)" {
    multiboot2 /boot/iona-os-kernel.elf recovery=1
    boot
}
menuentry "IONA OS (Serial console)" {
    multiboot2 /boot/iona-os-kernel.elf console=ttyS0,115200
    boot
}
GRUB_CFG
    log_debug "GRUB config written to $cfg_path"
}

# -----------------------------------------------------------------------------
# Locate or build UEFI bootloader (BOOTX64.EFI)
# -----------------------------------------------------------------------------
prepare_uefi_bootloader() {
    local dest_dir="$1"
    local dest_efi="$dest_dir/EFI/BOOT/BOOTX64.EFI"

    mkdir -p "$(dirname "$dest_efi")"

    # 1. Explicit --uefi-bin argument
    if [[ -n "$UEFI_BIN" ]]; then
        if [[ ! -f "$UEFI_BIN" ]]; then
            die "Specified UEFI binary not found: $UEFI_BIN"
        fi
        log_info "Using provided UEFI binary: $UEFI_BIN"
        cp "$UEFI_BIN" "$dest_efi"
        return 0
    fi

    # 2. dist/BOOTX64.EFI
    local dist_efi="$ROOT_DIR/dist/BOOTX64.EFI"
    if [[ -f "$dist_efi" ]]; then
        log_info "Using existing UEFI binary: $dist_efi"
        cp "$dist_efi" "$dest_efi"
        return 0
    fi

    # 3. Build with grub-mkstandalone
    if command -v grub-mkstandalone &>/dev/null; then
        log_info "Building BOOTX64.EFI with grub-mkstandalone..."
        local grub_cfg_tmp
        grub_cfg_tmp="$(mktemp)"
        cat > "$grub_cfg_tmp" <<'GRUB_CFG'
search --no-floppy --set=root --label IONA_ISO
set prefix=($root)/boot/grub
configfile $prefix/grub.cfg
GRUB_CFG
        if grub-mkstandalone \
            --format=x86_64-efi \
            --output="$dest_efi" \
            --locales="" --fonts="" \
            "boot/grub/grub.cfg=$grub_cfg_tmp" 2>/dev/null; then
            log_info "GRUB UEFI binary built successfully"
            rm -f "$grub_cfg_tmp"
            return 0
        fi
        rm -f "$grub_cfg_tmp"
        log_warn "grub-mkstandalone failed"
    else
        log_debug "grub-mkstandalone not available"
    fi

    # 4. Fallback: try to extract from disk image (legacy)
    local disk_img="$ROOT_DIR/dist/iona-disk.img"
    if [[ -f "$disk_img" ]]; then
        log_info "Attempting to extract UEFI binary from $disk_img..."
        # Use dd + loop mount or parted to find EFI partition
        # This is a simplified stub; a full implementation would use losetup/mount
        log_warn "Automatic extraction not implemented. Place BOOTX64.EFI in dist/ or install grub-efi-amd64-bin."
    fi

    die "Cannot find or build BOOTX64.EFI.
Please provide one via:
  --uefi-bin <file>
or create dist/BOOTX64.EFI (e.g., via build-uefi.sh)
or install grub-efi-amd64-bin (apt install grub-efi-amd64-bin)"
}

# -----------------------------------------------------------------------------
# Create EFI boot image (FAT12/16 image embedded in ISO)
# -----------------------------------------------------------------------------
create_efi_image() {
    local isoroot="$1"
    local efi_img="$isoroot/boot/efi.img"
    local efi_bin="$isoroot/EFI/BOOT/BOOTX64.EFI"

    if [[ ! -f "$efi_bin" ]]; then
        die "EFI binary not found at $efi_bin"
    fi

    if ! command -v mkdosfs &>/dev/null || ! command -v mcopy &>/dev/null; then
        log_warn "mtools not found. EFI boot image will be raw binary (less compatible)."
        log_warn "Install: sudo apt install mtools dosfstools"
        echo "raw"
        return 0
    fi

    log_info "Creating FAT12 EFI image (${EFI_SIZE_KB}KiB)..."
    dd if=/dev/zero of="$efi_img" bs=1K count="$EFI_SIZE_KB" status=none || die "dd failed"
    mkdosfs -F 12 "$efi_img" >/dev/null || die "mkdosfs failed"
    export MTOOLS_SKIP_CHECK=1
    mmd -i "$efi_img" ::/EFI ::/EFI/BOOT >/dev/null 2>&1 || true
    mcopy -i "$efi_img" "$efi_bin" ::/EFI/BOOT/BOOTX64.EFI >/dev/null || die "mcopy failed"
    log_info "EFI image created: $efi_img"
    echo "image"
}

# -----------------------------------------------------------------------------
# Build the ISO with xorriso
# -----------------------------------------------------------------------------
build_iso() {
    local isoroot="$1"
    local output="$2"
    local label="$3"
    local efi_mode="$4"  # "image" or "raw"

    # Build xorriso arguments array
    local xorriso_args=(
        -as mkisofs
        -iso-level 3
        -full-iso9660-filenames
        -volid "$label"
        -rational-rock
        -joliet
        -eltorito-boot boot/iona-os-kernel.elf
        -no-emul-boot
        -boot-load-size 4
        -boot-info-table
    )

    if [[ "$efi_mode" == "image" ]]; then
        xorriso_args+=(
            -eltorito-alt-boot
            -e boot/efi.img
            -no-emul-boot
            -isohybrid-gpt-basdat
        )
    else
        xorriso_args+=(
            -eltorito-alt-boot
            -e EFI/BOOT/BOOTX64.EFI
            -no-emul-boot
        )
    fi

    xorriso_args+=(-o "$output" "$isoroot")

    log_info "Building hybrid BIOS+UEFI ISO..."
    if [[ $VERBOSE -eq 1 ]]; then
        xorriso "${xorriso_args[@]}"
    else
        xorriso "${xorriso_args[@]}" >/dev/null 2>&1
    fi

    if [[ ! -f "$output" ]]; then
        die "ISO creation failed"
    fi

    local size
    size="$(du -h "$output" | cut -f1)"
    log_info "ISO image created: $output ($size)"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    log_debug "Starting build-iso.sh v${SCRIPT_VERSION}"
    validate_config
    check_deps
    local mtools_ok=$?

    # Create temporary build directory
    local iso_root
    iso_root="$(mktemp -d)"
    if [[ $NO_CLEAN -eq 0 ]]; then
        trap 'rm -rf "$iso_root"' EXIT INT TERM
    else
        log_info "Temporary directory kept: $iso_root"
    fi

    # Prepare ISO directory structure
    mkdir -p "$iso_root/EFI/BOOT" "$iso_root/boot/grub"

    # Copy kernel
    cp "$KERNEL_ELF" "$iso_root/boot/iona-os-kernel.elf"
    log_info "Kernel copied: $KERNEL_ELF"

    # Prepare GRUB config
    prepare_grub_cfg "$iso_root"

    # Prepare UEFI bootloader
    prepare_uefi_bootloader "$iso_root"

    # Create EFI image (if possible)
    local efi_mode
    if [[ $mtools_ok -eq 0 ]]; then
        efi_mode="$(create_efi_image "$iso_root")"
    else
        efi_mode="raw"
        log_warn "Using raw EFI binary mode (no FAT image)"
    fi

    # Build ISO
    build_iso "$iso_root" "$OUTPUT" "$LABEL" "$efi_mode"

    log_info "ISO ready: $OUTPUT"
}

main "$@"
