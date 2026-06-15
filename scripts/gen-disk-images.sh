#!/usr/bin/env bash
# =============================================================================
# Generate BIOS and UEFI disk images from a compiled kernel ELF binary.
#
# Uses the `bootloader` crate (v0.11) to create bootable disk images.
# The builder is cached in `/tmp/iona-disk-image-builder` for faster rebuilds.
#
# Usage:
#   ./scripts/gen-disk-images.sh [OPTIONS] --kernel <kernel-elf> --output-dir <dir>
#
# Options:
#   --kernel FILE       Path to the kernel ELF binary (required)
#   --output-dir DIR    Output directory for disk images (required)
#   --rebuild           Force rebuild of the disk image builder project
#   --verbose           Show verbose output (full cargo output)
#   --help, -h          Show this help message
#
# Environment:
#   IONA_VERBOSE        Set to 1 for verbose output
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# Constants & defaults
# -----------------------------------------------------------------------------
readonly BUILDER_DIR="/tmp/iona-disk-image-builder"
readonly TOOLCHAIN="nightly"
readonly COMPONENTS="llvm-tools-preview"

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
KERNEL_ELF=""
OUT_DIR=""
REBUILD=0
VERBOSE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)
            if [[ -z "${2:-}" ]]; then die "--kernel requires an argument"; fi
            KERNEL_ELF="$2"
            shift 2
            ;;
        --output-dir)
            if [[ -z "${2:-}" ]]; then die "--output-dir requires an argument"; fi
            OUT_DIR="$2"
            shift 2
            ;;
        --rebuild)
            REBUILD=1
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

if [[ -z "$KERNEL_ELF" ]]; then
    die "--kernel is required"
fi
if [[ -z "$OUT_DIR" ]]; then
    die "--output-dir is required"
fi

# Convert to absolute paths
KERNEL_ELF="$(realpath "$KERNEL_ELF" 2>/dev/null || die "Cannot resolve kernel path: $KERNEL_ELF")"
OUT_DIR="$(realpath -m "$OUT_DIR")"

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
check_deps() {
    for cmd in cargo rustup realpath; do
        if ! command -v "$cmd" &>/dev/null; then
            die "Required command not found: $cmd"
        fi
    done

    if [[ ! -f "$KERNEL_ELF" ]]; then
        die "Kernel binary not found: $KERNEL_ELF"
    fi

    # Ensure nightly toolchain with required components
    if ! rustup toolchain list | grep -q "$TOOLCHAIN"; then
        log_info "Installing $TOOLCHAIN toolchain..."
        rustup toolchain install "$TOOLCHAIN"
    fi
    if ! rustup component list --toolchain "$TOOLCHAIN" | grep -q "$COMPONENTS.*installed"; then
        log_info "Adding $COMPONENTS component to $TOOLCHAIN..."
        rustup component add --toolchain "$TOOLCHAIN" "$COMPONENTS"
    fi
}

# -----------------------------------------------------------------------------
# Prepare builder project
# -----------------------------------------------------------------------------
prepare_builder() {
    if [[ $REBUILD -eq 1 ]] && [[ -d "$BUILDER_DIR" ]]; then
        log_info "Removing existing builder directory (--rebuild)..."
        rm -rf "$BUILDER_DIR"
    fi

    if [[ -d "$BUILDER_DIR" ]]; then
        log_info "Using cached builder project in $BUILDER_DIR"
        return 0
    fi

    log_info "Creating disk image builder project in $BUILDER_DIR..."

    mkdir -p "$BUILDER_DIR/src"

    cat > "$BUILDER_DIR/Cargo.toml" <<'TOML'
[package]
name = "disk-image-builder"
version = "0.1.0"
edition = "2021"

[dependencies]
bootloader = { version = "0.11", features = ["uefi", "bios"] }
TOML

    cat > "$BUILDER_DIR/src/main.rs" <<'RUST'
use std::{env, path::PathBuf, process};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: disk-image-builder <kernel-binary> <output-dir>");
        process::exit(1);
    }
    let kernel_path = PathBuf::from(&args[1]);
    let out_dir = PathBuf::from(&args[2]);

    if !kernel_path.exists() {
        eprintln!("Error: kernel binary not found: {}", kernel_path.display());
        process::exit(1);
    }
    std::fs::create_dir_all(&out_dir).expect("failed to create output directory");

    let bios_path = out_dir.join("iona-bios.img");
    println!("Creating BIOS image: {}", bios_path.display());
    bootloader::BiosBoot::new(&kernel_path)
        .create_disk_image(&bios_path)
        .expect("BIOS disk image creation failed");
    println!("  OK: {}", bios_path.display());

    let uefi_path = out_dir.join("iona-uefi.img");
    println!("Creating UEFI image: {}", uefi_path.display());
    bootloader::UefiBoot::new(&kernel_path)
        .create_disk_image(&uefi_path)
        .expect("UEFI disk image creation failed");
    println!("  OK: {}", uefi_path.display());
}
RUST

    cat > "$BUILDER_DIR/rust-toolchain.toml" <<'TOML'
[toolchain]
channel = "nightly"
components = ["llvm-tools-preview"]
TOML

    log_info "Builder project created."
}

# -----------------------------------------------------------------------------
# Run the builder
# -----------------------------------------------------------------------------
run_builder() {
    mkdir -p "$OUT_DIR"

    log_info "Generating disk images in $OUT_DIR..."
    log_info "Kernel: $KERNEL_ELF"

    local cargo_args=("run" "--release" "--" "$KERNEL_ELF" "$OUT_DIR")
    if [[ $VERBOSE -eq 0 ]]; then
        cargo_args+=("2>&1")
    fi

    cd "$BUILDER_DIR"
    if [[ $VERBOSE -eq 1 ]]; then
        cargo "${cargo_args[@]}"
    else
        local output
        output="$(cargo "${cargo_args[@]}" 2>&1)" || {
            log_error "Builder failed. Run with --verbose for details."
            die "$output"
        }
        log_info "BIOS image: $OUT_DIR/iona-bios.img"
        log_info "UEFI image: $OUT_DIR/iona-uefi.img"
    fi
    cd - >/dev/null
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    check_deps
    prepare_builder
    run_builder
    log_info "Done."
}

main "$@"
