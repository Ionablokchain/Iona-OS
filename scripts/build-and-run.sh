#!/usr/bin/env bash
# =============================================================================
# IONA OS Build & Run Script — Production‑ready
#
# Builds the IONA OS kernel and launches it in QEMU.
#
# Usage:
#   ./scripts/build-run.sh [OPTIONS] [-- <QEMU_ARGS>...]
#
# Options:
#   --release           Build in release mode (default: debug)
#   --profile <name>    Build with a custom cargo profile (e.g., --profile perf)
#   --no-run            Build only, do not launch QEMU
#   --qemu-args <args>  Additional arguments to pass to QEMU (alternative to --)
#   --help, -h          Show this help message
#
# Environment variables:
#   PROFILE             Build profile (debug|release) – overridden by --release
#   QEMU_BIN            Path to QEMU binary (default: qemu-system-x86_64)
#   IONA_VERBOSE        Set to 1 for verbose logging
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# Constants & defaults
# -----------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(dirname "$SCRIPT_DIR")"
readonly TARGET="x86_64-unknown-none"
readonly DEFAULT_QEMU_BIN="qemu-system-x86_64"

# -----------------------------------------------------------------------------
# Colours (only if stdout is a terminal)
# -----------------------------------------------------------------------------
if [[ -t 1 ]]; then
    readonly RED='\033[0;31m'
    readonly GREEN='\033[0;32m'
    readonly YELLOW='\033[1;33m'
    readonly NC='\033[0m'
else
    readonly RED=''
    readonly GREEN=''
    readonly YELLOW=''
    readonly NC=''
fi

# -----------------------------------------------------------------------------
# Logging functions
# -----------------------------------------------------------------------------
log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*" >&2; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

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
BUILD_PROFILE="debug"
NO_RUN=0
QEMU_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --release)
            BUILD_PROFILE="release"
            shift
            ;;
        --profile)
            if [[ -z "${2:-}" ]]; then
                log_error "--profile requires an argument"
                exit 1
            fi
            BUILD_PROFILE="$2"
            shift 2
            ;;
        --no-run)
            NO_RUN=1
            shift
            ;;
        --qemu-args)
            if [[ -z "${2:-}" ]]; then
                log_error "--qemu-args requires an argument"
                exit 1
            fi
            # Split space-separated args
            read -ra extra <<< "$2"
            QEMU_ARGS+=("${extra[@]}")
            shift 2
            ;;
        --help|-h)
            show_help
            ;;
        --)
            shift
            QEMU_ARGS+=("$@")
            break
            ;;
        -*)
            log_error "Unknown option: $1"
            echo "Try '$0 --help' for more information."
            exit 1
            ;;
        *)
            log_error "Unexpected positional argument: $1"
            exit 1
            ;;
    esac
done

# Override profile from environment if not set by flags
PROFILE="${PROFILE:-$BUILD_PROFILE}"
log_info "Build profile: $PROFILE"

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
check_deps() {
    local missing=0
    if ! command -v cargo &>/dev/null; then
        log_error "cargo not found. Please install Rust: https://rustup.rs/"
        missing=1
    fi
    if [[ $NO_RUN -eq 0 ]]; then
        local qemu_bin="${QEMU_BIN:-$DEFAULT_QEMU_BIN}"
        if ! command -v "$qemu_bin" &>/dev/null; then
            log_error "QEMU not found (tried: $qemu_bin). Please install qemu-system-x86_64"
            missing=1
        fi
    fi
    if [[ ! -x "$SCRIPT_DIR/gen-disk-images.sh" ]]; then
        log_error "Disk image generation script not found or not executable: $SCRIPT_DIR/gen-disk-images.sh"
        missing=1
    fi
    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Cleanup trap (kill QEMU on exit)
# -----------------------------------------------------------------------------
QEMU_PID=""
cleanup() {
    if [[ -n "$QEMU_PID" ]] && kill -0 "$QEMU_PID" 2>/dev/null; then
        log_info "Terminating QEMU (PID $QEMU_PID)..."
        kill "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# -----------------------------------------------------------------------------
# Build kernel
# -----------------------------------------------------------------------------
build_kernel() {
    log_info "Building IONA OS kernel (profile: $PROFILE)..."
    local build_cmd=("cargo" "build")
    if [[ "$PROFILE" == "release" ]]; then
        build_cmd+=("--release")
    elif [[ "$PROFILE" != "debug" ]]; then
        build_cmd+=("--profile" "$PROFILE")
    fi
    if ! "${build_cmd[@]}" 2>&1; then
        log_error "Cargo build failed"
        exit 1
    fi
    local kernel_elf="$ROOT_DIR/target/$TARGET/$PROFILE/iona-os-kernel"
    if [[ ! -f "$kernel_elf" ]]; then
        log_error "Kernel ELF not found at $kernel_elf"
        exit 1
    fi
    log_success "Kernel built: $kernel_elf"
    echo "$kernel_elf"
}

# -----------------------------------------------------------------------------
# Generate disk images
# -----------------------------------------------------------------------------
generate_disks() {
    local kernel_elf="$1"
    local out_dir="$2"
    log_info "Generating disk images in $out_dir..."
    mkdir -p "$out_dir"
    if ! "$SCRIPT_DIR/gen-disk-images.sh" "$kernel_elf" "$out_dir" 2>&1; then
        log_error "Disk image generation failed"
        exit 1
    fi
    log_success "Disk images generated"
}

# -----------------------------------------------------------------------------
# Run QEMU
# -----------------------------------------------------------------------------
run_qemu() {
    local kernel_elf="$1"
    local qemu_bin="${QEMU_BIN:-$DEFAULT_QEMU_BIN}"
    local qemu_args=(
        -kernel "$kernel_elf"
        -serial mon:stdio
        -display none
        -no-reboot
        -machine q35
        -cpu qemu64
        -smp 2
        -m 2G
        -device isa-debug-exit,iobase=0xf4,iosize=0x04
    )
    # Add user-provided arguments
    qemu_args+=("${QEMU_ARGS[@]}")

    log_info "Launching QEMU: $qemu_bin ${qemu_args[*]}"
    "$qemu_bin" "${qemu_args[@]}" &
    QEMU_PID=$!
    wait "$QEMU_PID"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    check_deps
    local kernel_elf
    kernel_elf="$(build_kernel)"
    if [[ $NO_RUN -eq 0 ]]; then
        local build_img_dir="$ROOT_DIR/target/$TARGET/$PROFILE/build"
        generate_disks "$kernel_elf" "$build_img_dir"
        run_qemu "$kernel_elf"
    else
        log_info "Build completed (--no-run). Exiting."
    fi
}

main "$@"
