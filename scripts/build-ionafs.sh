#!/usr/bin/env bash
# =============================================================================
# IONA OS disk image builder — Production‑ready
#
# Creates an IONA filesystem (IONAFS) disk image with kernel, userspace binaries,
# configuration files, and runtime directories.
#
# Build modes:
#   normal (default):   non‑critical failures are logged as warnings
#   strict (--strict):  any inject failure aborts the build (for CI/release)
#
# Usage:
#   ./scripts/build-ionafs.sh [OPTIONS]
#
# Options:
#   --strict            Enable strict mode (fail on any inject error)
#   --output FILE       Output disk image path (default: ./dist/iona-disk.img)
#   --size MB           Disk image size in MiB (default: 256)
#   --no-clean          Do not remove existing image before building
#   --only-bin          Only build userspace binaries, skip disk image creation
#   --help, -h          Show this help message
#
# Environment variables:
#   IONA_BUILD_MODE     Set to "prod" to enable strict mode (equivalent to --strict)
#   IONA_VERBOSE        Set to 1 for verbose output
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# Constants & defaults
# -----------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(dirname "$SCRIPT_DIR")"
readonly DEFAULT_OUTPUT="$ROOT_DIR/dist/iona-disk.img"
readonly DEFAULT_SIZE_MB=256
readonly SUPERBLOCK_MAGIC="IONA"

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
STRICT_BUILD=0
OUTPUT="$DEFAULT_OUTPUT"
SIZE_MB="$DEFAULT_SIZE_MB"
NO_CLEAN=0
ONLY_BIN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --strict)
            STRICT_BUILD=1
            shift
            ;;
        --output)
            if [[ -z "${2:-}" ]]; then
                die "--output requires an argument"
            fi
            OUTPUT="$2"
            shift 2
            ;;
        --size)
            if [[ -z "${2:-}" ]]; then
                die "--size requires an argument"
            fi
            SIZE_MB="$2"
            shift 2
            ;;
        --no-clean)
            NO_CLEAN=1
            shift
            ;;
        --only-bin)
            ONLY_BIN=1
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

# Override strict mode from environment
if [[ "${IONA_BUILD_MODE:-dev}" == "prod" ]]; then
    STRICT_BUILD=1
    log_info "Strict mode enabled (IONA_BUILD_MODE=prod)"
fi

# -----------------------------------------------------------------------------
# Dependency checks
# -----------------------------------------------------------------------------
check_deps() {
    local missing=0
    for cmd in dd python3 xxd cargo; do
        if ! command -v "$cmd" &>/dev/null; then
            log_error "Missing required command: $cmd"
            missing=1
        fi
    done
    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Create blank disk image with superblock
# -----------------------------------------------------------------------------
create_disk_image() {
    local output="$1"
    local size_mb="$2"
    local out_dir
    out_dir="$(dirname "$output")"
    mkdir -p "$out_dir"

    if [[ -f "$output" && $NO_CLEAN -eq 0 ]]; then
        log_info "Removing existing image: $output"
        rm -f "$output"
    fi

    log_info "Creating ${size_mb}MiB disk image at $output"
    dd if=/dev/zero of="$output" bs=1M count="$size_mb" status=progress 2>&1 || die "dd failed"

    # Write superblock (magic + version + padding)
    python3 -c "
import sys, struct
with open(sys.argv[1], 'r+b') as f:
    f.seek(0)
    f.write(b'$SUPERBLOCK_MAGIC')
    f.write(struct.pack('<I', 0))   # version 0
    f.write(b'\x00' * 504)          # padding to 512 bytes
    print('Superblock written')
" "$output" || die "Failed to write superblock"

    log_info "Disk image created"
}

# -----------------------------------------------------------------------------
# Inject a file into IONAFS (non‑fatal)
# -----------------------------------------------------------------------------
inject_file() {
    local dest_path="$1"
    local content="$2"
    local tmp
    tmp="$(mktemp)"
    printf '%s' "$content" > "$tmp"

    if python3 "$SCRIPT_DIR/install-to-ionafs.py" \
        --disk "$OUTPUT" \
        --file "$tmp" \
        --path "$dest_path" 2>/dev/null; then
        log_debug "Injected $dest_path"
        rm -f "$tmp"
        return 0
    else
        log_warn "Failed to inject optional file: $dest_path"
        rm -f "$tmp"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Inject a required file (fails in strict mode)
# -----------------------------------------------------------------------------
inject_required() {
    local dest_path="$1"
    local content="$2"
    local tmp
    tmp="$(mktemp)"
    printf '%s' "$content" > "$tmp"

    if python3 "$SCRIPT_DIR/install-to-ionafs.py" \
        --disk "$OUTPUT" \
        --file "$tmp" \
        --path "$dest_path" 2>&1; then
        log_debug "Injected required $dest_path"
        rm -f "$tmp"
        return 0
    else
        log_error "Failed to inject required file: $dest_path"
        rm -f "$tmp"
        if [[ $STRICT_BUILD -eq 1 ]]; then
            die "Strict mode: required file injection failed"
        fi
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Install a binary from build artifacts (looks in multiple locations)
# -----------------------------------------------------------------------------
install_binary() {
    local bin_name="$1"
    shift
    local paths=("$@")
    local found=""
    local elf_path=""

    for cand in "${paths[@]}"; do
        local full="$ROOT_DIR/$cand"
        if [[ -f "$full" ]]; then
            found="$full"
            break
        fi
    done

    if [[ -z "$found" ]]; then
        log_warn "Binary $bin_name not found in any candidate location"
        return 1
    fi

    elf_path="$found"

    # Quick ELF validation (magic bytes)
    local magic
    magic="$(xxd -l 4 -p "$elf_path" 2>/dev/null || echo "")"
    if [[ "$magic" != "7f454c46" ]]; then
        log_error "File $elf_path is not a valid ELF (magic $magic)"
        return 1
    fi

    if python3 "$SCRIPT_DIR/install-to-ionafs.py" \
        --disk "$OUTPUT" \
        --file "$elf_path" \
        --path "/bin/$bin_name" 2>&1; then
        local size
        size="$(du -sh "$elf_path" | cut -f1)"
        log_info "Installed /bin/$bin_name ($size)"
        return 0
    else
        log_error "Failed to inject /bin/$bin_name"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Build a userspace binary if missing
# -----------------------------------------------------------------------------
build_if_missing() {
    local bin_name="$1"
    local crate_path="$2"
    local target_triple="${3:-x86_64-unknown-none}"

    local elf_path="$ROOT_DIR/$crate_path/target/$target_triple/release/$bin_name"
    if [[ -f "$elf_path" ]]; then
        # Already built
        return 0
    fi

    log_info "Building $bin_name (target: $target_triple)..."
    pushd "$ROOT_DIR/$crate_path" >/dev/null
    if cargo build --target "$target_triple" --release 2>&1; then
        log_info "Successfully built $bin_name"
        popd >/dev/null
        return 0
    else
        log_error "Failed to build $bin_name"
        popd >/dev/null
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    check_deps

    if [[ $ONLY_BIN -eq 1 ]]; then
        log_info "Only building userspace binaries (--only-bin)"
        # Build necessary userspace crates
        build_if_missing "iona-node"   "userspace/iona-node"   "x86_64-unknown-none" || \
            build_if_missing "iona-node" "userspace/iona-node" "" || \
            die "Cannot build iona-node"
        build_if_missing "iona-shell"  "userspace/iona-shell"  "x86_64-unknown-none" || \
            build_if_missing "iona-shell" "userspace/iona-shell" "" || \
            log_warn "iona-shell not built (optional)"
        build_if_missing "iona-utils"  "userspace/iona-utils"  "x86_64-unknown-none" || \
            build_if_missing "iona-utils" "userspace/iona-utils" "" || \
            log_warn "iona-utils not built (optional)"
        log_info "Binary build completed"
        exit 0
    fi

    create_disk_image "$OUTPUT" "$SIZE_MB"

    # ── Required files (must succeed in strict mode) ──────────────────────
    inject_required "/etc/iona-node.json" \
        '{"validator_id":0,"gossip_port":9000,"admin_port":7777,"peers":[],"first_boot":true}'

    # ── Optional files (warnings only) ────────────────────────────────────
    inject_file "/etc/resolv.conf" "nameserver 8.8.8.8"
    inject_file "/etc/iona-release" "IONA OS v0.6.0"
    inject_file "/etc/hostname" "iona-os"
    inject_file "/etc/motd" "Welcome to IONA OS\n"
    inject_file "/etc/network.conf" "dhcp=1"

    # ── Runtime directories (markers) ─────────────────────────────────────
    inject_file "/var/iona-node/.keep" ""
    inject_file "/var/crash/.keep" ""
    inject_file "/var/log/.keep" ""

    # ── Install userspace binaries ────────────────────────────────────────
    # Try to build missing ones automatically
    build_if_missing "iona-node" "userspace/iona-node" "x86_64-unknown-none" || true
    build_if_missing "iona-shell" "userspace/iona-shell" "x86_64-unknown-none" || true
    build_if_missing "iona-utils" "userspace/iona-utils" "x86_64-unknown-none" || true

    # Candidate paths for each binary
    local node_candidates=(
        "userspace/iona-node/target/x86_64-unknown-none/release/iona-node"
        "userspace/iona-node/target/release/iona-node"
        "target/x86_64-unknown-none/release/iona-node"
    )
    local shell_candidates=(
        "userspace/iona-shell/target/x86_64-unknown-none/release/iona-shell"
        "userspace/iona-shell/target/release/iona-shell"
    )
    local utils_candidates=(
        "userspace/iona-utils/target/x86_64-unknown-none/release/iona-utils"
        "userspace/iona-utils/target/release/iona-utils"
    )

    install_binary "iona-node" "${node_candidates[@]}" || {
        if [[ $STRICT_BUILD -eq 1 ]]; then
            die "Required binary iona-node not installed"
        else
            log_warn "iona-node not installed"
        fi
    }
    install_binary "iona-shell" "${shell_candidates[@]}" || {
        log_warn "iona-shell not installed (optional)"
    }
    install_binary "iona-utils" "${utils_candidates[@]}" || {
        log_warn "iona-utils not installed (optional)"
    }

    # ── Release manifest (if present) ─────────────────────────────────────
    local manifest="$ROOT_DIR/dist/release-manifest.json"
    if [[ -f "$manifest" ]]; then
        inject_file "/etc/iona-artifacts.json" "$(cat "$manifest")"
    fi

    log_info "IONAFS image built: $OUTPUT"
}

main "$@"
