#!/usr/bin/env bash
# =============================================================================
# CI Boot Test — IONA OS in QEMU
#
# Boots IONA OS in QEMU, verifies kernel + critical subsystems (memory, PCI,
# IONAFS, network, GUI, consensus) within a timeout.
#
# Usage:
#   ./scripts/ci-boot.sh [OPTIONS]
#
# Options:
#   --kernel FILE       Kernel ELF path (default: dist/iona-os-kernel.elf)
#   --disk FILE         Disk image path (default: dist/iona-disk.img)
#   --timeout SECONDS   Maximum boot time (default: 30)
#   --serial-log FILE   Where to write serial output (default: temp file)
#   --checks LIST       Comma-separated list of check names (default: all)
#   --patterns "P1;P2"  Custom semicolon-separated patterns (overrides defaults)
#   --no-clean          Keep serial log file after test
#   --verbose           Verbose output (show QEMU output on failure)
#   --help, -h          Show this help message
#
# Environment variables:
#   IONA_VERBOSE        Set to 1 for verbose output
#
# Exit codes:
#   0   All checks passed
#   1   Missing dependencies or files
#   2   Timeout or QEMU error
#   3   One or more checks failed
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# -----------------------------------------------------------------------------
# Constants & defaults
# -----------------------------------------------------------------------------
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR="$(dirname "$SCRIPT_DIR")"
readonly DEFAULT_KERNEL="$ROOT_DIR/dist/iona-os-kernel.elf"
readonly DEFAULT_DISK="$ROOT_DIR/dist/iona-disk.img"
readonly DEFAULT_TIMEOUT=30
readonly DEFAULT_CHECKS="kernel,memory,pci,ionafs,network,gui,consensus"

# Default patterns for each check (regex)
declare -A DEFAULT_PATTERNS=(
    ["kernel"]="IONA OS"
    ["memory"]="\\[BOOT\\].*MM"
    ["pci"]="\\[PCI\\]"
    ["ionafs"]="\\[IONAFS\\]"
    ["network"]="\\[NET\\]"
    ["gui"]="\\[GUI\\]"
    ["consensus"]="\\[BFT\\]"
)

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
KERNEL="$DEFAULT_KERNEL"
DISK="$DEFAULT_DISK"
TIMEOUT="$DEFAULT_TIMEOUT"
SERIAL_LOG=""
CLEAN_LOG=1
VERBOSE=0
CHECKS_LIST=""
CUSTOM_PATTERNS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kernel)
            if [[ -z "${2:-}" ]]; then die "--kernel requires an argument"; fi
            KERNEL="$2"
            shift 2
            ;;
        --disk)
            if [[ -z "${2:-}" ]]; then die "--disk requires an argument"; fi
            DISK="$2"
            shift 2
            ;;
        --timeout)
            if [[ -z "${2:-}" ]]; then die "--timeout requires an argument"; fi
            TIMEOUT="$2"
            shift 2
            ;;
        --serial-log)
            if [[ -z "${2:-}" ]]; then die "--serial-log requires an argument"; fi
            SERIAL_LOG="$2"
            shift 2
            ;;
        --checks)
            if [[ -z "${2:-}" ]]; then die "--checks requires an argument"; fi
            CHECKS_LIST="$2"
            shift 2
            ;;
        --patterns)
            if [[ -z "${2:-}" ]]; then die "--patterns requires an argument"; fi
            CUSTOM_PATTERNS="$2"
            shift 2
            ;;
        --no-clean)
            CLEAN_LOG=0
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
    if ! command -v qemu-system-x86_64 &>/dev/null; then
        die "qemu-system-x86_64 not found. Install: sudo apt install qemu-system-x86"
    fi
    if [[ ! -f "$KERNEL" ]]; then
        die "Kernel ELF not found: $KERNEL. Run ./build-all.sh first."
    fi
    if [[ ! -f "$DISK" ]]; then
        die "Disk image not found: $DISK. Run ./build-all.sh first."
    fi
}

# -----------------------------------------------------------------------------
# Run QEMU and capture serial output
# -----------------------------------------------------------------------------
run_qemu() {
    local log_file="$1"
    local timeout_sec="$2"

    log_info "Booting IONA OS in QEMU (timeout ${timeout_sec}s)..."
    log_debug "Kernel: $KERNEL"
    log_debug "Disk: $DISK"
    log_debug "Serial log: $log_file"

    set +e
    timeout "$timeout_sec" qemu-system-x86_64 \
        -kernel "$KERNEL" \
        -drive file="$DISK",format=raw,if=virtio \
        -m 512M \
        -serial file:"$log_file" \
        -display none \
        -no-reboot \
        2>/dev/null
    local exit_code=$?
    set -e

    if [[ $exit_code -eq 124 ]]; then
        log_error "QEMU timed out after ${timeout_sec}s"
        return 2
    elif [[ $exit_code -ne 0 ]]; then
        log_error "QEMU exited with code $exit_code"
        return 1
    fi
    return 0
}

# -----------------------------------------------------------------------------
# Check patterns in serial log
# -----------------------------------------------------------------------------
check_pattern() {
    local name="$1"
    local pattern="$2"
    local log_file="$3"

    if grep -q -E "$pattern" "$log_file" 2>/dev/null; then
        log_info "✓ $name"
        return 0
    else
        log_error "✗ $name (pattern: $pattern)"
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Summary and exit
# -----------------------------------------------------------------------------
summary() {
    local passed=$1
    local total=$2
    local log_file=$3

    echo ""
    log_info "Results: $passed / $total checks passed"
    if [[ $passed -eq $total ]]; then
        log_info "CI boot test passed"
        return 0
    else
        log_error "CI boot test failed ($((total - passed)) failures)"
        if [[ -f "$log_file" ]]; then
            log_warn "Last 20 lines of serial log:"
            tail -20 "$log_file" | sed 's/^/  /'
        fi
        return 1
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    check_deps

    # Prepare check list and patterns
    local checks=()
    local patterns=()

    if [[ -n "$CUSTOM_PATTERNS" ]]; then
        IFS=';' read -ra patterns <<< "$CUSTOM_PATTERNS"
        # Use generic check names: check1, check2, ...
        for i in "${!patterns[@]}"; do
            checks+=("custom$((i+1))")
        done
    else
        local check_names
        if [[ -n "$CHECKS_LIST" ]]; then
            IFS=',' read -ra check_names <<< "$CHECKS_LIST"
        else
            IFS=',' read -ra check_names <<< "$DEFAULT_CHECKS"
        fi
        for name in "${check_names[@]}"; do
            if [[ -n "${DEFAULT_PATTERNS[$name]:-}" ]]; then
                checks+=("$name")
                patterns+=("${DEFAULT_PATTERNS[$name]}")
            else
                log_warn "Unknown check name: $name (skipped)"
            fi
        done
    fi

    if [[ ${#checks[@]} -eq 0 ]]; then
        die "No valid checks defined"
    fi

    # Create temporary log file if not provided
    local log_file="$SERIAL_LOG"
    local temp_log=0
    if [[ -z "$log_file" ]]; then
        log_file="$(mktemp /tmp/iona-serial.XXXXXX.log)"
        temp_log=1
        log_debug "Using temporary log file: $log_file"
    fi

    # Run QEMU
    local qemu_exit=0
    run_qemu "$log_file" "$TIMEOUT" || qemu_exit=$?

    if [[ $qemu_exit -ne 0 ]]; then
        if [[ $temp_log -eq 1 && $CLEAN_LOG -eq 0 ]]; then
            log_warn "Serial log preserved: $log_file"
        elif [[ $temp_log -eq 1 ]]; then
            rm -f "$log_file"
        fi
        exit 2
    fi

    # Run checks
    local passed=0
    local failed=0
    for i in "${!checks[@]}"; do
        if check_pattern "${checks[$i]}" "${patterns[$i]}" "$log_file"; then
            ((passed++))
        else
            ((failed++))
        fi
    done

    # Summary
    local total=$((passed + failed))
    summary "$passed" "$total" "$log_file"
    local summary_exit=$?

    # Cleanup
    if [[ $temp_log -eq 1 && $CLEAN_LOG -eq 1 ]]; then
        rm -f "$log_file"
    elif [[ $temp_log -eq 1 && $CLEAN_LOG -eq 0 ]]; then
        log_info "Serial log preserved: $log_file"
    fi

    exit $summary_exit
}

main "$@"
