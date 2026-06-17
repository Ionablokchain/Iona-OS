//! Build script for IONA OS kernel.
//!
//! Responsibilities:
//! - Verify the target architecture and triple are correct.
//! - Emit linker arguments for the kernel image.
//! - Embed build information (git hash, timestamp, version) as environment variables.
//! - Detect whether post‑build disk image scripts are available.
//! - Configure `rerun-if-changed` triggers for incremental rebuilds.
//!
//! Post‑build steps (handled externally):
//!   scripts/gen-disk-images.sh   →  iona-bios.img + iona-uefi.img
//!   scripts/qemu.sh              →  launch QEMU with the disk image
//!
//! Convenience wrappers:
//!   ./scripts/build-and-run.sh   (build + disk image + QEMU)
//!   ./build-all.sh               (kernel + userspace + WASM)

use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Expected target triple for the kernel.
const EXPECTED_TARGET: &str = "x86_64-unknown-none";

/// Linker script path (relative to the crate root).
const LINKER_SCRIPT: &str = "src/arch/x86_64/linker.ld";

/// Post‑build scripts.
const GEN_DISK_SCRIPT: &str = "scripts/gen-disk-images.sh";
const QEMU_SCRIPT: &str = "scripts/qemu.sh";

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Get the git hash (short, 8 chars) and dirty flag.
fn get_git_info() -> (String, bool) {
    let hash = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let dirty = Command::new("git")
        .args(["diff", "--quiet"])
        .status()
        .map(|s| !s.success())
        .unwrap_or(false);

    (hash, dirty)
}

/// Get the build timestamp as a UNIX timestamp and ISO 8601 string.
fn get_timestamp() -> (u64, String) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ts = now.as_secs();
    let datetime = chrono::DateTime::from_timestamp(ts as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH);
    (ts, datetime.to_rfc3339())
}

/// Check if we are running in a CI environment.
fn is_ci() -> bool {
    env::var("CI").is_ok()
}

// -----------------------------------------------------------------------------
// Validation checks
// -----------------------------------------------------------------------------

/// Validate the target triple and architecture.
fn check_target() {
    let target = env::var("TARGET").unwrap_or_default();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target != EXPECTED_TARGET {
        eprintln!(
            "❌ IONA OS kernel is designed for target `{}` (current: `{}`).",
            EXPECTED_TARGET, target
        );
        eprintln!("   Please build with: `cargo build --target {}", EXPECTED_TARGET);
        std::process::exit(1);
    }

    if arch != "x86_64" {
        eprintln!(
            "❌ IONA OS kernel only supports `x86_64` architecture (current: `{}`).",
            arch
        );
        std::process::exit(1);
    }
}

/// Check that the linker script exists.
fn check_linker_script() {
    if !Path::new(LINKER_SCRIPT).exists() {
        eprintln!(
            "❌ Linker script not found: `{}`.",
            LINKER_SCRIPT
        );
        eprintln!("   The kernel cannot be built without a linker script.");
        std::process::exit(1);
    }
}

/// Check for post‑build scripts (warnings only, unless CI).
fn check_post_build_scripts() {
    let missing: Vec<&str> = [GEN_DISK_SCRIPT, QEMU_SCRIPT]
        .iter()
        .filter(|&s| !Path::new(s).exists())
        .copied()
        .collect();

    if !missing.is_empty() {
        if is_ci() {
            eprintln!(
                "❌ CI build requires post‑build scripts: {}",
                missing.join(", ")
            );
            std::process::exit(1);
        } else {
            eprintln!(
                "⚠️  Post‑build scripts not found: {}",
                missing.join(", ")
            );
            eprintln!(
                "   You will need to run `{}` manually after the build.",
                GEN_DISK_SCRIPT
            );
        }
    }
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

fn main() {
    // 1. Validate target and linker script.
    check_target();
    check_linker_script();

    // 2. Emit linker arguments.
    println!("cargo:rustc-link-arg=-T{}", LINKER_SCRIPT);
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=0x1000");

    // 3. Gather build information.
    let (git_hash, dirty) = get_git_info();
    let version = if dirty {
        format!("{}-dirty", git_hash)
    } else {
        git_hash.clone()
    };
    let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());
    let full_version = format!("v{} ({})", pkg_version, version);

    let (timestamp, date) = get_timestamp();
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    // 4. Emit environment variables for the kernel to use.
    println!("cargo:rustc-env=IONA_GIT_HASH={}", git_hash);
    println!("cargo:rustc-env=IONA_BUILD_VERSION={}", full_version);
    println!("cargo:rustc-env=IONA_BUILD_TIMESTAMP={}", timestamp);
    println!("cargo:rustc-env=IONA_BUILD_DATE={}", date);
    println!("cargo:rustc-env=IONA_TARGET={}", target);
    println!("cargo:rustc-env=IONA_DIRTY={}", if dirty { "1" } else { "0" });
    println!("cargo:rustc-env=IONA_PKG_VERSION={}", pkg_version);

    // 5. Set rerun‑if‑changed triggers.
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", LINKER_SCRIPT);
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=scripts/gen-disk-images.sh");
    println!("cargo:rerun-if-changed=scripts/qemu.sh");

    // 6. Check post‑build scripts (non‑fatal unless CI).
    check_post_build_scripts();

    // 7. Optional: detect if `std` feature is accidentally enabled.
    if env::var("CARGO_FEATURE_STD").is_ok() {
        eprintln!(
            "⚠️  The `std` feature is enabled, but IONA OS is a `no_std` kernel. \
             This may cause linker errors."
        );
    }

    println!("cargo:warning=IONA OS build configured successfully.");
    println!("cargo:warning=Version: {}", full_version);
    println!("cargo:warning=Target: {}", target);
}
