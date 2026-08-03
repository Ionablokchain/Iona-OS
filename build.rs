//! Build script for IONA OS kernel.
//!
//! Responsibilities:
//! - Verify the target architecture and triple are correct.
//! - Emit linker arguments for the kernel image.
//! - Embed build information (git hash, timestamp, version) as environment variables.
//! - Detect toolchain and linker availability.
//! - Configure `rerun-if-changed` triggers for incremental rebuilds.
//! - Validate required features and warn about common misconfigurations.
//! - Optionally run post‑build disk image generation scripts (disabled by default).
//!
//! # Environment Variables
//! - `IONA_SKIP_POST_BUILD` – set to `1` to skip post‑build script checks.
//! - `IONA_CI` – set to `1` to treat missing scripts as fatal errors.
//! - `IONA_VERBOSE` – set to `1` for verbose output.
//! - `IONA_DISABLE_LINKER_CHECKS` – set to `1` to skip linker availability checks.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const EXPECTED_TARGET: &str = "x86_64-unknown-none";
const LINKER_SCRIPT: &str = "src/arch/x86_64/linker.ld";
const GEN_DISK_SCRIPT: &str = "scripts/gen-disk-images.sh";
const QEMU_SCRIPT: &str = "scripts/qemu.sh";

// -----------------------------------------------------------------------------
// Colours (for build output)
// -----------------------------------------------------------------------------

#[allow(dead_code)]
mod colour {
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const CYAN: &str = "\x1b[36m";
    pub const RESET: &str = "\x1b[0m";
}

fn ci() -> bool {
    env::var("IONA_CI").is_ok() || env::var("CI").is_ok()
}

fn verbose() -> bool {
    env::var("IONA_VERBOSE").is_ok()
}

fn skip_post_build() -> bool {
    env::var("IONA_SKIP_POST_BUILD").is_ok()
}

fn disable_linker_checks() -> bool {
    env::var("IONA_DISABLE_LINKER_CHECKS").is_ok()
}

// -----------------------------------------------------------------------------
// Logger
// -----------------------------------------------------------------------------

fn info(msg: &str) {
    println!("cargo:warning={}", msg);
    if verbose() {
        eprintln!("{}[INFO]{} {}", colour::BLUE, colour::RESET, msg);
    }
}

fn warn(msg: &str) {
    println!("cargo:warning={}", msg);
    eprintln!("{}[WARN]{} {}", colour::YELLOW, colour::RESET, msg);
}

fn error(msg: &str) -> ! {
    eprintln!("{}[ERROR]{} {}", colour::RED, colour::RESET, msg);
    std::process::exit(1);
}

fn success(msg: &str) {
    if verbose() {
        eprintln!("{}[OK]{} {}", colour::GREEN, colour::RESET, msg);
    }
}

// -----------------------------------------------------------------------------
// Git information
// -----------------------------------------------------------------------------

struct GitInfo {
    hash: String,
    dirty: bool,
}

fn get_git_info() -> GitInfo {
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

    GitInfo { hash, dirty }
}

// -----------------------------------------------------------------------------
// Timestamp
// -----------------------------------------------------------------------------

fn get_timestamp() -> (u64, String) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let ts = now.as_secs();
    let datetime = chrono::DateTime::from_timestamp(ts as i64, 0)
        .unwrap_or_else(|| chrono::DateTime::UNIX_EPOCH);
    (ts, datetime.to_rfc3339())
}

// -----------------------------------------------------------------------------
// Toolchain checks
// -----------------------------------------------------------------------------

fn check_toolchain() {
    if disable_linker_checks() {
        info("Linker checks disabled by IONA_DISABLE_LINKER_CHECKS");
        return;
    }

    // Check that `ld` is available (or the linker used by cargo).
    let linker = env::var("CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER")
        .unwrap_or_else(|_| "ld".to_string());

    let status = Command::new(&linker)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    match status {
        Ok(s) if s.success() => success(&format!("Linker `{}` is available", linker)),
        _ => {
            warn(&format!(
                "Linker `{}` not found or not working. \
                 Ensure you have a cross‑compilation toolchain installed.",
                linker
            ));
            if ci() {
                error("CI requires a working linker");
            }
        }
    }

    // Check Rust version (minimal).
    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_string());
    let version = Command::new(&rustc)
        .arg("--version")
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok());

    if let Some(v) = version {
        info(&format!("Rustc version: {}", v.trim()));
        // We don't enforce a minimum version here, but we warn if it's too old.
        // Parsing is cumbersome; we rely on Cargo's MSRV.
    }
}

// -----------------------------------------------------------------------------
// Target verification
// -----------------------------------------------------------------------------

fn check_target() {
    let target = env::var("TARGET").unwrap_or_default();
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target != EXPECTED_TARGET {
        error(&format!(
            "IONA OS kernel is designed for target `{}` (current: `{}`).\n\
             Please build with: `cargo build --target {}`",
            EXPECTED_TARGET, target, EXPECTED_TARGET
        ));
    }

    if arch != "x86_64" {
        error(&format!(
            "IONA OS kernel only supports `x86_64` architecture (current: `{}`).",
            arch
        ));
    }

    success(&format!("Target `{}` verified", target));
}

// -----------------------------------------------------------------------------
// Linker script
// -----------------------------------------------------------------------------

fn check_linker_script() {
    let path = Path::new(LINKER_SCRIPT);
    if !path.exists() {
        error(&format!(
            "Linker script not found: `{}`.\n\
             The kernel cannot be built without a linker script.",
            LINKER_SCRIPT
        ));
    }
    success(&format!("Linker script `{}` found", LINKER_SCRIPT));
}

// -----------------------------------------------------------------------------
// Feature validation
// -----------------------------------------------------------------------------

fn check_features() {
    // Detect if `std` feature is accidentally enabled.
    if env::var("CARGO_FEATURE_STD").is_ok() {
        warn("The `std` feature is enabled, but IONA OS is a `no_std` kernel. \
              This may cause linker errors.");
    }

    // Check for conflicting features (if any).
    // Example: if both "test" and "production" are enabled.
    // We can add more as needed.
}

// -----------------------------------------------------------------------------
// Post‑build scripts
// -----------------------------------------------------------------------------

fn check_post_build_scripts() {
    if skip_post_build() {
        info("Skipping post‑build script checks (IONA_SKIP_POST_BUILD)");
        return;
    }

    let missing: Vec<&str> = [GEN_DISK_SCRIPT, QEMU_SCRIPT]
        .iter()
        .filter(|&s| !Path::new(s).exists())
        .copied()
        .collect();

    if !missing.is_empty() {
        if ci() {
            error(&format!(
                "CI build requires post‑build scripts: {}",
                missing.join(", ")
            ));
        } else {
            warn(&format!(
                "Post‑build scripts not found: {}.\n\
                 You will need to run `{}` manually after the build.",
                missing.join(", "),
                GEN_DISK_SCRIPT
            ));
        }
    } else {
        success("All post‑build scripts found");
    }
}

// -----------------------------------------------------------------------------
// Emit environment variables
// -----------------------------------------------------------------------------

fn emit_env_vars() {
    let git = get_git_info();
    let pkg_version = env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "unknown".to_string());
    let version = if git.dirty {
        format!("{}-dirty", git.hash)
    } else {
        git.hash.clone()
    };
    let full_version = format!("v{} ({})", pkg_version, version);

    let (timestamp, date) = get_timestamp();
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());

    println!("cargo:rustc-env=IONA_GIT_HASH={}", git.hash);
    println!("cargo:rustc-env=IONA_BUILD_VERSION={}", full_version);
    println!("cargo:rustc-env=IONA_BUILD_TIMESTAMP={}", timestamp);
    println!("cargo:rustc-env=IONA_BUILD_DATE={}", date);
    println!("cargo:rustc-env=IONA_TARGET={}", target);
    println!("cargo:rustc-env=IONA_DIRTY={}", if git.dirty { "1" } else { "0" });
    println!("cargo:rustc-env=IONA_PKG_VERSION={}", pkg_version);
}

// -----------------------------------------------------------------------------
// Emit linker arguments
// -----------------------------------------------------------------------------

fn emit_linker_args() {
    println!("cargo:rustc-link-arg=-T{}", LINKER_SCRIPT);
    println!("cargo:rustc-link-arg=-nostdlib");
    println!("cargo:rustc-link-arg=-z");
    println!("cargo:rustc-link-arg=max-page-size=0x1000");
}

// -----------------------------------------------------------------------------
// Rerun‑if‑changed triggers
// -----------------------------------------------------------------------------

fn emit_rerun_triggers() {
    // Core source files
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={}", LINKER_SCRIPT);
    println!("cargo:rerun-if-changed=Cargo.toml");
    println!("cargo:rerun-if-changed=Cargo.lock");

    // Git data (only if .git exists)
    if Path::new(".git/HEAD").exists() {
        println!("cargo:rerun-if-changed=.git/HEAD");
        println!("cargo:rerun-if-changed=.git/index");
    }

    // Scripts (if they exist)
    if Path::new(GEN_DISK_SCRIPT).exists() {
        println!("cargo:rerun-if-changed={}", GEN_DISK_SCRIPT);
    }
    if Path::new(QEMU_SCRIPT).exists() {
        println!("cargo:rerun-if-changed={}", QEMU_SCRIPT);
    }

    // Also watch for env var changes that affect build.
    println!("cargo:rerun-if-env-changed=IONA_CI");
    println!("cargo:rerun-if-env-changed=IONA_VERBOSE");
    println!("cargo:rerun-if-env-changed=IONA_SKIP_POST_BUILD");
    println!("cargo:rerun-if-env-changed=IONA_DISABLE_LINKER_CHECKS");
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

fn main() {
    // Show banner in verbose mode.
    if verbose() {
        eprintln!(
            "{}─── IONA OS Kernel Build ───{}",
            colour::MAGENTA, colour::RESET
        );
    }

    // 1. Validate target and linker script.
    check_target();
    check_linker_script();

    // 2. Toolchain checks.
    check_toolchain();

    // 3. Feature validation.
    check_features();

    // 4. Emit environment variables.
    emit_env_vars();

    // 5. Emit linker arguments.
    emit_linker_args();

    // 6. Set rerun‑if‑changed triggers.
    emit_rerun_triggers();

    // 7. Check post‑build scripts (non‑fatal unless CI).
    check_post_build_scripts();

    // 8. Final success message.
    let version = env::var("IONA_BUILD_VERSION").unwrap_or_else(|_| "unknown".to_string());
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    info(&format!("IONA OS build configured successfully. Version: {}, Target: {}", version, target));

    if verbose() {
        eprintln!(
            "{}─── Build configuration complete ───{}",
            colour::MAGENTA, colour::RESET
        );
    }
}
