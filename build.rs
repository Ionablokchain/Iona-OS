//! Build script for IONA OS kernel.
//!
//! Responsibilities:
//! - Verify that the target is `x86_64-unknown-none`.
//! - Emit linker arguments for the kernel image.
//! - Embed build information (git hash, timestamp) as environment variables.
//! - Detect whether the post-build disk image scripts are available.
//!
//! Post-build steps (handled externally):
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

fn main() {
    // -------------------------------------------------------------------------
    // 1. Target verification
    // -------------------------------------------------------------------------
    let target = env::var("TARGET").unwrap_or_else(|_| "unknown".to_string());
    if target != "x86_64-unknown-none" {
        println!("cargo:warning=IONA OS is designed for x86_64-unknown-none (current: {target})");
        println!("cargo:warning=Build may fail or produce an unbootable binary.");
    }

    // -------------------------------------------------------------------------
    // 2. Linker configuration
    // -------------------------------------------------------------------------
    // Use the linker script that defines the kernel's memory layout.
    let linker_script = "src/arch/x86_64/linker.ld";
    if Path::new(linker_script).exists() {
        println!("cargo:rustc-link-arg=-T{linker_script}");
    } else {
        println!("cargo:warning=Linker script {linker_script} not found – using default layout");
    }

    // Optional: force lld or gold (if installed)
    if target == "x86_64-unknown-none" {
        println!("cargo:rustc-link-arg=-nostdlib");
        println!("cargo:rustc-link-arg=-z");
        println!("cargo:rustc-link-arg=max-page-size=0x1000");
    }

    // -------------------------------------------------------------------------
    // 3. Embed build information
    // -------------------------------------------------------------------------
    // Git hash (abbreviated, 8 chars)
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Git dirty flag
    let dirty = Command::new("git")
        .args(["diff", "--quiet"])
        .status()
        .map(|s| !s.success())
        .unwrap_or(false);

    let version = format!("{}{}", git_hash, if dirty { "-dirty" } else { "" });

    // ISO 8601 build timestamp (UTC)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    println!("cargo:rustc-env=IONA_GIT_HASH={version}");
    println!("cargo:rustc-env=IONA_BUILD_TIMESTAMP={now}");
    println!("cargo:rustc-env=IONA_TARGET={target}");

    // -------------------------------------------------------------------------
    // 4. Detect post-build scripts
    // -------------------------------------------------------------------------
    let gen_images = "scripts/gen-disk-images.sh";
    let qemu_script = "scripts/qemu.sh";

    for script in &[gen_images, qemu_script] {
        if !Path::new(script).exists() {
            println!("cargo:warning=Post-build script not found: {script}");
            println!("cargo:warning=Run 'scripts/gen-disk-images.sh' manually after build.");
        }
    }

    // -------------------------------------------------------------------------
    // 5. Re-run conditions
    // -------------------------------------------------------------------------
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={linker_script}");
    println!("cargo:rerun-if-changed=scripts/gen-disk-images.sh");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
}
