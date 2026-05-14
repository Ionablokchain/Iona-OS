#!/usr/bin/env bash
# Generate BIOS and UEFI disk images from a compiled kernel ELF binary.
#
# Usage:
#   ./scripts/gen-disk-images.sh <kernel-elf> <output-dir>
#
# This script creates a temporary Cargo project that uses the bootloader
# crate (v0.11) to generate bootable disk images. The temporary project
# is cached in /tmp/iona-disk-image-builder for faster rebuilds.

set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <kernel-elf> <output-dir>"
    exit 1
fi

KERNEL_ELF="$(realpath "$1")"
OUT_DIR="$(realpath "$2")"

if [ ! -f "$KERNEL_ELF" ]; then
    echo "Error: kernel binary not found: $KERNEL_ELF"
    exit 1
fi

mkdir -p "$OUT_DIR"

# Cached builder project in /tmp
BUILDER_DIR="/tmp/iona-disk-image-builder"

# Create or update the builder project
if [ ! -f "$BUILDER_DIR/Cargo.toml" ]; then
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
fi

# Build and run the disk image builder
cd "$BUILDER_DIR"
cargo run --release -- "$KERNEL_ELF" "$OUT_DIR" 2>&1
