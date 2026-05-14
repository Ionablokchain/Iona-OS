//! Build script pentru iona-os-kernel
//!
//! Nota: generarea disk image-urilor bootabile (UEFI + BIOS) se face
//! post-build via scripts/gen-disk-images.sh, deoarece build.rs rulează
//! înainte de compilarea binarului kernel.
//!
//! Flux complet:
//!   1. cargo build  →  compilează kernelul (build.rs rulează aici)
//!   2. scripts/gen-disk-images.sh  →  generează iona-bios.img + iona-uefi.img
//!   3. scripts/qemu.sh  →  lansează QEMU cu disk image-ul generat
//!
//! Sau direct:
//!   ./scripts/build-and-run.sh     (pașii 1+2+3 combinate)
//!   ./build-all.sh                 (build complet: kernel + userspace + WASM)

fn main() {
    println!("cargo:rerun-if-changed=src/");
    println!("cargo:rerun-if-changed=build.rs");
}
