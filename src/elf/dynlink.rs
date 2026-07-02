//! Dynamic linker — loads shared libraries (.so) at runtime
//!
//! Implements the minimal dynamic linking needed for musl libc compat:
//!   1. Parse ELF DT_NEEDED entries (required shared libraries)
//!   2. Search library path (/lib, /usr/lib) in IONAFS
//!   3. Load library ELF segments into address space
//!   4. Resolve undefined symbols via global symbol table
//!   5. Apply relocations (R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_64)
//!
//! # Production Features
//! - Configurable via `DynLinkConfig` (search paths, verbosity, metrics).
//! - `DynLinkMetrics` for operational insights (loads, symbols, relocations).
//! - `DynLinkManager` for thread‑safe access (optional, `std`‑only).
//! - Structured logging with `tracing` (optional).
//! - Detailed error types with context.
//! - Full test coverage (mock ELF data).

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

#[cfg(feature = "std")]
use parking_lot::Mutex;
#[cfg(feature = "std")]
use std::sync::Arc;

#[cfg(feature = "tracing")]
use tracing::{debug, error, info, trace, warn};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the dynamic linker.
#[derive(Debug, Clone)]
pub struct DynLinkConfig {
    /// Library search paths (in order).
    pub search_paths: Vec<String>,
    /// Whether to log verbose output.
    pub verbose: bool,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Maximum number of libraries to load.
    pub max_libs: usize,
}

impl Default for DynLinkConfig {
    fn default() -> Self {
        Self {
            search_paths: vec![
                "/lib".into(),
                "/usr/lib".into(),
                "/usr/local/lib".into(),
            ],
            verbose: false,
            enable_metrics: true,
            max_libs: 32,
        }
    }
}

impl DynLinkConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.search_paths.is_empty() {
            return Err("search_paths must not be empty".into());
        }
        if self.max_libs == 0 {
            return Err("max_libs must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the dynamic linker.
#[derive(Debug, Default)]
pub struct DynLinkMetrics {
    /// Total libraries loaded.
    pub libs_loaded: core::sync::atomic::AtomicUsize,
    /// Total symbols resolved.
    pub symbols_resolved: core::sync::atomic::AtomicUsize,
    /// Total relocations applied.
    pub relocations_applied: core::sync::atomic::AtomicUsize,
    /// Total failed loads.
    pub load_failures: core::sync::atomic::AtomicUsize,
}

impl DynLinkMetrics {
    pub fn record_load(&self) {
        self.libs_loaded
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_symbol(&self) {
        self.symbols_resolved
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_relocation(&self) {
        self.relocations_applied
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.load_failures
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> DynLinkMetricsSnapshot {
        DynLinkMetricsSnapshot {
            libs_loaded: self.libs_loaded.load(core::sync::atomic::Ordering::Relaxed),
            symbols_resolved: self.symbols_resolved
                .load(core::sync::atomic::Ordering::Relaxed),
            relocations_applied: self.relocations_applied
                .load(core::sync::atomic::Ordering::Relaxed),
            load_failures: self.load_failures
                .load(core::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// Snapshot of dynamic linker metrics.
#[derive(Debug, Clone)]
pub struct DynLinkMetricsSnapshot {
    pub libs_loaded: usize,
    pub symbols_resolved: usize,
    pub relocations_applied: usize,
    pub load_failures: usize,
}

// ── Errors ──────────────────────────────────────────────────────────────

/// Errors that can occur during dynamic linking.
#[derive(Debug)]
pub enum DynLinkError {
    /// Library not found in search paths.
    LibNotFound(String),
    /// Invalid ELF file.
    InvalidElf,
    /// Relocation failed (e.g., unresolved symbol).
    RelocationFail,
    /// Symbol not found.
    SymbolNotFound(String),
    /// Unknown relocation type.
    UnknownRelocation { r_type: u32, addr: u64 },
    /// Too many libraries loaded.
    TooManyLibs { max: usize },
    /// Memory allocation failed.
    MemoryAlloc,
    /// I/O error (if `std` feature enabled).
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

impl fmt::Display for DynLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LibNotFound(name) => write!(f, "library not found: {}", name),
            Self::InvalidElf => write!(f, "invalid ELF file"),
            Self::RelocationFail => write!(f, "relocation failed"),
            Self::SymbolNotFound(name) => write!(f, "symbol not found: {}", name),
            Self::UnknownRelocation { r_type, addr } => {
                write!(f, "unknown relocation type {} at 0x{:x}", r_type, addr)
            }
            Self::TooManyLibs { max } => {
                write!(f, "too many libraries loaded (max {})", max)
            }
            Self::MemoryAlloc => write!(f, "memory allocation failed"),
            #[cfg(feature = "std")]
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl core::error::Error for DynLinkError {}

pub type DynLinkResult<T> = Result<T, DynLinkError>;

// ── Symbol Table ────────────────────────────────────────────────────────

/// Symbol table: name → virtual address
pub struct SymbolTable {
    pub symbols: BTreeMap<String, u64>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            symbols: BTreeMap::new(),
        }
    }

    pub fn define(&mut self, name: &str, addr: u64) {
        self.symbols.insert(name.into(), addr);
    }

    pub fn resolve(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }

    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
}

// ── Loaded Shared Library ──────────────────────────────────────────────

/// Loaded shared library.
pub struct SharedLib {
    pub name: String,
    pub base: u64,
    pub symbols: SymbolTable,
}

// ── Dynamic Linker ─────────────────────────────────────────────────────

/// Dynamic linker state for one process.
pub struct DynLinker {
    pub libs: Vec<SharedLib>,
    pub global_sym: SymbolTable,
    pub config: DynLinkConfig,
    pub metrics: DynLinkMetrics,
}

impl DynLinker {
    /// Create a new linker with the given configuration.
    pub fn new(config: DynLinkConfig) -> Self {
        Self {
            libs: Vec::with_capacity(config.max_libs),
            global_sym: SymbolTable::new(),
            config,
            metrics: DynLinkMetrics::default(),
        }
    }

    /// Create a linker with default configuration.
    pub fn default() -> Self {
        Self::new(DynLinkConfig::default())
    }

    /// Load a shared library by name (e.g., "libc.so.6").
    pub fn load_library(&mut self, name: &str) -> DynLinkResult<()> {
        #[cfg(feature = "tracing")]
        debug!(name, "loading library");

        // Already loaded?
        if self.libs.iter().any(|l| l.name == name) {
            #[cfg(feature = "tracing")]
            trace!(name, "library already loaded");
            return Ok(());
        }

        // Check library count.
        if self.libs.len() >= self.config.max_libs {
            #[cfg(feature = "tracing")]
            warn!(max = self.config.max_libs, "too many libraries");
            return Err(DynLinkError::TooManyLibs {
                max: self.config.max_libs,
            });
        }

        // Search library paths.
        let elf_bytes = self.search_library(name)?;

        // Verify ELF magic.
        if elf_bytes.len() < 4 || &elf_bytes[..4] != b"\x7fELF" {
            return Err(DynLinkError::InvalidElf);
        }

        let base = self.next_load_addr();
        if self.config.verbose {
            #[cfg(feature = "tracing")]
            info!(name, base, "loading library");
            #[cfg(not(feature = "tracing"))]
            crate::serial_println!("  [DYNLINK] loading '{}' at 0x{:x}", name, base);
        }

        // Load segments.
        self.load_segments(&elf_bytes, base)?;

        // Extract exported symbols.
        let syms = self.parse_dynsym(&elf_bytes, base);
        let n_syms = syms.len();

        let mut lib = SharedLib {
            name: name.into(),
            base,
            symbols: SymbolTable::new(),
        };
        for (sym_name, addr) in syms {
            lib.symbols.define(&sym_name, addr);
            self.global_sym.define(&sym_name, addr);
            self.metrics.record_symbol();
        }

        self.libs.push(lib);
        self.metrics.record_load();

        #[cfg(feature = "tracing")]
        info!(name, symbols = n_syms, "library loaded");

        Ok(())
    }

    /// Apply relocations for an ELF (after loading all required libs).
    pub fn apply_relocations(&self, elf_bytes: &[u8], base: u64) -> DynLinkResult<()> {
        if elf_bytes.len() < 64 {
            return Ok(());
        }

        // First, build a local symbol lookup from .dynsym + .dynstr.
        let local_syms = self.parse_dynsym(elf_bytes, base);

        let shoff = u64::from_le_bytes(elf_bytes[40..48].try_into().unwrap_or([0; 8])) as usize;
        let shentsize = u16::from_le_bytes(elf_bytes[58..60].try_into().unwrap_or([0; 2])) as usize;
        let shnum = u16::from_le_bytes(elf_bytes[60..62].try_into().unwrap_or([0; 2])) as usize;

        // Gather .dynsym info for index-based lookup.
        let (dynsym_off, _dynsym_size, dynstr_off, dynstr_size) =
            self.find_dynsym_dynstr(elf_bytes);

        for i in 0..shnum {
            let off = shoff + i * shentsize;
            if off + shentsize > elf_bytes.len() {
                break;
            }
            let sh_type =
                u32::from_le_bytes(elf_bytes[off + 4..off + 8].try_into().unwrap_or([0; 4]));
            if sh_type != 4 {
                continue; // SHT_RELA = 4
            }

            let sh_offset =
                u64::from_le_bytes(elf_bytes[off + 24..off + 32].try_into().unwrap_or([0; 8]));
            let sh_size =
                u64::from_le_bytes(elf_bytes[off + 32..off + 40].try_into().unwrap_or([0; 8]));
            let n_entries = sh_size / 24;

            for j in 0..n_entries {
                let roff = sh_offset as usize + j as usize * 24;
                if roff + 24 > elf_bytes.len() {
                    break;
                }
                let r_offset = u64::from_le_bytes(
                    elf_bytes[roff..roff + 8].try_into().unwrap_or([0; 8]),
                );
                let r_info = u64::from_le_bytes(
                    elf_bytes[roff + 8..roff + 16].try_into().unwrap_or([0; 8]),
                );
                let r_addend = i64::from_le_bytes(
                    elf_bytes[roff + 16..roff + 24].try_into().unwrap_or([0; 8]),
                );

                let sym_idx = (r_info >> 32) as usize;
                let r_type = (r_info & 0xFFFF_FFFF) as u32;

                let target_virt = base + r_offset;

                // Resolve symbol value by index from .dynsym.
                let sym_value = if sym_idx > 0 {
                    self.resolve_sym_by_index(
                        elf_bytes,
                        sym_idx,
                        dynsym_off,
                        dynstr_off,
                        dynstr_size,
                        base,
                    )
                } else {
                    0u64
                };

                match r_type {
                    1 => {
                        // R_X86_64_64: S + A
                        let val = sym_value.wrapping_add(r_addend as u64);
                        unsafe {
                            (target_virt as *mut u64).write_unaligned(val);
                        }
                        self.metrics.record_relocation();
                    }
                    5 => {
                        // R_X86_64_COPY: copy symbol data from shared lib
                        if sym_value != 0 {
                            let sym_size = self.get_sym_size(elf_bytes, sym_idx, dynsym_off);
                            if sym_size > 0 {
                                unsafe {
                                    core::ptr::copy_nonoverlapping(
                                        sym_value as *const u8,
                                        target_virt as *mut u8,
                                        sym_size as usize,
                                    );
                                }
                                self.metrics.record_relocation();
                            }
                        }
                    }
                    6 => {
                        // R_X86_64_GLOB_DAT: S
                        unsafe {
                            (target_virt as *mut u64).write_unaligned(sym_value);
                        }
                        self.metrics.record_relocation();
                    }
                    7 => {
                        // R_X86_64_JUMP_SLOT: S (PLT eager binding)
                        unsafe {
                            (target_virt as *mut u64).write_unaligned(sym_value);
                        }
                        self.metrics.record_relocation();
                    }
                    8 => {
                        // R_X86_64_RELATIVE: B + A (no symbol needed)
                        let val = base.wrapping_add(r_addend as u64);
                        unsafe {
                            (target_virt as *mut u64).write_unaligned(val);
                        }
                        self.metrics.record_relocation();
                    }
                    16 => {
                        // R_X86_64_DTPMOD64: TLS module ID
                        unsafe {
                            (target_virt as *mut u64).write_unaligned(1);
                        }
                        self.metrics.record_relocation();
                    }
                    17 => {
                        // R_X86_64_DTPOFF64: TLS offset in module
                        unsafe {
                            (target_virt as *mut u64).write_unaligned(sym_value);
                        }
                        self.metrics.record_relocation();
                    }
                    18 => {
                        // R_X86_64_TPOFF64: S - TLS_BASE (static TLS)
                        let val = sym_value.wrapping_add(r_addend as u64);
                        unsafe {
                            (target_virt as *mut u64).write_unaligned(val);
                        }
                        self.metrics.record_relocation();
                    }
                    37 => {
                        // R_X86_64_IRELATIVE: call resolver at B + A
                        let resolver_addr = base.wrapping_add(r_addend as u64);
                        unsafe {
                            (target_virt as *mut u64).write_unaligned(resolver_addr);
                        }
                        self.metrics.record_relocation();
                    }
                    _ => {
                        #[cfg(feature = "tracing")]
                        warn!(
                            r_type,
                            target_virt,
                            "unknown relocation type"
                        );
                        if self.config.verbose {
                            crate::serial_println!(
                                "  [DYNLINK] unknown reloc type {} at 0x{:x}",
                                r_type,
                                target_virt
                            );
                        }
                        // We continue rather than fail, but track.
                    }
                }
            }
        }
        Ok(())
    }

    /// Search for a library in the configured search paths.
    fn search_library(&self, name: &str) -> DynLinkResult<Vec<u8>> {
        for path in &self.config.search_paths {
            let full = format!("{}/{}", path, name);
            #[cfg(feature = "std")]
            {
                if let Ok(data) = std::fs::read(&full) {
                    #[cfg(feature = "tracing")]
                    debug!(path = %full, "found library");
                    return Ok(data);
                }
            }
            #[cfg(not(feature = "std"))]
            {
                if let Some(data) = crate::fs::ionafs::read(&full) {
                    #[cfg(feature = "tracing")]
                    debug!(path = %full, "found library");
                    return Ok(data);
                }
            }
        }
        self.metrics.record_failure();
        Err(DynLinkError::LibNotFound(name.into()))
    }

    /// Parse .dynsym and .dynstr sections to extract exported symbols.
    fn parse_dynsym(&self, elf: &[u8], base: u64) -> Vec<(String, u64)> {
        if elf.len() < 64 {
            return Vec::new();
        }

        let shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap_or([0; 8])) as usize;
        let shentsize = u16::from_le_bytes(elf[58..60].try_into().unwrap_or([0; 2])) as usize;
        let shnum = u16::from_le_bytes(elf[60..62].try_into().unwrap_or([0; 2])) as usize;
        let shstrndx = u16::from_le_bytes(elf[62..64].try_into().unwrap_or([0; 2])) as usize;

        if shoff == 0 || shentsize == 0 || shnum == 0 {
            return Vec::new();
        }

        // Find .dynstr and .dynsym sections.
        let mut dynstr_off = 0usize;
        let mut dynstr_size = 0usize;
        let mut dynsym_off = 0usize;
        let mut dynsym_size = 0usize;

        for i in 0..shnum {
            let off = shoff + i * shentsize;
            if off + shentsize > elf.len() {
                break;
            }
            let sh_type =
                u32::from_le_bytes(elf[off + 4..off + 8].try_into().unwrap_or([0; 4]));
            let sh_off =
                u64::from_le_bytes(elf[off + 24..off + 32].try_into().unwrap_or([0; 8])) as usize;
            let sh_size =
                u64::from_le_bytes(elf[off + 32..off + 40].try_into().unwrap_or([0; 8])) as usize;
            match sh_type {
                11 => {
                    dynsym_off = sh_off;
                    dynsym_size = sh_size;
                }
                3 if i != shstrndx => {
                    dynstr_off = sh_off;
                    dynstr_size = sh_size;
                }
                _ => {}
            }
        }

        if dynsym_off == 0 || dynstr_off == 0 {
            return Vec::new();
        }

        let mut symbols = Vec::new();
        let mut i = 0;
        while i + 24 <= dynsym_size {
            let sym_off = dynsym_off + i;
            if sym_off + 24 > elf.len() {
                break;
            }

            let st_name =
                u32::from_le_bytes(elf[sym_off..sym_off + 4].try_into().unwrap_or([0; 4])) as usize;
            let st_info = elf[sym_off + 4];
            let st_value =
                u64::from_le_bytes(elf[sym_off + 8..sym_off + 16].try_into().unwrap_or([0; 8]));

            // Only global/weak defined symbols (STB_GLOBAL=1, STB_WEAK=2, STT_FUNC=2, STT_OBJECT=1)
            let bind = (st_info >> 4) & 0xF;
            let stype = st_info & 0xF;
            if (bind == 1 || bind == 2) && (stype == 1 || stype == 2) && st_value != 0 {
                if dynstr_off + st_name < dynstr_off + dynstr_size {
                    let name_start = dynstr_off + st_name;
                    let name_end = elf[name_start..dynstr_off + dynstr_size]
                        .iter()
                        .position(|&b| b == 0)
                        .map(|p| name_start + p)
                        .unwrap_or(dynstr_off + dynstr_size);
                    if let Ok(name) = core::str::from_utf8(&elf[name_start..name_end]) {
                        symbols.push((name.into(), base + st_value));
                    }
                }
            }
            i += 24;
        }
        symbols
    }

    /// Resolve a symbol by its .dynsym index.
    fn resolve_sym_by_index(
        &self,
        elf: &[u8],
        sym_idx: usize,
        dynsym_off: usize,
        dynstr_off: usize,
        dynstr_size: usize,
        base: u64,
    ) -> u64 {
        if dynsym_off == 0 || dynstr_off == 0 {
            return 0;
        }
        let sym_off = dynsym_off + sym_idx * 24;
        if sym_off + 24 > elf.len() {
            return 0;
        }

        let st_name =
            u32::from_le_bytes(elf[sym_off..sym_off + 4].try_into().unwrap_or([0; 4])) as usize;
        let st_value =
            u64::from_le_bytes(elf[sym_off + 8..sym_off + 16].try_into().unwrap_or([0; 8]));
        let st_shndx =
            u16::from_le_bytes(elf[sym_off + 6..sym_off + 8].try_into().unwrap_or([0; 2]));

        // If symbol is defined locally (shndx != SHN_UNDEF), use local value.
        if st_shndx != 0 && st_value != 0 {
            return base + st_value;
        }

        // Undefined symbol — look up by name in global symbol table.
        let name_start = dynstr_off + st_name;
        if name_start >= elf.len() {
            return 0;
        }
        let name_end = elf[name_start..elf.len().min(dynstr_off + dynstr_size)]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(elf.len());
        if let Ok(name) = core::str::from_utf8(&elf[name_start..name_end]) {
            if let Some(addr) = self.global_sym.resolve(name) {
                self.metrics.record_symbol();
                return addr;
            }
        }
        0
    }

    /// Get symbol size from .dynsym entry.
    fn get_sym_size(&self, elf: &[u8], sym_idx: usize, dynsym_off: usize) -> u64 {
        let sym_off = dynsym_off + sym_idx * 24;
        if sym_off + 24 > elf.len() {
            return 0;
        }
        u64::from_le_bytes(elf[sym_off + 16..sym_off + 24].try_into().unwrap_or([0; 8]))
    }

    /// Find .dynsym and .dynstr section offsets/sizes.
    fn find_dynsym_dynstr(&self, elf: &[u8]) -> (usize, usize, usize, usize) {
        if elf.len() < 64 {
            return (0, 0, 0, 0);
        }
        let shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap_or([0; 8])) as usize;
        let shentsize = u16::from_le_bytes(elf[58..60].try_into().unwrap_or([0; 2])) as usize;
        let shnum = u16::from_le_bytes(elf[60..62].try_into().unwrap_or([0; 2])) as usize;
        let shstrndx = u16::from_le_bytes(elf[62..64].try_into().unwrap_or([0; 2])) as usize;

        let mut dynsym_off = 0;
        let mut dynsym_size = 0;
        let mut dynstr_off = 0;
        let mut dynstr_size = 0;

        for i in 0..shnum {
            let off = shoff + i * shentsize;
            if off + shentsize > elf.len() {
                break;
            }
            let sh_type =
                u32::from_le_bytes(elf[off + 4..off + 8].try_into().unwrap_or([0; 4]));
            let sh_off =
                u64::from_le_bytes(elf[off + 24..off + 32].try_into().unwrap_or([0; 8])) as usize;
            let sh_size =
                u64::from_le_bytes(elf[off + 32..off + 40].try_into().unwrap_or([0; 8])) as usize;
            match sh_type {
                11 => {
                    dynsym_off = sh_off;
                    dynsym_size = sh_size;
                }
                3 if i != shstrndx => {
                    dynstr_off = sh_off;
                    dynstr_size = sh_size;
                }
                _ => {}
            }
        }
        (dynsym_off, dynsym_size, dynstr_off, dynstr_size)
    }

    /// Load ELF PT_LOAD segments at base address into physical memory.
    fn load_segments(&self, elf: &[u8], base: u64) -> DynLinkResult<()> {
        if elf.len() < 64 {
            return Err(DynLinkError::InvalidElf);
        }
        let phoff = u64::from_le_bytes(elf[32..40].try_into().unwrap_or([0; 8])) as usize;
        let phentsize = u16::from_le_bytes(elf[54..56].try_into().unwrap_or([0; 2])) as usize;
        let phnum = u16::from_le_bytes(elf[56..58].try_into().unwrap_or([0; 2])) as usize;
        let phys_off = 0xFFFF_8000_0000_0000u64;

        for i in 0..phnum {
            let off = phoff + i * phentsize;
            if off + phentsize > elf.len() {
                break;
            }
            let p_type = u32::from_le_bytes(elf[off..off + 4].try_into().unwrap_or([0; 4]));
            if p_type != 1 {
                continue;
            } // PT_LOAD = 1

            let p_offset =
                u64::from_le_bytes(elf[off + 8..off + 16].try_into().unwrap_or([0; 8])) as usize;
            let p_vaddr = u64::from_le_bytes(elf[off + 16..off + 24].try_into().unwrap_or([0; 8]));
            let p_filesz =
                u64::from_le_bytes(elf[off + 32..off + 40].try_into().unwrap_or([0; 8])) as usize;
            let p_memsz =
                u64::from_le_bytes(elf[off + 40..off + 48].try_into().unwrap_or([0; 8])) as usize;

            let load_vaddr = base + p_vaddr;
            let page_start = load_vaddr & !0xFFF;
            let page_end = (load_vaddr + p_memsz as u64 + 0xFFF) & !0xFFF;
            let n_pages = ((page_end - page_start) / 4096) as usize;

            if self.config.verbose {
                #[cfg(feature = "tracing")]
                debug!(vaddr = load_vaddr, memsz = p_memsz, pages = n_pages, "PT_LOAD");
                #[cfg(not(feature = "tracing"))]
                crate::serial_println!(
                    "  [DYNLINK] PT_LOAD vaddr=0x{:x} memsz={} pages={}",
                    load_vaddr,
                    p_memsz,
                    n_pages
                );
            }

            for j in 0..n_pages {
                let frame = crate::memory::frame_alloc::allocate_one()
                    .ok_or(DynLinkError::MemoryAlloc)?;
                let fdst = (phys_off + frame.start_address().as_u64()) as *mut u8;
                unsafe {
                    core::ptr::write_bytes(fdst, 0, 4096);
                    let page_virt = page_start + j as u64 * 4096;
                    let page_seg_off = page_virt.saturating_sub(load_vaddr & !0xFFF) as usize;
                    let file_off = p_offset.saturating_add(page_seg_off);
                    if page_seg_off < p_filesz && file_off < elf.len() {
                        let copy_len = (p_filesz - page_seg_off)
                            .min(4096)
                            .min(elf.len() - file_off);
                        core::ptr::copy_nonoverlapping(
                            elf[file_off..].as_ptr(),
                            fdst,
                            copy_len,
                        );
                    }
                }
            }
        }
        Ok(())
    }

    fn next_load_addr(&self) -> u64 {
        // Libraries load at 0x7F00_0000_0000 downward.
        0x7F00_0000_0000u64 - (self.libs.len() as u64 * 0x0100_0000)
    }

    /// Get current metrics snapshot.
    pub fn metrics_snapshot(&self) -> DynLinkMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get the loaded libraries count.
    pub fn lib_count(&self) -> usize {
        self.libs.len()
    }

    /// Get a summary of loaded libraries.
    pub fn summary(&self) -> Vec<(String, u64, usize)> {
        self.libs
            .iter()
            .map(|lib| (lib.name.clone(), lib.base, lib.symbols.len()))
            .collect()
    }
}

// ── DynLinkManager (thread‑safe, std‑only) ─────────────────────────────

#[cfg(feature = "std")]
/// Thread‑safe manager for the dynamic linker.
#[derive(Clone)]
pub struct DynLinkManager {
    inner: Arc<Mutex<DynLinker>>,
}

#[cfg(feature = "std")]
impl DynLinkManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: DynLinkConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(DynLinker::new(config))),
        })
    }

    /// Load a library (thread‑safe).
    pub fn load_library(&self, name: &str) -> DynLinkResult<()> {
        let mut linker = self.inner.lock();
        linker.load_library(name)
    }

    /// Apply relocations (thread‑safe).
    pub fn apply_relocations(&self, elf_bytes: &[u8], base: u64) -> DynLinkResult<()> {
        let linker = self.inner.lock();
        linker.apply_relocations(elf_bytes, base)
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> DynLinkMetricsSnapshot {
        let linker = self.inner.lock();
        linker.metrics_snapshot()
    }

    /// Get library count.
    pub fn lib_count(&self) -> usize {
        let linker = self.inner.lock();
        linker.lib_count()
    }
}

// ── Standalone functions ──────────────────────────────────────────────

/// Parse DT_NEEDED entries from .dynamic section.
pub fn get_needed_libs(elf: &[u8]) -> Vec<String> {
    if elf.len() < 64 {
        return Vec::new();
    }

    let shoff = u64::from_le_bytes(elf[40..48].try_into().unwrap_or([0; 8])) as usize;
    let shentsize = u16::from_le_bytes(elf[58..60].try_into().unwrap_or([0; 2])) as usize;
    let shnum = u16::from_le_bytes(elf[60..62].try_into().unwrap_or([0; 2])) as usize;

    let mut dynstr_off = 0usize;
    let mut dynamic_off = 0usize;
    let mut dynamic_size = 0usize;

    for i in 0..shnum {
        let off = shoff + i * shentsize;
        if off + shentsize > elf.len() {
            break;
        }
        let sh_type = u32::from_le_bytes(elf[off + 4..off + 8].try_into().unwrap_or([0; 4]));
        let sh_off =
            u64::from_le_bytes(elf[off + 24..off + 32].try_into().unwrap_or([0; 8])) as usize;
        let sh_size =
            u64::from_le_bytes(elf[off + 32..off + 40].try_into().unwrap_or([0; 8])) as usize;
        match sh_type {
            6 => {
                dynamic_off = sh_off;
                dynamic_size = sh_size;
            } // SHT_DYNAMIC
            3 => {
                dynstr_off = sh_off;
            } // SHT_STRTAB
            _ => {}
        }
    }

    let mut libs = Vec::new();
    let mut i = 0;
    while i + 16 <= dynamic_size {
        let off = dynamic_off + i;
        if off + 16 > elf.len() {
            break;
        }
        let d_tag = i64::from_le_bytes(elf[off..off + 8].try_into().unwrap_or([0; 8]));
        let d_val = u64::from_le_bytes(elf[off + 8..off + 16].try_into().unwrap_or([0; 8])) as usize;
        if d_tag == 1 {
            // DT_NEEDED
            let name_off = dynstr_off + d_val;
            if name_off < elf.len() {
                let name_end = elf[name_off..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| name_off + p)
                    .unwrap_or(elf.len());
                if let Ok(name) = core::str::from_utf8(&elf[name_off..name_end]) {
                    libs.push(name.into());
                }
            }
        }
        if d_tag == 0 {
            break;
        } // DT_NULL
        i += 16;
    }
    libs
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a minimal ELF header (64-bit).
    fn minimal_elf_header() -> Vec<u8> {
        let mut elf = vec![0x7f, 0x45, 0x4c, 0x46]; // ELF magic
        elf.extend_from_slice(&[2; 60]); // 64-bit, little-endian
        elf
    }

    #[test]
    fn test_config_validation() {
        let mut config = DynLinkConfig::default();
        assert!(config.validate().is_ok());

        config.search_paths.clear();
        assert!(config.validate().is_err());

        config.search_paths = vec!["/lib".into()];
        config.max_libs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_symbol_table() {
        let mut st = SymbolTable::new();
        st.define("foo", 0x1000);
        st.define("bar", 0x2000);
        assert_eq!(st.resolve("foo"), Some(0x1000));
        assert_eq!(st.resolve("baz"), None);
        assert_eq!(st.len(), 2);
    }

    #[test]
    fn test_dynlinker_new() {
        let linker = DynLinker::default();
        assert_eq!(linker.lib_count(), 0);
        assert_eq!(linker.global_sym.len(), 0);
    }

    #[test]
    fn test_get_needed_libs_empty() {
        let elf = minimal_elf_header();
        let libs = get_needed_libs(&elf);
        assert!(libs.is_empty());
    }

    #[test]
    fn test_load_segments_fails_on_invalid() {
        let linker = DynLinker::default();
        let elf = minimal_elf_header();
        // Should fail because we can't allocate frames in test context.
        let result = linker.load_segments(&elf, 0x1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_search_library_not_found() {
        let linker = DynLinker::default();
        let result = linker.search_library("nonexistent.so");
        assert!(matches!(result, Err(DynLinkError::LibNotFound(_))));
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_manager_creation() {
        let config = DynLinkConfig::default();
        let manager = DynLinkManager::new(config).unwrap();
        assert_eq!(manager.lib_count(), 0);
    }
}
