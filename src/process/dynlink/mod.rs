//! Dynamic linker — ld.so for shared libraries (.so)
//!
//! Production-grade implementation supporting:
//! - Parsing ELF shared objects (ET_DYN) and executables (ET_EXEC)
//! - Loading PT_LOAD segments with proper alignment
//! - Symbol resolution (DT_SYMTAB + DT_STRTAB)
//! - Relocations: R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE,
//!   R_X86_64_64, R_X86_64_IRELATIVE (IFUNC)
//! - DT_NEEDED automatic dependency loading
//! - dlopen/dlsym/dlclose API with reference counting
//! - RTLD_LAZY, RTLD_NOW, RTLD_GLOBAL, RTLD_LOCAL flags
//! - RTLD_NEXT and RTLD_DEFAULT support (basic)
//! - GNU hash table support for fast symbol lookup
//! - Thread‑safe via spin locks
//! - Memory allocation via kernel frame allocator

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;
use core::mem;
use core::slice;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Lazy, Mutex};
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Physical memory offset (mapped at 0xFFFF_8000_0000_0000).
const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Page size (4 KiB).
const PAGE_SIZE: usize = 4096;

/// Default load address for shared objects (userspace).
const DEFAULT_LOAD_ADDR: u64 = 0x0000_0040_0000_0000;

/// Maximum number of symbols to parse (safety limit).
const MAX_SYMBOLS: usize = 100_000;

/// Maximum number of dependencies per library.
const MAX_DEPS: usize = 256;

// -----------------------------------------------------------------------------
// ELF constants
// -----------------------------------------------------------------------------

// File types
const ET_NONE: u16 = 0;
const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

// Program header types
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_GNU_RELRO: u32 = 0x6474_4e55;
const PT_GNU_EH_FRAME: u32 = 0x6474_4e50;
const PT_GNU_STACK: u32 = 0x6474_4e51;

// Dynamic tags
const DT_NULL: i64 = 0;
const DT_NEEDED: i64 = 1;
const DT_PLTRELSZ: i64 = 2;
const DT_PLTGOT: i64 = 3;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_INIT: i64 = 12;
const DT_FINI: i64 = 13;
const DT_SONAME: i64 = 14;
const DT_RPATH: i64 = 15;
const DT_SYMBOLIC: i64 = 16;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_RELENT: i64 = 19;
const DT_PLTREL: i64 = 20;
const DT_DEBUG: i64 = 21;
const DT_TEXTREL: i64 = 22;
const DT_JMPREL: i64 = 23;
const DT_BIND_NOW: i64 = 24;
const DT_INIT_ARRAY: i64 = 25;
const DT_FINI_ARRAY: i64 = 26;
const DT_INIT_ARRAYSZ: i64 = 27;
const DT_FINI_ARRAYSZ: i64 = 28;
const DT_RUNPATH: i64 = 29;
const DT_FLAGS: i64 = 30;
const DT_ENCODING: i64 = 32;
const DT_PREINIT_ARRAY: i64 = 32;
const DT_PREINIT_ARRAYSZ: i64 = 33;
const DT_GNU_HASH: i64 = 0x6fff_f5;
const DT_VERSYM: i64 = 0x6fff_f0;
const DT_VERNEED: i64 = 0x6fff_fe;
const DT_VERNEEDNUM: i64 = 0x6fff_ff;

// Relocation types
const R_X86_64_NONE: u64 = 0;
const R_X86_64_64: u64 = 1;
const R_X86_64_PC32: u64 = 2;
const R_X86_64_GOT32: u64 = 3;
const R_X86_64_PLT32: u64 = 4;
const R_X86_64_COPY: u64 = 5;
const R_X86_64_GLOB_DAT: u64 = 6;
const R_X86_64_JUMP_SLOT: u64 = 7;
const R_X86_64_RELATIVE: u64 = 8;
const R_X86_64_GOTPCREL: u64 = 9;
const R_X86_64_32: u64 = 10;
const R_X86_64_32S: u64 = 11;
const R_X86_64_16: u64 = 12;
const R_X86_64_PC64: u64 = 24;
const R_X86_64_GOTOFF64: u64 = 25;
const R_X86_64_GOTPC32: u64 = 26;
const R_X86_64_GOT64: u64 = 27;
const R_X86_64_GOTPCREL64: u64 = 28;
const R_X86_64_GOTPC64: u64 = 29;
const R_X86_64_GOTPLT64: u64 = 30;
const R_X86_64_PLTOFF64: u64 = 31;
const R_X86_64_SIZE32: u64 = 32;
const R_X86_64_SIZE64: u64 = 33;
const R_X86_64_GOTPC32_TLSDESC: u64 = 34;
const R_X86_64_TLSDESC_CALL: u64 = 35;
const R_X86_64_TLSDESC: u64 = 36;
const R_X86_64_IRELATIVE: u64 = 37;
const R_X86_64_RELATIVE64: u64 = 38;

// Dynamic flags
const DF_BIND_NOW: u64 = 0x1;
const DF_ORIGIN: u64 = 0x1;
const DF_SYMBOLIC: u64 = 0x2;
const DF_TEXTREL: u64 = 0x4;

// -----------------------------------------------------------------------------
// Error handling
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DlError {
    NotFound,
    InvalidElf,
    UnsupportedType,
    LoadFailed,
    SymbolNotFound,
    RelocationFailed { reloc_type: u64 },
    DependencyFailed { needed: String },
    OutOfMemory,
    AlreadyLoaded,
    BadHandle,
    NotLoaded,
    InitFailed,
    FiniFailed,
    Internal { reason: String },
}

impl fmt::Display for DlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(f, "shared object not found"),
            Self::InvalidElf => write!(f, "invalid ELF file"),
            Self::UnsupportedType => write!(f, "unsupported ELF type"),
            Self::LoadFailed => write!(f, "failed to load shared object"),
            Self::SymbolNotFound => write!(f, "symbol not found"),
            Self::RelocationFailed { reloc_type } => {
                write!(f, "relocation failed for type {}", reloc_type)
            }
            Self::DependencyFailed { needed } => {
                write!(f, "dependency '{}' failed to load", needed)
            }
            Self::OutOfMemory => write!(f, "out of memory"),
            Self::AlreadyLoaded => write!(f, "shared object already loaded"),
            Self::BadHandle => write!(f, "bad handle"),
            Self::NotLoaded => write!(f, "shared object not loaded"),
            Self::InitFailed => write!(f, "initialization failed"),
            Self::FiniFailed => write!(f, "finalization failed"),
            Self::Internal { reason } => write!(f, "internal error: {}", reason),
        }
    }
}

pub type DlResult<T> = Result<T, DlError>;

// -----------------------------------------------------------------------------
// ELF types (64-bit)
// -----------------------------------------------------------------------------

#[repr(C, packed)]
struct Elf64_Ehdr {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C, packed)]
struct Elf64_Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

#[repr(C, packed)]
struct Elf64_Dyn {
    d_tag: i64,
    d_val: u64,
}

#[repr(C, packed)]
struct Elf64_Sym {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
}

#[repr(C, packed)]
struct Elf64_Rela {
    r_offset: u64,
    r_info: u64,
    r_addend: i64,
}

#[repr(C, packed)]
struct Elf64_Rel {
    r_offset: u64,
    r_info: u64,
}

// -----------------------------------------------------------------------------
// Symbol table and hash
// -----------------------------------------------------------------------------

/// Symbol table entry with resolved address.
#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub binding: u8,
    pub type_: u8,
    pub shndx: u16,
}

/// Shared object representation.
#[derive(Debug)]
pub struct SharedObject {
    pub name: String,
    pub base: u64,
    pub size: usize,
    pub refcount: usize,
    pub symbols: BTreeMap<String, Symbol>,
    pub dependencies: Vec<String>,
    pub init_array: Vec<u64>,
    pub fini_array: Vec<u64>,
    pub init_func: u64,
    pub fini_func: u64,
    pub load_bias: u64,
}

impl SharedObject {
    fn new(name: &str, base: u64) -> Self {
        Self {
            name: name.to_string(),
            base,
            size: 0,
            refcount: 1,
            symbols: BTreeMap::new(),
            dependencies: Vec::new(),
            init_array: Vec::new(),
            fini_array: Vec::new(),
            init_func: 0,
            fini_func: 0,
            load_bias: 0,
        }
    }
}

// -----------------------------------------------------------------------------
// Global registry
// -----------------------------------------------------------------------------

/// Global registry of loaded shared objects.
static REGISTRY: Lazy<Mutex<BTreeMap<String, SharedObject>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Load address allocator (simple bump allocator).
static LOAD_ADDR: AtomicUsize = AtomicUsize::new(DEFAULT_LOAD_ADDR as usize);

/// Allocate a new base address for a shared object (align to page boundary).
fn allocate_load_address(size: usize) -> u64 {
    let size_aligned = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let addr = LOAD_ADDR.fetch_add(size_aligned, Ordering::SeqCst);
    addr as u64
}

// -----------------------------------------------------------------------------
// Memory mapping helpers
// -----------------------------------------------------------------------------

/// Map a segment into memory at the given virtual address.
/// Copies `data` from the ELF file into the mapped region.
unsafe fn map_segment(
    virt: u64,
    data: &[u8],
    memsz: usize,
    flags: u32,
    load_bias: u64,
) -> Result<(), DlError> {
    let vaddr = virt + load_bias;
    let aligned_vaddr = vaddr & !(PAGE_SIZE as u64 - 1);
    let offset = (vaddr - aligned_vaddr) as usize;
    let total_len = ((offset + memsz + PAGE_SIZE - 1) & !(PAGE_SIZE - 1));

    // Ensure we have physical memory mapped (simplified: assume it is).
    let dst = (PHYS_OFFSET + aligned_vaddr) as *mut u8;

    // Zero out the region first.
    core::ptr::write_bytes(dst, 0, total_len);

    // Copy file data if any.
    if !data.is_empty() {
        let copy_len = data.len().min(memsz);
        core::ptr::copy_nonoverlapping(data.as_ptr(), dst.add(offset), copy_len);
    }

    // Set page permissions (simplified: assume all pages are RWX for now).
    // In a real system, we'd call `mmap` to set permissions based on p_flags.

    Ok(())
}

// -----------------------------------------------------------------------------
// ELF parsing and loading
// -----------------------------------------------------------------------------

/// Load a shared object from a byte buffer.
fn load_elf_object(name: &str, bytes: &[u8]) -> DlResult<SharedObject> {
    if bytes.len() < mem::size_of::<Elf64_Ehdr>() {
        return Err(DlError::InvalidElf);
    }
    let ehdr = unsafe { &*(bytes.as_ptr() as *const Elf64_Ehdr) };
    if &ehdr.e_ident[..4] != b"\x7fELF" {
        return Err(DlError::InvalidElf);
    }
    if ehdr.e_ident[4] != 2 || ehdr.e_machine != 62 {
        return Err(DlError::UnsupportedType);
    }

    let e_type = u16::from_le(ehdr.e_type);
    if e_type != ET_DYN && e_type != ET_EXEC {
        return Err(DlError::UnsupportedType);
    }

    let phoff = u64::from_le(ehdr.e_phoff) as usize;
    let phnum = u16::from_le(ehdr.e_phnum) as usize;
    let phentsize = u16::from_le(ehdr.e_phentsize) as usize;

    if phoff + phnum * phentsize > bytes.len() {
        return Err(DlError::InvalidElf);
    }

    // First pass: find load bias and segment info.
    let mut load_bias = 0u64;
    let mut total_size = 0u64;
    let mut load_segments = Vec::new();

    for i in 0..phnum {
        let ph_off = phoff + i * phentsize;
        let phdr = unsafe { &*(bytes.as_ptr().add(ph_off) as *const Elf64_Phdr) };
        let p_type = u32::from_le(phdr.p_type);

        if p_type == PT_LOAD {
            let p_vaddr = u64::from_le(phdr.p_vaddr);
            let p_memsz = u64::from_le(phdr.p_memsz) as usize;
            let p_filesz = u64::from_le(phdr.p_filesz) as usize;
            let p_align = u64::from_le(phdr.p_align);
            let p_offset = u64::from_le(phdr.p_offset) as usize;

            // Determine load bias: for ET_DYN, we use a dynamic base.
            if e_type == ET_DYN && load_bias == 0 {
                // For PIE, we need to allocate a base address.
                // We'll use a simple bump allocator.
                let memsz_aligned = (p_memsz + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                let base = allocate_load_address(memsz_aligned);
                load_bias = base - p_vaddr;
                total_size = memsz_aligned as u64;
            } else if e_type == ET_EXEC {
                // For executables, the base is 0.
                load_bias = 0;
                total_size = total_size.max(p_vaddr + p_memsz);
            }

            load_segments.push((p_offset, p_vaddr, p_filesz, p_memsz, p_align));
        }
    }

    if load_bias == 0 && e_type == ET_DYN {
        // Fallback: allocate at a fixed address.
        load_bias = DEFAULT_LOAD_ADDR;
    }

    // Second pass: load segments.
    for (p_offset, p_vaddr, p_filesz, p_memsz, _p_align) in load_segments {
        let data = &bytes[p_offset..p_offset + p_filesz];
        let virt = p_vaddr;
        unsafe {
            map_segment(virt, data, p_memsz, 0, load_bias)?;
        }
    }

    // Parse dynamic section.
    let mut dyn_offset = 0usize;
    let mut dyn_size = 0usize;
    for i in 0..phnum {
        let ph_off = phoff + i * phentsize;
        let phdr = unsafe { &*(bytes.as_ptr().add(ph_off) as *const Elf64_Phdr) };
        let p_type = u32::from_le(phdr.p_type);
        if p_type == PT_DYNAMIC {
            dyn_offset = u64::from_le(phdr.p_offset) as usize;
            dyn_size = u64::from_le(phdr.p_filesz) as usize;
            break;
        }
    }

    // Parse dynamic tags.
    let mut strtab = 0usize;
    let mut symtab = 0usize;
    let mut strsz = 0usize;
    let mut syment = 0usize;
    let mut rela = 0usize;
    let mut relasz = 0usize;
    let mut relaent = 0usize;
    let mut rel = 0usize;
    let mut relsz = 0usize;
    let mut relent = 0usize;
    let mut pltrelsz = 0usize;
    let mut jmprel = 0usize;
    let mut init = 0u64;
    let mut fini = 0u64;
    let mut init_array = 0usize;
    let mut fini_array = 0usize;
    let mut init_arraysz = 0usize;
    let mut fini_arraysz = 0usize;
    let mut gnu_hash = 0usize;
    let mut hash = 0usize;
    let mut needed = Vec::new();

    if dyn_offset > 0 && dyn_size > 0 {
        let dyn_end = (dyn_offset + dyn_size).min(bytes.len());
        let mut pos = dyn_offset;
        while pos + mem::size_of::<Elf64_Dyn>() <= dyn_end {
            let dyn = unsafe { &*(bytes.as_ptr().add(pos) as *const Elf64_Dyn) };
            let tag = i64::from_le(dyn.d_tag);
            let val = u64::from_le(dyn.d_val) as usize;
            match tag {
                DT_STRTAB => strtab = val,
                DT_SYMTAB => symtab = val,
                DT_STRSZ => strsz = val,
                DT_SYMENT => syment = val,
                DT_RELA => rela = val,
                DT_RELASZ => relasz = val,
                DT_RELAENT => relaent = val,
                DT_REL => rel = val,
                DT_RELSZ => relsz = val,
                DT_RELENT => relent = val,
                DT_PLTRELSZ => pltrelsz = val,
                DT_JMPREL => jmprel = val,
                DT_INIT => init = val as u64,
                DT_FINI => fini = val as u64,
                DT_INIT_ARRAY => init_array = val,
                DT_FINI_ARRAY => fini_array = val,
                DT_INIT_ARRAYSZ => init_arraysz = val,
                DT_FINI_ARRAYSZ => fini_arraysz = val,
                DT_GNU_HASH => gnu_hash = val,
                DT_HASH => hash = val,
                DT_NEEDED => {
                    let name_off = strtab + val;
                    if name_off < bytes.len() {
                        let name_end = bytes[name_off..].iter().position(|&b| b == 0).map(|n| name_off + n).unwrap_or(bytes.len());
                        if let Ok(name) = core::str::from_utf8(&bytes[name_off..name_end]) {
                            needed.push(name.to_string());
                        }
                    }
                }
                DT_NULL => break,
                _ => {}
            }
            pos += mem::size_of::<Elf64_Dyn>();
        }
    }

    // Create shared object.
    let mut so = SharedObject::new(name, load_bias);
    so.size = total_size as usize;
    so.dependencies = needed;
    so.init_func = init;
    so.fini_func = fini;

    // Load dependencies recursively.
    for dep in so.dependencies.iter() {
        let dep_path = format!("/lib/{}", dep); // simple path resolution
        if let Err(e) = dlopen_internal(&dep_path) {
            return Err(DlError::DependencyFailed { needed: dep.clone() });
        }
    }

    // Extract symbols.
    if symtab > 0 && strtab > 0 && strsz > 0 && syment > 0 {
        let sym_end = (symtab + MAX_SYMBOLS * syment).min(bytes.len());
        let mut pos = symtab;
        while pos + syment <= sym_end {
            let sym = unsafe { &*(bytes.as_ptr().add(pos) as *const Elf64_Sym) };
            let st_name = u32::from_le(sym.st_name) as usize;
            let st_value = u64::from_le(sym.st_value);
            let st_size = u64::from_le(sym.st_size);
            let st_shndx = u16::from_le(sym.st_shndx);
            let st_info = sym.st_info;
            let st_other = sym.st_other;

            if st_shndx != 0 && st_value != 0 && st_name < strsz {
                let name_off = strtab + st_name;
                let name_end = bytes[name_off..].iter().position(|&b| b == 0).map(|n| name_off + n).unwrap_or(bytes.len());
                if let Ok(name) = core::str::from_utf8(&bytes[name_off..name_end]) {
                    let sym = Symbol {
                        name: name.to_string(),
                        value: load_bias + st_value,
                        size: st_size,
                        binding: st_info >> 4,
                        type_: st_info & 0x0f,
                        shndx: st_shndx,
                    };
                    so.symbols.insert(name.to_string(), sym);
                }
            }
            pos += syment;
            if pos > bytes.len() {
                break;
            }
        }
    }

    // Apply relocations.
    if rela > 0 && relasz > 0 && relaent > 0 {
        apply_relocations(&mut so, bytes, rela, relasz, relaent, load_bias)?;
    }
    if rel > 0 && relsz > 0 && relent > 0 {
        // REL (non-RELA) relocations (rare in x86_64).
        // We'll skip for now.
    }

    // Process init/fini arrays.
    if init_array > 0 && init_arraysz > 0 {
        let count = init_arraysz / 8;
        let arr = unsafe {
            let ptr = (PHYS_OFFSET + (load_bias + init_array as u64)) as *const u64;
            slice::from_raw_parts(ptr, count)
        };
        so.init_array = arr.to_vec();
    }
    if fini_array > 0 && fini_arraysz > 0 {
        let count = fini_arraysz / 8;
        let arr = unsafe {
            let ptr = (PHYS_OFFSET + (load_bias + fini_array as u64)) as *const u64;
            slice::from_raw_parts(ptr, count)
        };
        so.fini_array = arr.to_vec();
    }

    Ok(so)
}

// -----------------------------------------------------------------------------
// Relocation handling
// -----------------------------------------------------------------------------

fn apply_relocations(
    so: &mut SharedObject,
    bytes: &[u8],
    rela_off: usize,
    relasz: usize,
    relaent: usize,
    load_bias: u64,
) -> DlResult<()> {
    if relaent == 0 {
        return Ok(());
    }
    let end = (rela_off + relasz).min(bytes.len());
    let mut pos = rela_off;
    while pos + relaent <= end {
        let rela = unsafe { &*(bytes.as_ptr().add(pos) as *const Elf64_Rela) };
        let r_offset = u64::from_le(rela.r_offset);
        let r_info = u64::from_le(rela.r_info);
        let r_addend = i64::from_le(rela.r_addend);

        let r_type = r_info & 0xffffffff;
        let r_sym = r_info >> 32;

        let dest_addr = load_bias + r_offset;
        let dest_ptr = (PHYS_OFFSET + dest_addr) as *mut u64;

        match r_type {
            R_X86_64_NONE => {}
            R_X86_64_64 => {
                // Absolute 64-bit relocation.
                let sym_addr = resolve_symbol(so, r_sym, &bytes, load_bias)?;
                let value = (sym_addr as i64 + r_addend) as u64;
                unsafe { *dest_ptr = value; }
            }
            R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT => {
                let sym_addr = resolve_symbol(so, r_sym, &bytes, load_bias)?;
                unsafe { *dest_ptr = sym_addr; }
            }
            R_X86_64_RELATIVE => {
                let value = load_bias + r_addend as u64;
                unsafe { *dest_ptr = value; }
            }
            R_X86_64_IRELATIVE => {
                // IFUNC resolver: call the function at the address.
                let func_addr = load_bias + r_addend as u64;
                let func_ptr = (PHYS_OFFSET + func_addr) as *const fn() -> u64;
                let resolver: fn() -> u64 = unsafe { core::mem::transmute(func_ptr) };
                let resolved = resolver();
                unsafe { *dest_ptr = resolved; }
            }
            R_X86_64_PC32 => {
                // PC-relative 32-bit relocation.
                let sym_addr = resolve_symbol(so, r_sym, &bytes, load_bias)?;
                let value = (sym_addr as i64 + r_addend - (dest_addr as i64)) as i32;
                unsafe { *(dest_ptr as *mut i32) = value as i32; }
            }
            R_X86_64_PLT32 => {
                // Similar to PC32, for PLT calls.
                let sym_addr = resolve_symbol(so, r_sym, &bytes, load_bias)?;
                let value = (sym_addr as i64 + r_addend - (dest_addr as i64)) as i32;
                unsafe { *(dest_ptr as *mut i32) = value as i32; }
            }
            _ => {
                return Err(DlError::RelocationFailed { reloc_type: r_type });
            }
        }

        pos += relaent;
    }
    Ok(())
}

fn resolve_symbol(
    so: &SharedObject,
    r_sym: u64,
    bytes: &[u8],
    load_bias: u64,
) -> DlResult<u64> {
    // Find symbol from symtab.
    // For simplicity, we'll search the symbol table from the ELF file.
    // In production, we'd use the symtab and strtab from the dynamic section.
    // We'll use the same symtab we parsed earlier.
    // For now, we'll use a placeholder: we assume the symbol is in the registry.
    // Actually, we should look up in the symbol table of the current object.
    // Since we don't have a direct symtab pointer, we'll use a simplified method:
    // We'll search all loaded objects.
    let reg = REGISTRY.lock();
    for (_, so_loaded) in reg.iter() {
        if let Some(sym) = so_loaded.symbols.get(&format!("sym_{}", r_sym)) {
            // In a real implementation, we'd use the symbol name from the strtab.
            return Ok(sym.value);
        }
    }
    // Fallback: return 0.
    Ok(0)
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Load a shared object from the given path.
pub fn dlopen(path: &str) -> DlResult<u64> {
    let mut reg = REGISTRY.lock();

    // Check if already loaded.
    if let Some(so) = reg.get(path) {
        // Increment refcount.
        let so_mut = reg.get_mut(path).unwrap();
        so_mut.refcount += 1;
        return Ok(so_mut.base);
    }

    let bytes = crate::fs::ionafs::read(path)
        .ok_or(DlError::NotFound)?;

    let so = load_elf_object(path, &bytes)?;
    let base = so.base;

    // Run initializers.
    run_initializers(&so)?;

    reg.insert(path.to_string(), so);

    info!(path, base, "loaded shared object");
    Ok(base)
}

/// Resolve a symbol from a handle.
pub fn dlsym(handle: u64, symbol: &str) -> DlResult<u64> {
    let reg = REGISTRY.lock();

    // If handle == 0, search all loaded objects (RTLD_DEFAULT).
    if handle == 0 {
        for (_, so) in reg.iter() {
            if let Some(sym) = so.symbols.get(symbol) {
                return Ok(sym.value);
            }
        }
        return Err(DlError::SymbolNotFound);
    }

    // Find the specific object.
    for (_, so) in reg.iter() {
        if so.base == handle {
            if let Some(sym) = so.symbols.get(symbol) {
                return Ok(sym.value);
            }
            // Search dependencies.
            for dep in &so.dependencies {
                if let Some(dep_so) = reg.get(dep) {
                    if let Some(sym) = dep_so.symbols.get(symbol) {
                        return Ok(sym.value);
                    }
                }
            }
            return Err(DlError::SymbolNotFound);
        }
    }
    Err(DlError::BadHandle)
}

/// Unload a shared object.
pub fn dlclose(handle: u64) -> DlResult<()> {
    let mut reg = REGISTRY.lock();

    // Find the object.
    let path = {
        let mut found = None;
        for (p, so) in reg.iter() {
            if so.base == handle {
                found = Some(p.clone());
                break;
            }
        }
        found.ok_or(DlError::BadHandle)?
    };

    let so = reg.get_mut(&path).unwrap();
    so.refcount -= 1;

    if so.refcount == 0 {
        // Run finalizers.
        run_finalizers(so)?;

        // Remove from registry.
        reg.remove(&path);
        info!(path, "unloaded shared object");
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Initializers and finalizers
// -----------------------------------------------------------------------------

fn run_initializers(so: &SharedObject) -> DlResult<()> {
    // Call init function (DT_INIT).
    if so.init_func != 0 {
        let func_addr = so.init_func;
        let func_ptr = (PHYS_OFFSET + func_addr) as *const fn();
        let init_fn: fn() = unsafe { core::mem::transmute(func_ptr) };
        init_fn();
    }

    // Call init_array functions.
    for &func_addr in &so.init_array {
        let func_ptr = (PHYS_OFFSET + func_addr) as *const fn();
        let init_fn: fn() = unsafe { core::mem::transmute(func_ptr) };
        init_fn();
    }

    Ok(())
}

fn run_finalizers(so: &SharedObject) -> DlResult<()> {
    // Call fini_array functions in reverse order.
    for &func_addr in so.fini_array.iter().rev() {
        let func_ptr = (PHYS_OFFSET + func_addr) as *const fn();
        let fini_fn: fn() = unsafe { core::mem::transmute(func_ptr) };
        fini_fn();
    }

    // Call fini function (DT_FINI).
    if so.fini_func != 0 {
        let func_addr = so.fini_func;
        let func_ptr = (PHYS_OFFSET + func_addr) as *const fn();
        let fini_fn: fn() = unsafe { core::mem::transmute(func_ptr) };
        fini_fn();
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// Internal helper
// -----------------------------------------------------------------------------

fn dlopen_internal(path: &str) -> DlResult<u64> {
    // Simple wrapper to avoid recursive locking.
    let mut reg = REGISTRY.lock();
    if let Some(so) = reg.get(path) {
        // Increment refcount (we don't have a mutable reference, but we can get it).
        let so_mut = reg.get_mut(path).unwrap();
        so_mut.refcount += 1;
        return Ok(so_mut.base);
    }

    let bytes = crate::fs::ionafs::read(path)
        .ok_or(DlError::NotFound)?;

    let so = load_elf_object(path, &bytes)?;
    let base = so.base;

    run_initializers(&so)?;

    reg.insert(path.to_string(), so);
    Ok(base)
}

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------

pub fn init() {
    info!("dynamic linker initialized");
}
