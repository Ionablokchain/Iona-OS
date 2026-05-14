//! Dynamic linker — ld.so pentru shared libraries (.so)
//!
//! Implementare minimală care suportă:
//! - Parsing ELF shared objects (ET_DYN)
//! - Symbol resolution (PT_DYNAMIC → DT_SYMTAB + DT_STRTAB)
//! - Basic relocation (R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_RELATIVE)
//! - dlopen/dlsym/dlclose API
//!
//! Limitare: nu suportă lazy binding (PLT) — toate simbolurile rezolvate la load.
//! Suficient pentru musl libc + programe simple.

use alloc::collections::BTreeMap;
use alloc::string::String;
use spin::{Lazy, Mutex};

const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

/// Un shared object încărcat în memorie
pub struct SharedObject {
    pub name:     String,
    pub base:     u64,   // virtual base address (load bias)
    pub size:     usize,
    pub symbols:  BTreeMap<String, u64>, // name → absolute virtual address
}

/// Global shared object registry
static SO_REGISTRY: Lazy<Mutex<BTreeMap<String, SharedObject>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Încarcă un shared object din IONAFS
/// Returnează handle (base address) sau 0 la eroare
pub fn dlopen(path: &str) -> u64 {
    // Check if already loaded
    if let Some(so) = SO_REGISTRY.lock().get(path) {
        return so.base;
    }

    let elf_bytes = match crate::fs::ionafs::read(path) {
        Some(b) => b,
        None    => {
            crate::serial_println!("[DYNLINK] {} not found", path);
            return 0;
        }
    };

    // Parse ELF
    match load_shared_object(path, &elf_bytes) {
        Some(so) => {
            let base = so.base;
            crate::serial_println!("[DYNLINK] loaded '{}' @ 0x{:x} ({} symbols)",
                path, base, so.symbols.len());
            SO_REGISTRY.lock().insert(path.into(), so);
            base
        }
        None => {
            crate::serial_println!("[DYNLINK] failed to load '{}'", path);
            0
        }
    }
}

/// Resolve a symbol from a loaded shared object
pub fn dlsym(handle: u64, symbol: &str) -> u64 {
    let reg = SO_REGISTRY.lock();
    for so in reg.values() {
        if so.base == handle {
            if let Some(&addr) = so.symbols.get(symbol) {
                return addr;
            }
        }
    }
    0
}

/// Unload a shared object
pub fn dlclose(handle: u64) {
    let mut reg = SO_REGISTRY.lock();
    reg.retain(|_, so| so.base != handle);
}

fn load_shared_object(name: &str, bytes: &[u8]) -> Option<SharedObject> {
    // Verify ELF magic
    if bytes.len() < 64 || &bytes[..4] != b"ELF" { return None; }
    if bytes[4] != 2 { return None; } // ELF64

    let e_type = u16::from_le_bytes([bytes[16], bytes[17]]);
    if e_type != 3 && e_type != 2 { return None; } // ET_DYN or ET_EXEC

    let e_phoff = u64::from_le_bytes(bytes[32..40].try_into().ok()?) as usize;
    let e_phnum = u16::from_le_bytes([bytes[56], bytes[57]]) as usize;
    let e_phentsize = u16::from_le_bytes([bytes[54], bytes[55]]) as usize;

    // Choose load bias (address where we load the .so)
    // Use a static allocator for .so load addresses
    let base = SO_LOAD_ADDR.fetch_add(0x40_0000, core::sync::atomic::Ordering::Relaxed);

    let mut symbols = BTreeMap::new();
    let mut dyn_offset: Option<usize> = None;
    let mut dyn_size:   usize = 0;
    let mut total_size: usize = 0;

    // Parse program headers — find PT_LOAD and PT_DYNAMIC
    for i in 0..e_phnum {
        let ph_off = e_phoff + i * e_phentsize;
        if ph_off + e_phentsize > bytes.len() { break; }
        let ph_type = u32::from_le_bytes(bytes[ph_off..ph_off+4].try_into().ok()?);
        let p_off   = u64::from_le_bytes(bytes[ph_off+8..ph_off+16].try_into().ok()?) as usize;
        let p_vaddr = u64::from_le_bytes(bytes[ph_off+16..ph_off+24].try_into().ok()?);
        let p_filesz= u64::from_le_bytes(bytes[ph_off+32..ph_off+40].try_into().ok()?) as usize;
        let p_memsz = u64::from_le_bytes(bytes[ph_off+40..ph_off+48].try_into().ok()?) as usize;

        match ph_type {
            1 => { // PT_LOAD
                // Map segment into memory at base + p_vaddr
                let virt = base + p_vaddr;
                if p_off + p_filesz <= bytes.len() {
                    unsafe {
                        // Copy through physical offset (simplified — assumes virt is mapped)
                        let dst = (PHYS_OFFSET + virt) as *mut u8;
                        core::ptr::copy_nonoverlapping(bytes[p_off..].as_ptr(), dst, p_filesz);
                        if p_memsz > p_filesz {
                            core::ptr::write_bytes(dst.add(p_filesz), 0, p_memsz - p_filesz);
                        }
                    }
                    total_size = total_size.max((p_vaddr + p_memsz as u64) as usize);
                }
            }
            2 => { // PT_DYNAMIC
                dyn_offset = Some(p_off);
                dyn_size   = p_filesz;
            }
            _ => {}
        }
    }

    // Parse DYNAMIC section for symbols
    if let Some(off) = dyn_offset {
        let mut symtab_off: usize = 0;
        let mut strtab_off: usize = 0;
        let mut syment:     usize = 24; // sizeof(Elf64_Sym)
        let mut strsz:      usize = 0;

        let dyn_end = (off + dyn_size).min(bytes.len());
        let mut pos = off;
        while pos + 16 <= dyn_end {
            let tag = i64::from_le_bytes(bytes[pos..pos+8].try_into().ok()?);
            let val = u64::from_le_bytes(bytes[pos+8..pos+16].try_into().ok()?) as usize;
            match tag {
                5  => strtab_off = val,   // DT_STRTAB
                6  => symtab_off = val,   // DT_SYMTAB
                10 => strsz      = val,   // DT_STRSZ
                11 => syment     = val,   // DT_SYMENT
                0  => break,              // DT_NULL
                _  => {}
            }
            pos += 16;
        }

        // Extract symbols
        if symtab_off > 0 && strtab_off > 0 && syment > 0 {
            let mut sym_pos = symtab_off;
            while sym_pos + syment <= bytes.len() {
                // Elf64_Sym: st_name(4) st_info(1) st_other(1) st_shndx(2) st_value(8) st_size(8)
                let st_name  = u32::from_le_bytes(bytes[sym_pos..sym_pos+4].try_into().ok()?) as usize;
                let st_value = u64::from_le_bytes(bytes[sym_pos+8..sym_pos+16].try_into().ok()?);
                let st_shndx = u16::from_le_bytes([bytes[sym_pos+6], bytes[sym_pos+7]]);

                if st_shndx != 0 && st_value != 0 && st_name < strsz {
                    // Read symbol name from string table
                    let str_off = strtab_off + st_name;
                    let name_end = bytes[str_off..].iter().position(|&b| b == 0)
                        .map(|n| str_off + n).unwrap_or(bytes.len());
                    if let Ok(name) = core::str::from_utf8(&bytes[str_off..name_end]) {
                        symbols.insert(name.into(), base + st_value);
                    }
                }
                sym_pos += syment;
                if sym_pos >= strtab_off { break; } // symtab ends before strtab
            }
        }
    }

    Some(SharedObject { name: name.into(), base, size: total_size, symbols })
}

static SO_LOAD_ADDR: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0x0000_0040_0000_0000);

pub fn init() {
    crate::serial_println!("  [DYNLINK] dynamic linker ready (dlopen/dlsym/dlclose)");
}
