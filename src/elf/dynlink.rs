//! Dynamic linker — loads shared libraries (.so) at runtime
//!
//! Implements the minimal dynamic linking needed for musl libc compat:
//!   1. Parse ELF DT_NEEDED entries (required shared libraries)
//!   2. Search library path (/lib, /usr/lib) in IONAFS
//!   3. Load library ELF segments into address space
//!   4. Resolve undefined symbols via global symbol table
//!   5. Apply relocations (R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT, R_X86_64_64)
//!
//! This is the foundation; full ld.so compatibility is a longer effort.

use alloc::{collections::BTreeMap, string::String, vec::Vec, format};

#[derive(Debug)]
pub enum DynLinkError {
    LibNotFound(String),
    InvalidElf,
    RelocationFail,
    SymbolNotFound(String),
}

/// Symbol table: name → virtual address
pub struct SymbolTable {
    pub symbols: BTreeMap<String, u64>,
}

impl SymbolTable {
    pub fn new() -> Self { Self { symbols: BTreeMap::new() } }

    pub fn define(&mut self, name: &str, addr: u64) {
        self.symbols.insert(name.into(), addr);
    }

    pub fn resolve(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).copied()
    }
}

/// Loaded shared library
pub struct SharedLib {
    pub name:     String,
    pub base:     u64,   // load base address
    pub symbols:  SymbolTable,
}

/// Dynamic linker state for one process
pub struct DynLinker {
    pub libs:       Vec<SharedLib>,
    pub global_sym: SymbolTable, // merged symbol table
    pub search_path: Vec<String>,
}

impl DynLinker {
    pub fn new() -> Self {
        Self {
            libs: Vec::new(),
            global_sym: SymbolTable::new(),
            search_path: alloc::vec!["/lib".into(), "/usr/lib".into(), "/usr/local/lib".into()],
        }
    }

    /// Load a shared library by name (e.g., "libc.so.6")
    pub fn load_library(&mut self, name: &str) -> Result<(), DynLinkError> {
        // Already loaded?
        if self.libs.iter().any(|l| l.name == name) { return Ok(()); }

        // Search library paths
        let elf_bytes = self.search_path.iter()
            .find_map(|path| {
                let full = format!("{}/{}", path, name);
                crate::fs::ionafs::read(&full)
            })
            .ok_or_else(|| DynLinkError::LibNotFound(name.into()))?;

        // Verify ELF magic
        if elf_bytes.len() < 4 || &elf_bytes[..4] != b"ELF" {
            return Err(DynLinkError::InvalidElf);
        }

        // Parse ELF and load segments (reuse kernel ELF loader)
        let base = self.next_load_addr();
        crate::serial_println!("  [DYNLINK] loading '{}' at 0x{:x}", name, base);

        self.load_segments(&elf_bytes, base)?;

        // Extract exported symbols from .dynsym
        let syms = self.parse_dynsym(&elf_bytes, base);
        let n_syms = syms.len();

        let mut lib = SharedLib { name: name.into(), base, symbols: SymbolTable::new() };
        for (name, addr) in syms {
            lib.symbols.define(&name, addr);
            self.global_sym.define(&name, addr);
        }

        self.libs.push(lib);
        crate::serial_println!("  [DYNLINK] '{}': {} symbols exported", name, n_syms);
        Ok(())
    }

    /// Apply relocations for an ELF (after loading all required libs).
    ///
    /// Supported relocation types (x86_64 ELF ABI):
    ///   R_X86_64_64         (1):  S + A          — absolute 64-bit
    ///   R_X86_64_COPY       (5):  memcpy from shared lib symbol
    ///   R_X86_64_GLOB_DAT   (6):  S             — GOT data pointer
    ///   R_X86_64_JUMP_SLOT  (7):  S             — PLT function pointer
    ///   R_X86_64_RELATIVE   (8):  B + A         — base-relative (no symbol)
    ///   R_X86_64_TPOFF64   (18):  S - TLS_BASE  — thread-local offset
    ///   R_X86_64_DTPMOD64  (16):  module ID     — TLS module index
    ///   R_X86_64_DTPOFF64  (17):  S             — TLS offset in module
    ///   R_X86_64_IRELATIVE (37):  indirect (call resolver at B + A)
    pub fn apply_relocations(&self, elf_bytes: &[u8], base: u64) -> Result<(), DynLinkError> {
        if elf_bytes.len() < 64 { return Ok(()); }

        // First, build a local symbol lookup from .dynsym + .dynstr
        let local_syms = self.parse_dynsym(elf_bytes, base);

        let shoff     = u64::from_le_bytes(elf_bytes[40..48].try_into().unwrap_or([0;8]));
        let shentsize = u16::from_le_bytes(elf_bytes[58..60].try_into().unwrap_or([0;2])) as usize;
        let shnum     = u16::from_le_bytes(elf_bytes[60..62].try_into().unwrap_or([0;2])) as usize;

        // Gather .dynsym info for index-based lookup
        let (dynsym_off, dynsym_size, dynstr_off, dynstr_size) =
            self.find_dynsym_dynstr(elf_bytes);

        for i in 0..shnum {
            let off = shoff as usize + i * shentsize;
            if off + shentsize > elf_bytes.len() { break; }
            let sh_type = u32::from_le_bytes(elf_bytes[off+4..off+8].try_into().unwrap_or([0;4]));
            if sh_type != 4 { continue; } // SHT_RELA = 4

            let sh_offset = u64::from_le_bytes(elf_bytes[off+24..off+32].try_into().unwrap_or([0;8]));
            let sh_size   = u64::from_le_bytes(elf_bytes[off+32..off+40].try_into().unwrap_or([0;8]));
            let n_entries = sh_size / 24;

            for j in 0..n_entries {
                let roff = sh_offset as usize + j as usize * 24;
                if roff + 24 > elf_bytes.len() { break; }
                let r_offset = u64::from_le_bytes(elf_bytes[roff..roff+8].try_into().unwrap_or([0;8]));
                let r_info   = u64::from_le_bytes(elf_bytes[roff+8..roff+16].try_into().unwrap_or([0;8]));
                let r_addend = i64::from_le_bytes(elf_bytes[roff+16..roff+24].try_into().unwrap_or([0;8]));

                let sym_idx = (r_info >> 32) as usize;
                let r_type  = (r_info & 0xFFFF_FFFF) as u32;

                let target_virt = base + r_offset;

                // Resolve symbol value by index from .dynsym
                let sym_value = if sym_idx > 0 {
                    self.resolve_sym_by_index(elf_bytes, sym_idx,
                        dynsym_off, dynstr_off, dynstr_size, base)
                } else { 0u64 };

                match r_type {
                    1 => { // R_X86_64_64: S + A
                        let val = sym_value.wrapping_add(r_addend as u64);
                        unsafe { (target_virt as *mut u64).write_unaligned(val); }
                    }
                    5 => { // R_X86_64_COPY: copy symbol data from shared lib
                        if sym_value != 0 {
                            // Get symbol size from .dynsym entry
                            let sym_size = self.get_sym_size(elf_bytes, sym_idx, dynsym_off);
                            if sym_size > 0 {
                                unsafe {
                                    core::ptr::copy_nonoverlapping(
                                        sym_value as *const u8,
                                        target_virt as *mut u8,
                                        sym_size as usize,
                                    );
                                }
                            }
                        }
                    }
                    6 => { // R_X86_64_GLOB_DAT: S
                        unsafe { (target_virt as *mut u64).write_unaligned(sym_value); }
                    }
                    7 => { // R_X86_64_JUMP_SLOT: S (PLT eager binding)
                        unsafe { (target_virt as *mut u64).write_unaligned(sym_value); }
                    }
                    8 => { // R_X86_64_RELATIVE: B + A (no symbol needed)
                        let val = base.wrapping_add(r_addend as u64);
                        unsafe { (target_virt as *mut u64).write_unaligned(val); }
                    }
                    16 => { // R_X86_64_DTPMOD64: TLS module ID
                        // For single-module executables, module ID = 1
                        unsafe { (target_virt as *mut u64).write_unaligned(1); }
                    }
                    17 => { // R_X86_64_DTPOFF64: TLS offset in module
                        unsafe { (target_virt as *mut u64).write_unaligned(sym_value); }
                    }
                    18 => { // R_X86_64_TPOFF64: S - TLS_BASE (static TLS)
                        // For static TLS model, the offset is stored directly
                        let val = sym_value.wrapping_add(r_addend as u64);
                        unsafe { (target_virt as *mut u64).write_unaligned(val); }
                    }
                    37 => { // R_X86_64_IRELATIVE: call resolver at B + A
                        let resolver_addr = base.wrapping_add(r_addend as u64);
                        // The resolver function returns the actual address
                        // In kernel context, we store the resolver result
                        unsafe { (target_virt as *mut u64).write_unaligned(resolver_addr); }
                    }
                    _ => {
                        // Unknown relocation type — log and skip
                        crate::serial_println!("  [DYNLINK] unknown reloc type {} at 0x{:x}",
                            r_type, target_virt);
                    }
                }
            }
        }
        Ok(())
    }

    /// Resolve a symbol by its .dynsym index — first check local .dynsym,
    /// then fall back to the global symbol table.
    fn resolve_sym_by_index(&self, elf: &[u8], sym_idx: usize,
        dynsym_off: usize, dynstr_off: usize, dynstr_size: usize, base: u64) -> u64
    {
        if dynsym_off == 0 || dynstr_off == 0 { return 0; }
        let sym_off = dynsym_off + sym_idx * 24; // Elf64_Sym = 24 bytes
        if sym_off + 24 > elf.len() { return 0; }

        let st_name  = u32::from_le_bytes(elf[sym_off..sym_off+4].try_into().unwrap_or([0;4])) as usize;
        let st_value = u64::from_le_bytes(elf[sym_off+8..sym_off+16].try_into().unwrap_or([0;8]));
        let st_shndx = u16::from_le_bytes(elf[sym_off+6..sym_off+8].try_into().unwrap_or([0;2]));

        // If symbol is defined locally (shndx != SHN_UNDEF), use local value
        if st_shndx != 0 && st_value != 0 {
            return base + st_value;
        }

        // Undefined symbol — look up by name in global symbol table
        let name_start = dynstr_off + st_name;
        if name_start >= elf.len() { return 0; }
        let name_end = elf[name_start..elf.len().min(dynstr_off + dynstr_size)]
            .iter().position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(elf.len());
        if let Ok(name) = core::str::from_utf8(&elf[name_start..name_end]) {
            if let Some(addr) = self.global_sym.resolve(name) {
                return addr;
            }
        }
        0
    }

    /// Get symbol size from .dynsym entry
    fn get_sym_size(&self, elf: &[u8], sym_idx: usize, dynsym_off: usize) -> u64 {
        let sym_off = dynsym_off + sym_idx * 24;
        if sym_off + 24 > elf.len() { return 0; }
        u64::from_le_bytes(elf[sym_off+16..sym_off+24].try_into().unwrap_or([0;8]))
    }

    /// Find .dynsym and .dynstr section offsets/sizes
    fn find_dynsym_dynstr(&self, elf: &[u8]) -> (usize, usize, usize, usize) {
        if elf.len() < 64 { return (0, 0, 0, 0); }
        let shoff     = u64::from_le_bytes(elf[40..48].try_into().unwrap_or([0;8])) as usize;
        let shentsize = u16::from_le_bytes(elf[58..60].try_into().unwrap_or([0;2])) as usize;
        let shnum     = u16::from_le_bytes(elf[60..62].try_into().unwrap_or([0;2])) as usize;
        let shstrndx  = u16::from_le_bytes(elf[62..64].try_into().unwrap_or([0;2])) as usize;

        let mut dynsym_off = 0; let mut dynsym_size = 0;
        let mut dynstr_off = 0; let mut dynstr_size = 0;

        for i in 0..shnum {
            let off = shoff + i * shentsize;
            if off + shentsize > elf.len() { break; }
            let sh_type = u32::from_le_bytes(elf[off+4..off+8].try_into().unwrap_or([0;4]));
            let sh_off  = u64::from_le_bytes(elf[off+24..off+32].try_into().unwrap_or([0;8])) as usize;
            let sh_size = u64::from_le_bytes(elf[off+32..off+40].try_into().unwrap_or([0;8])) as usize;
            match sh_type {
                11 => { dynsym_off = sh_off; dynsym_size = sh_size; }
                3 if i != shstrndx => { dynstr_off = sh_off; dynstr_size = sh_size; }
                _ => {}
            }
        }
        (dynsym_off, dynsym_size, dynstr_off, dynstr_size)
    }

    /// Parse .dynsym and .dynstr sections to extract exported symbols
    fn parse_dynsym(&self, elf: &[u8], base: u64) -> Vec<(String, u64)> {
        if elf.len() < 64 { return Vec::new(); }

        // ELF64 header fields
        let shoff     = u64::from_le_bytes(elf[40..48].try_into().unwrap_or([0;8])) as usize;
        let shentsize = u16::from_le_bytes(elf[58..60].try_into().unwrap_or([0;2])) as usize;
        let shnum     = u16::from_le_bytes(elf[60..62].try_into().unwrap_or([0;2])) as usize;
        let shstrndx  = u16::from_le_bytes(elf[62..64].try_into().unwrap_or([0;2])) as usize;

        if shoff == 0 || shentsize == 0 || shnum == 0 { return Vec::new(); }

        // Find .dynstr (SHT_STRTAB=3 linked from .dynsym)
        let mut dynstr_off  = 0usize;
        let mut dynstr_size = 0usize;
        let mut dynsym_off  = 0usize;
        let mut dynsym_size = 0usize;

        for i in 0..shnum {
            let off = shoff + i * shentsize;
            if off + shentsize > elf.len() { break; }
            let sh_type = u32::from_le_bytes(elf[off+4..off+8].try_into().unwrap_or([0;4]));
            let sh_off  = u64::from_le_bytes(elf[off+24..off+32].try_into().unwrap_or([0;8])) as usize;
            let sh_size = u64::from_le_bytes(elf[off+32..off+40].try_into().unwrap_or([0;8])) as usize;
            match sh_type {
                11 => { dynsym_off = sh_off; dynsym_size = sh_size; } // SHT_DYNSYM
                3  if i != shstrndx => { dynstr_off = sh_off; dynstr_size = sh_size; } // SHT_STRTAB (not shstrtab)
                _  => {}
            }
        }

        if dynsym_off == 0 || dynstr_off == 0 { return Vec::new(); }

        // ELF64 symbol entry = 24 bytes
        let mut symbols = Vec::new();
        let mut i = 0;
        while i + 24 <= dynsym_size {
            let sym_off = dynsym_off + i;
            if sym_off + 24 > elf.len() { break; }

            let st_name  = u32::from_le_bytes(elf[sym_off..sym_off+4].try_into().unwrap_or([0;4])) as usize;
            let st_info  = elf[sym_off + 4];
            let st_value = u64::from_le_bytes(elf[sym_off+8..sym_off+16].try_into().unwrap_or([0;8]));

            // Only global/weak defined symbols (STB_GLOBAL=1, STB_WEAK=2, STT_FUNC=2, STT_OBJECT=1)
            let bind = (st_info >> 4) & 0xF;
            let stype = st_info & 0xF;
            if (bind == 1 || bind == 2) && (stype == 1 || stype == 2) && st_value != 0 {
                // Get name from .dynstr
                if dynstr_off + st_name < dynstr_off + dynstr_size {
                    let name_start = dynstr_off + st_name;
                    let name_end   = elf[name_start..dynstr_off + dynstr_size]
                        .iter().position(|&b| b == 0)
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

    /// Load ELF PT_LOAD segments at base address into physical memory
    fn load_segments(&self, elf: &[u8], base: u64) -> Result<(), DynLinkError> {
        if elf.len() < 64 { return Err(DynLinkError::InvalidElf); }
        let phoff     = u64::from_le_bytes(elf[32..40].try_into().unwrap_or([0;8])) as usize;
        let phentsize = u16::from_le_bytes(elf[54..56].try_into().unwrap_or([0;2])) as usize;
        let phnum     = u16::from_le_bytes(elf[56..58].try_into().unwrap_or([0;2])) as usize;
        let phys_off  = 0xFFFF_8000_0000_0000u64;

        for i in 0..phnum {
            let off = phoff + i * phentsize;
            if off + phentsize > elf.len() { break; }
            let p_type   = u32::from_le_bytes(elf[off..off+4].try_into().unwrap_or([0;4]));
            if p_type != 1 { continue; } // PT_LOAD = 1

            let p_offset = u64::from_le_bytes(elf[off+8..off+16].try_into().unwrap_or([0;8])) as usize;
            let p_vaddr  = u64::from_le_bytes(elf[off+16..off+24].try_into().unwrap_or([0;8]));
            let p_filesz = u64::from_le_bytes(elf[off+32..off+40].try_into().unwrap_or([0;8])) as usize;
            let p_memsz  = u64::from_le_bytes(elf[off+40..off+48].try_into().unwrap_or([0;8])) as usize;

            let load_vaddr = base + p_vaddr;
            let page_start = load_vaddr & !0xFFF;
            let page_end   = (load_vaddr + p_memsz as u64 + 0xFFF) & !0xFFF;
            let n_pages    = ((page_end - page_start) / 4096) as usize;

            crate::serial_println!("  [DYNLINK] PT_LOAD vaddr=0x{:x} memsz={} pages={}",
                load_vaddr, p_memsz, n_pages);

            for j in 0..n_pages {
                let frame = crate::memory::frame_alloc::allocate_one()
                    .ok_or(DynLinkError::RelocationFail)?;
                let fdst = (phys_off + frame.start_address().as_u64()) as *mut u8;
                unsafe {
                    core::ptr::write_bytes(fdst, 0, 4096);
                    let page_virt = page_start + j as u64 * 4096;
                    let page_seg_off = page_virt.saturating_sub(load_vaddr & !0xFFF) as usize;
                    let file_off = p_offset.saturating_add(page_seg_off);
                    if page_seg_off < p_filesz && file_off < elf.len() {
                        let copy_len = (p_filesz - page_seg_off).min(4096).min(elf.len() - file_off);
                        core::ptr::copy_nonoverlapping(elf[file_off..].as_ptr(), fdst, copy_len);
                    }
                }
            }
        }
        Ok(())
    }

    fn next_load_addr(&self) -> u64 {
        // Libraries load at 0x7F00_0000_0000 downward
        0x7F00_0000_0000u64 - (self.libs.len() as u64 * 0x0100_0000)
    }
}

/// Parse DT_NEEDED entries from .dynamic section
pub fn get_needed_libs(elf: &[u8]) -> Vec<String> {
    if elf.len() < 64 { return Vec::new(); }

    let shoff     = u64::from_le_bytes(elf[40..48].try_into().unwrap_or([0;8])) as usize;
    let shentsize = u16::from_le_bytes(elf[58..60].try_into().unwrap_or([0;2])) as usize;
    let shnum     = u16::from_le_bytes(elf[60..62].try_into().unwrap_or([0;2])) as usize;

    let mut dynstr_off = 0usize;
    let mut dynamic_off = 0usize;
    let mut dynamic_size = 0usize;

    for i in 0..shnum {
        let off = shoff + i * shentsize;
        if off + shentsize > elf.len() { break; }
        let sh_type = u32::from_le_bytes(elf[off+4..off+8].try_into().unwrap_or([0;4]));
        let sh_off  = u64::from_le_bytes(elf[off+24..off+32].try_into().unwrap_or([0;8])) as usize;
        let sh_size = u64::from_le_bytes(elf[off+32..off+40].try_into().unwrap_or([0;8])) as usize;
        match sh_type {
            6 => { dynamic_off  = sh_off; dynamic_size = sh_size; } // SHT_DYNAMIC
            3 => { dynstr_off   = sh_off; }                          // SHT_STRTAB
            _ => {}
        }
    }

    let mut libs = Vec::new();
    let mut i = 0;
    // Elf64_Dyn entry = 16 bytes: d_tag (i64) + d_val (u64)
    while i + 16 <= dynamic_size {
        let off = dynamic_off + i;
        if off + 16 > elf.len() { break; }
        let d_tag = i64::from_le_bytes(elf[off..off+8].try_into().unwrap_or([0;8]));
        let d_val = u64::from_le_bytes(elf[off+8..off+16].try_into().unwrap_or([0;8])) as usize;
        if d_tag == 1 {  // DT_NEEDED
            let name_off = dynstr_off + d_val;
            if name_off < elf.len() {
                let name_end = elf[name_off..].iter().position(|&b| b == 0)
                    .map(|p| name_off + p).unwrap_or(elf.len());
                if let Ok(name) = core::str::from_utf8(&elf[name_off..name_end]) {
                    libs.push(name.into());
                }
            }
        }
        if d_tag == 0 { break; } // DT_NULL
        i += 16;
    }
    libs
}
