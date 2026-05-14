//! Shared Memory — IPC prin pagini fizice partajate
//!
//! API: sys_shmget / sys_shmat / sys_shmdt / sys_shmctl
//! Implementare: map aceleași pagini fizice în multiple address space-uri

use alloc::collections::BTreeMap;
use spin::{Lazy, Mutex};
use x86_64::PhysAddr;

pub struct ShmSegment {
    pub key:       u64,
    pub size:      usize,
    pub phys_base: u64,   // base physical address
    pub ref_count: u32,
    pub flags:     u32,
}

static SHM_TABLE: Lazy<Mutex<BTreeMap<u64, ShmSegment>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

static SHM_NEXT_KEY: Mutex<u64> = Mutex::new(1);

/// Create or get a shared memory segment
pub fn shmget(key: u64, size: usize, flags: u32) -> Result<u64, &'static str> {
    let mut table = SHM_TABLE.lock();
    // IPC_CREAT = 0o1000
    if flags & 0o1000 != 0 || !table.contains_key(&key) {
        // Allocate physical pages for the segment
        let pages = (size + 4095) / 4096;
        let mut phys_base = 0u64;
        for _ in 0..pages {
            match crate::memory::frame_alloc::allocate_one() {
                Some(f) => {
                    if phys_base == 0 { phys_base = f.start_address().as_u64(); }
                    crate::memory::frame_alloc::inc_ref(f);
                }
                None => return Err("OOM for shm"),
            }
        }
        let seg = ShmSegment { key, size, phys_base, ref_count: 0, flags };
        table.insert(key, seg);
        crate::serial_println!("  [SHM] created key={} size={} phys=0x{:x}", key, size, phys_base);
    }
    Ok(key)
}

/// Attach shared memory to current address space
pub fn shmat(key: u64, hint_virt: u64) -> Result<u64, &'static str> {
    let mut table = SHM_TABLE.lock();
    let seg = table.get_mut(&key).ok_or("SHM key not found")?;
    seg.ref_count += 1;

    // Map at hint_virt (or let kernel choose if 0)
    let virt = if hint_virt != 0 { hint_virt } else {
        0x0000_7000_0000_0000 - seg.ref_count as u64 * 0x10_0000
    };

    crate::serial_println!("  [SHM] attached key={} at virt=0x{:x}", key, virt);
    // In a full implementation: map phys pages into current page table at virt
    // For now: return the virtual address (mapping is simplified)
    Ok(virt)
}

/// Detach shared memory
pub fn shmdt(key: u64) -> bool {
    let mut table = SHM_TABLE.lock();
    if let Some(seg) = table.get_mut(&key) {
        seg.ref_count = seg.ref_count.saturating_sub(1);
        if seg.ref_count == 0 {
            // Could free physical pages here
            crate::serial_println!("  [SHM] key={} ref_count=0 (can be freed)", key);
        }
        return true;
    }
    false
}

pub fn shm_stats() -> (usize, usize) {
    let table = SHM_TABLE.lock();
    let count = table.len();
    let total_bytes: usize = table.values().map(|s| s.size).sum();
    (count, total_bytes)
}
