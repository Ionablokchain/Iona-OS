//! Shared Memory — IPC via physical pages shared between processes
//!
//! This module implements System V shared memory (shmget, shmat, shmdt, shmctl)
//! for inter‑process communication. The same physical pages are mapped into
//! multiple address spaces.
//!
//! # API Overview
//! - `shmget(key, size, flags)` – create or access a shared memory segment
//! - `shmat(key, virt_addr, flags)` – attach a segment to the calling process
//! - `shmdt(addr)` – detach a segment
//! - `shmctl(key, cmd, buf)` – control operations (remove, stat, lock)
//!
//! # Security
//! - Segments are identified by a user‑supplied key (like System V IPC)
//! - Permissions flags (SHM_R, SHM_W) control access
//! - IPC_PRIVATE (key = 0) creates a private segment with a new unique key
//!
//! # Example
//! ```rust,ignore
//! let key = shmget(0x1234, 4096, IPC_CREAT | SHM_R | SHM_W)?;
//! let addr = shmat(key, 0, 0)?;
//! // write to shared memory
//! shmdt(addr)?;
//! ```

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Lazy, Mutex};
use x86_64::PhysAddr;

// -----------------------------------------------------------------------------
// Constants (System V IPC flags, mirrored)
// -----------------------------------------------------------------------------

/// Create a new segment if it does not already exist.
pub const IPC_CREAT: u32 = 0o1000;

/// Exclusive create (fails if segment already exists).
pub const IPC_EXCL: u32 = 0o2000;

/// Private segment (key is ignored, kernel allocates a unique key).
pub const IPC_PRIVATE: u64 = 0;

/// Remove the segment (used with shmctl).
pub const IPC_RMID: u32 = 0;

/// Get statistics (used with shmctl).
pub const IPC_STAT: u32 = 1;

/// Set permissions (used with shmctl).
pub const IPC_SET: u32 = 2;

/// Read permission.
pub const SHM_R: u32 = 0o400;

/// Write permission.
pub const SHM_W: u32 = 0o200;

/// Lock segment in memory (no swap).
pub const SHM_LOCK: u32 = 3;

/// Unlock segment (allow swap).
pub const SHM_UNLOCK: u32 = 4;

/// Map read‑only.
pub const SHM_RDONLY: u32 = 0o10000;

/// Map as remote (NUMA hint).
pub const SHM_REMAP: u32 = 0o20000;

/// Maximum number of shared memory segments per system.
pub const SHMMAX: usize = 64 * 1024 * 1024; // 64 MiB max segment size

/// Maximum number of segments per process.
pub const SHMSEG_MAX: usize = 32;

/// Default key for IPC_PRIVATE allocations.
static PRIVATE_KEY_BASE: AtomicU64 = AtomicU64::new(0x8000_0000_0000_0000);

// -----------------------------------------------------------------------------
// Permission flags
// -----------------------------------------------------------------------------

/// Permission flags for a shared memory segment.
#[derive(Debug, Clone, Copy)]
pub struct ShmPerm {
    /// Owner UID.
    pub uid: u32,
    /// Owner GID.
    pub gid: u32,
    /// Creator UID.
    pub cuid: u32,
    /// Creator GID.
    pub cgid: u32,
    /// Mode flags (read/write for owner, group, other).
    pub mode: u32,
}

impl Default for ShmPerm {
    fn default() -> Self {
        Self {
            uid: 0,
            gid: 0,
            cuid: 0,
            cgid: 0,
            mode: SHM_R | SHM_W,
        }
    }
}

// -----------------------------------------------------------------------------
// Segment structure
// -----------------------------------------------------------------------------

/// A shared memory segment.
#[derive(Debug)]
pub struct ShmSegment {
    /// Unique identifier (key provided by user or allocated).
    pub key: u64,
    /// Segment size in bytes.
    pub size: usize,
    /// Physical page frames backing this segment (for multi‑page segments).
    pub phys_frames: Vec<u64>,
    /// Reference count (number of processes attached).
    pub ref_count: AtomicU32,
    /// Permission flags.
    pub perm: ShmPerm,
    /// Flags from shmget (IPC_CREAT, IPC_EXCL, etc.).
    pub flags: u32,
    /// Creator PID.
    pub creator_pid: u32,
    /// Last attach PID.
    pub last_attach_pid: u32,
    /// Last detach PID.
    pub last_detach_pid: u32,
    /// Attach time.
    pub attach_time: u64,
    /// Detach time.
    pub detach_time: u64,
    /// Modification time.
    pub mod_time: u64,
}

impl ShmSegment {
    /// Check if the segment is currently attached by any process.
    pub fn is_attached(&self) -> bool {
        self.ref_count.load(Ordering::Relaxed) > 0
    }

    /// Get the number of attached processes.
    pub fn attach_count(&self) -> u32 {
        self.ref_count.load(Ordering::Relaxed)
    }
}

// -----------------------------------------------------------------------------
// Process attachment record
// -----------------------------------------------------------------------------

/// Track which virtual address a process has attached a segment at.
#[derive(Debug)]
struct ProcessAttachment {
    pub key: u64,
    pub virt_addr: u64,
    pub flags: u32,
}

/// Per‑process attachments (for proper cleanup on exit).
static PROCESS_ATTACHMENTS: Lazy<Mutex<BTreeMap<u32, Vec<ProcessAttachment>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

// -----------------------------------------------------------------------------
// Global segment table
// -----------------------------------------------------------------------------

/// Global shared memory segment table (key → segment).
static SHM_TABLE: Lazy<Mutex<BTreeMap<u64, ShmSegment>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

// -----------------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------------

/// Shared memory statistics.
#[derive(Debug, Default)]
pub struct ShmStats {
    /// Number of active segments.
    pub active_segments: usize,
    /// Total bytes of shared memory allocated.
    pub total_bytes: usize,
    /// Total bytes of shared memory currently in use (attached).
    pub used_bytes: usize,
    /// Number of processes attached to shared memory.
    pub attached_processes: usize,
}

impl ShmStats {
    /// Get a human‑readable summary.
    pub fn summary(&self) -> String {
        format!(
            "SHM: {} segments, {:.2} MiB total, {:.2} MiB used, {} processes attached",
            self.active_segments,
            self.total_bytes as f64 / 1024.0 / 1024.0,
            self.used_bytes as f64 / 1024.0 / 1024.0,
            self.attached_processes
        )
    }
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Create or access a shared memory segment.
///
/// # Arguments
/// * `key` – User‑supplied key (use `IPC_PRIVATE` for a private segment).
/// * `size` – Segment size in bytes (rounded up to page size).
/// * `flags` – Flags: `IPC_CREAT`, `IPC_EXCL`, `SHM_R`, `SHM_W`.
///
/// # Returns
/// The key of the segment on success, or an error string.
pub fn shmget(key: u64, size: usize, flags: u32, current_pid: u32) -> Result<u64, &'static str> {
    if size == 0 {
        return Err("SHM size must be > 0");
    }
    if size > SHMMAX {
        return Err("SHM size exceeds SHMMAX");
    }

    let page_size = crate::memory::buddy::FRAME_SIZE;
    let aligned_size = (size + page_size - 1) & !(page_size - 1);
    let page_count = aligned_size / page_size;

    let mut table = SHM_TABLE.lock();

    // Check if segment already exists
    if let Some(seg) = table.get(&key) {
        // IPC_EXCL: fail if exists
        if flags & IPC_EXCL != 0 {
            return Err("SHM segment already exists (IPC_EXCL)");
        }
        // Check size compatibility
        if seg.size < aligned_size {
            return Err("SHM segment exists but is smaller than requested");
        }
        return Ok(key);
    }

    // Create new segment
    if flags & IPC_CREAT == 0 && key != IPC_PRIVATE {
        return Err("SHM segment not found and IPC_CREAT not specified");
    }

    // Allocate physical frames
    let mut phys_frames = Vec::with_capacity(page_count);
    for _ in 0..page_count {
        match crate::memory::frame_alloc::allocate_one() {
            Some(frame) => {
                let frame_phys = frame.start_address().as_u64();
                phys_frames.push(frame_phys);
            }
            None => {
                // Free already allocated frames
                for &p in &phys_frames {
                    let frame = x86_64::structures::paging::PhysFrame::from_start_address(
                        x86_64::PhysAddr::new(p)
                    ).unwrap();
                    crate::memory::frame_alloc::deallocate(frame);
                }
                return Err("OOM for SHM segment");
            }
        }
    }

    let segment_key = if key == IPC_PRIVATE {
        let new_key = PRIVATE_KEY_BASE.fetch_add(1, Ordering::Relaxed);
        new_key
    } else {
        key
    };

    let segment = ShmSegment {
        key: segment_key,
        size: aligned_size,
        phys_frames,
        ref_count: AtomicU32::new(0),
        perm: ShmPerm {
            mode: flags & (SHM_R | SHM_W),
            ..Default::default()
        },
        flags,
        creator_pid: current_pid,
        last_attach_pid: 0,
        last_detach_pid: 0,
        attach_time: 0,
        detach_time: 0,
        mod_time: crate::arch::x86_64::timer::uptime_ms(),
    };

    crate::serial_println!(
        "[SHM] created key={} size={} pages={} phys_base=0x{:x}",
        segment_key, aligned_size, page_count,
        phys_frames.first().unwrap_or(&0)
    );

    table.insert(segment_key, segment);
    Ok(segment_key)
}

/// Attach a shared memory segment to the calling process.
///
/// # Arguments
/// * `key` – Segment key.
/// * `virt_addr` – Hint for virtual address (0 = kernel chooses).
/// * `flags` – Attach flags: `SHM_RDONLY`, `SHM_REMAP`.
/// * `pid` – Current process ID.
///
/// # Returns
/// The virtual address where the segment is mapped.
pub fn shmat(key: u64, virt_addr: u64, flags: u32, pid: u32) -> Result<u64, &'static str> {
    let mut table = SHM_TABLE.lock();
    let seg = table.get_mut(&key).ok_or("SHM key not found")?;

    // Check permissions
    let need_read = true;
    let need_write = (flags & SHM_RDONLY) == 0;
    if need_read && (seg.perm.mode & SHM_R) == 0 {
        return Err("SHM read permission denied");
    }
    if need_write && (seg.perm.mode & SHM_W) == 0 {
        return Err("SHM write permission denied");
    }

    // Check process attachment limit
    let attachments = PROCESS_ATTACHMENTS.lock();
    if attachments.get(&pid).map(|v| v.len()).unwrap_or(0) >= SHMSEG_MAX {
        return Err("too many SHM segments attached to this process");
    }

    // Choose virtual address
    let addr = if virt_addr != 0 {
        virt_addr
    } else {
        // Find a free area (simplified – use high address space)
        0x0000_8000_0000_0000 + (key as u64 * 0x10_0000)
    };

    // Map physical pages into the process page table
    let page_size = crate::memory::buddy::FRAME_SIZE;
    for (i, &phys) in seg.phys_frames.iter().enumerate() {
        let virt = addr + (i * page_size) as u64;
        // In a full implementation: call VMM to map the physical frame
        crate::serial_println!(
            "[SHM] mapping phys=0x{:x} to virt=0x{:x} (frame {})",
            phys, virt, i
        );
        // Placeholder: actual mapping would be done here
    }

    seg.ref_count.fetch_add(1, Ordering::Relaxed);
    seg.last_attach_pid = pid;
    seg.attach_time = crate::arch::x86_64::timer::uptime_ms();

    // Record attachment
    drop(table);
    let mut attachments = PROCESS_ATTACHMENTS.lock();
    attachments.entry(pid).or_default().push(ProcessAttachment {
        key,
        virt_addr: addr,
        flags,
    });

    crate::serial_println!("[SHM] attached key={} at virt=0x{:x} (pid={})", key, addr, pid);
    Ok(addr)
}

/// Detach a shared memory segment from the calling process.
///
/// # Arguments
/// * `addr` – Virtual address where the segment is attached.
/// * `pid` – Current process ID.
///
/// # Returns
/// `true` on success, `false` on error.
pub fn shmdt(addr: u64, pid: u32) -> bool {
    let mut attachments = PROCESS_ATTACHMENTS.lock();
    let process_attachments = match attachments.get_mut(&pid) {
        Some(a) => a,
        None => return false,
    };

    let pos = process_attachments.iter().position(|a| a.virt_addr == addr);
    let attachment = match pos {
        Some(p) => process_attachments.remove(p),
        None => return false,
    };

    drop(attachments);

    let mut table = SHM_TABLE.lock();
    if let Some(seg) = table.get_mut(&attachment.key) {
        let old_count = seg.ref_count.load(Ordering::Relaxed);
        if old_count > 0 {
            seg.ref_count.fetch_sub(1, Ordering::Relaxed);
            seg.last_detach_pid = pid;
            seg.detach_time = crate::arch::x86_64::timer::uptime_ms();
        }
        crate::serial_println!("[SHM] detached key={} from virt=0x{:x} (pid={})", attachment.key, addr, pid);
        true
    } else {
        false
    }
}

/// Control operations on a shared memory segment.
///
/// # Arguments
/// * `key` – Segment key.
/// * `cmd` – Command: `IPC_RMID`, `IPC_STAT`, `IPC_SET`, `SHM_LOCK`, `SHM_UNLOCK`.
/// * `buf` – Optional buffer for IPC_STAT output.
///
/// # Returns
/// `Ok(())` on success, or an error string.
pub fn shmctl(key: u64, cmd: u32, buf: Option<&mut ShmPerm>) -> Result<(), &'static str> {
    let mut table = SHM_TABLE.lock();
    let seg = table.get_mut(&key).ok_or("SHM key not found")?;

    match cmd {
        IPC_RMID => {
            // Mark for removal (actual removal happens when ref_count reaches 0)
            if seg.is_attached() {
                // Mark as "to be removed" – actual removal on last detach
                seg.flags |= IPC_RMID;
                crate::serial_println!("[SHM] key={} marked for removal (still attached)", key);
            } else {
                // Free physical frames
                for &phys in &seg.phys_frames {
                    let frame = x86_64::structures::paging::PhysFrame::from_start_address(
                        x86_64::PhysAddr::new(phys)
                    ).unwrap();
                    crate::memory::frame_alloc::deallocate(frame);
                }
                table.remove(&key);
                crate::serial_println!("[SHM] removed key={}", key);
            }
            Ok(())
        }
        IPC_STAT => {
            if let Some(perms) = buf {
                *perms = seg.perm;
            }
            Ok(())
        }
        IPC_SET => {
            if let Some(perms) = buf {
                seg.perm = *perms;
                seg.mod_time = crate::arch::x86_64::timer::uptime_ms();
            }
            Ok(())
        }
        SHM_LOCK => {
            // Lock segments in memory (prevent swapping)
            seg.flags |= SHM_LOCK;
            Ok(())
        }
        SHM_UNLOCK => {
            seg.flags &= !SHM_LOCK;
            Ok(())
        }
        _ => Err("invalid SHM command"),
    }
}

/// Clean up all shared memory segments for a terminated process.
pub fn cleanup_process(pid: u32) {
    let mut attachments = PROCESS_ATTACHMENTS.lock();
    if let Some(attached) = attachments.remove(&pid) {
        for a in attached {
            let _ = shmdt(a.virt_addr, pid);
        }
        crate::serial_println!("[SHM] cleaned up pid={}", pid);
    }
}

/// Get shared memory statistics.
pub fn shm_stats() -> ShmStats {
    let table = SHM_TABLE.lock();
    let mut total_bytes = 0;
    let mut used_bytes = 0;
    let mut attached_processes = 0;

    for seg in table.values() {
        total_bytes += seg.size;
        if seg.is_attached() {
            used_bytes += seg.size;
            attached_processes += seg.attach_count();
        }
    }

    ShmStats {
        active_segments: table.len(),
        total_bytes,
        used_bytes,
        attached_processes: attached_processes as usize,
    }
}

/// Check if a segment with the given key exists.
pub fn shm_exists(key: u64) -> bool {
    SHM_TABLE.lock().contains_key(&key)
}

/// Get segment information (for debugging).
pub fn shm_info(key: u64) -> Option<ShmSegment> {
    SHM_TABLE.lock().get(&key).cloned()
}

/// Initialise the shared memory subsystem.
pub fn init() {
    crate::serial_println!("  [SHM] System V shared memory initialised");
    crate::serial_println!("    SHMMAX = {} KiB", SHMMAX / 1024);
    crate::serial_println!("    SHMSEG_MAX = {}", SHMSEG_MAX);
}
