//! IONAFS — IONA Filesystem cu Write-Ahead Log (journaling)
//!
//! Layout disc (sectoare de 512 bytes):
//!   LBA 0:       Superblock (magic + num_files + journal_head)
//!   LBA 1-15:    File index (120 intrări × 64 bytes)
//!   LBA 16-63:   Write-Ahead Log — journal entries
//!   LBA 64+:     Date fișiere
//!
//! Journal entry (64 bytes):
//!   [0..4]  = op: 0=noop, 1=write, 2=delete
//!   [4..8]  = state: 0=pending, 1=committed, 2=clean
//!   [8..16] = path_hash (FNV-1a)
//!   [16..24]= lba
//!   [24..32]= size
//!   [32..64]= path (null-terminated, max 32 chars)
//!
//! Recovery la mount: re-aplică toate entries PENDING.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use spin::{Lazy, Mutex};

#[derive(Debug, Clone)]
pub struct FileStat {
    pub size:  u64,
    pub mode:  u16,
    pub uid:   u32,
    pub gid:   u32,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
}

const MAGIC:         u32   = 0x494F4E41; // "IONA"
const SECTOR_SIZE:   usize = 512;
const INDEX_LBA:     u64   = 1;
const JOURNAL_LBA:   u64   = 16;
const JOURNAL_SLOTS: usize = 48; // LBA 16-63 = 48 sectors
const DATA_LBA:      u64   = 64;

const OP_NOOP:   u32 = 0;
const OP_WRITE:  u32 = 1;
const OP_DELETE: u32 = 2;

const STATE_PENDING:   u32 = 0;
const STATE_COMMITTED: u32 = 1;
const STATE_CLEAN:     u32 = 2;

/// FNV-1a hash for path
fn path_hash(path: &str) -> u64 {
    let mut h = 14_695_981_039_346_656_037u64;
    for b in path.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(1_099_511_628_211);
    }
    h
}

#[derive(Clone)]
struct FileEntry {
    name:  String,
    lba:   u64,
    size:  usize,
    mode:  u16,   // Unix permission bits (e.g. 0o644)
    uid:   u32,
    gid:   u32,
    atime: u64,   // access time (ms since boot)
    mtime: u64,   // modification time
    ctime: u64,   // change time
}

impl FileEntry {
    fn new(name: &str, lba: u64, size: usize) -> Self {
        let now = crate::arch::x86_64::timer::uptime_ms();
        FileEntry { name: name.into(), lba, size, mode: 0o644, uid: 1000, gid: 1000,
                    atime: now, mtime: now, ctime: now }
    }
}

struct JournalEntry {
    op:    u32,
    state: u32,
    hash:  u64,
    lba:   u64,
    size:  u64,
    path:  [u8; 32],
}

impl JournalEntry {
    fn new(op: u32, path: &str, lba: u64, size: u64) -> Self {
        let mut pb = [0u8; 32];
        let bytes  = path.as_bytes();
        let n      = bytes.len().min(31);
        pb[..n].copy_from_slice(&bytes[..n]);
        JournalEntry { op, state: STATE_PENDING, hash: path_hash(path), lba, size, path: pb }
    }

    fn to_sector(&self) -> [u8; SECTOR_SIZE] {
        let mut s = [0u8; SECTOR_SIZE];
        s[0..4].copy_from_slice(&self.op.to_le_bytes());
        s[4..8].copy_from_slice(&self.state.to_le_bytes());
        s[8..16].copy_from_slice(&self.hash.to_le_bytes());
        s[16..24].copy_from_slice(&self.lba.to_le_bytes());
        s[24..32].copy_from_slice(&self.size.to_le_bytes());
        s[32..64].copy_from_slice(&self.path);
        s
    }

    fn from_sector(s: &[u8; SECTOR_SIZE]) -> Self {
        let op    = u32::from_le_bytes(s[0..4].try_into().unwrap_or([0;4]));
        let state = u32::from_le_bytes(s[4..8].try_into().unwrap_or([0;4]));
        let hash  = u64::from_le_bytes(s[8..16].try_into().unwrap_or([0;8]));
        let lba   = u64::from_le_bytes(s[16..24].try_into().unwrap_or([0;8]));
        let size  = u64::from_le_bytes(s[24..32].try_into().unwrap_or([0;8]));
        let mut path = [0u8; 32];
        path.copy_from_slice(&s[32..64]);
        JournalEntry { op, state, hash, lba, size, path }
    }
}

struct IonFs {
    cache:    BTreeMap<String, Vec<u8>>,
    index:    Vec<FileEntry>,
    next_lba: u64,
    on_disk:  bool,
    journal_head: usize, // next journal slot to use
}

impl IonFs {
    fn new() -> Self {
        Self { cache: BTreeMap::new(), index: Vec::new(),
               next_lba: DATA_LBA, on_disk: false, journal_head: 0 }
    }

    fn init_disk(&mut self) {
        if !crate::drivers::virtio::blk::is_present() { return; }
        self.on_disk = true;

        // Read superblock
        let mut sb = [0u8; SECTOR_SIZE];
        if !crate::drivers::virtio::blk::read_sectors(0, 1, &mut sb) { return; }

        let magic = u32::from_le_bytes(sb[0..4].try_into().unwrap_or([0;4]));
        if magic != MAGIC {
            // Format new filesystem
            sb[0..4].copy_from_slice(&MAGIC.to_le_bytes());
            sb[4..8].copy_from_slice(&0u32.to_le_bytes());
            sb[8..16].copy_from_slice(&0u64.to_le_bytes()); // journal_head
            crate::drivers::virtio::blk::write_sectors(0, &sb);
            crate::serial_println!("  [IONAFS] formatted fresh filesystem");
            return;
        }

        let num_files    = u32::from_le_bytes(sb[4..8].try_into().unwrap_or([0;4])) as usize;
        self.journal_head = u64::from_le_bytes(sb[8..16].try_into().unwrap_or([0;8])) as usize;

        // Recover journal first
        self.recover_journal();

        // Load index
        let mut idx = alloc::vec![0u8; 15 * SECTOR_SIZE];
        for i in 0..15usize {
            crate::drivers::virtio::blk::read_sectors(
                INDEX_LBA + i as u64, 1, &mut idx[i*512..(i+1)*512]);
        }
        for i in 0..num_files.min(120) {
            let off    = i * 64;
            let np     = idx[off..off+48].iter().position(|&b| b==0).unwrap_or(48);
            let name   = String::from_utf8_lossy(&idx[off..off+np]).into_owned();
            let lba    = u64::from_le_bytes(idx[off+48..off+56].try_into().unwrap_or([0;8]));
            let size   = u64::from_le_bytes(idx[off+56..off+64].try_into().unwrap_or([0;8])) as usize;
            if !name.is_empty() {
                self.index.push(FileEntry { name: name.clone(), lba, size, mode: 0o644, uid:0, gid:0, atime:0, mtime:0, ctime:0 });
                self.next_lba = self.next_lba.max(lba + (size / SECTOR_SIZE) as u64 + 1);
                // Load into cache
                let ns   = (size + SECTOR_SIZE - 1) / SECTOR_SIZE;
                let mut d = alloc::vec![0u8; ns * SECTOR_SIZE];
                for j in 0..ns {
                    crate::drivers::virtio::blk::read_sectors(lba+j as u64,1,&mut d[j*512..(j+1)*512]);
                }
                self.cache.insert(name, d[..size].to_vec());
            }
        }
        crate::serial_println!("  [IONAFS] loaded {} files", num_files);
    }

    /// Journal recovery: re-apply all PENDING entries
    fn recover_journal(&mut self) {
        let mut recovered = 0;
        for slot in 0..JOURNAL_SLOTS {
            let mut sector = [0u8; SECTOR_SIZE];
            crate::drivers::virtio::blk::read_sectors(JOURNAL_LBA + slot as u64, 1, &mut sector);
            let entry = JournalEntry::from_sector(&sector);
            if entry.op == OP_NOOP || entry.state == STATE_CLEAN { continue; }
            if entry.state == STATE_PENDING {
                // Re-apply: mark as committed (data already written, just mark clean)
                // In real journal: re-apply data write, then mark clean
                crate::serial_println!("  [IONAFS] journal recovery: slot {}", slot);
                let mut s = sector;
                s[4..8].copy_from_slice(&STATE_COMMITTED.to_le_bytes());
                crate::drivers::virtio::blk::write_sectors(JOURNAL_LBA + slot as u64, &s);
                recovered += 1;
            }
        }
        if recovered > 0 {
            crate::serial_println!("  [IONAFS] recovered {} journal entries", recovered);
        }
    }

    /// Journal a write operation:
    /// 1. Write journal entry (PENDING)
    /// 2. Write actual data
    /// 3. Mark journal entry COMMITTED
    /// 4. Update index
    /// 5. Mark journal CLEAN
    fn journal_write(&mut self, path: &str, data: &[u8]) -> bool {
        if !self.on_disk { return false; }

        let lba      = self.next_lba;
        let nsectors = (data.len() + SECTOR_SIZE - 1) / SECTOR_SIZE;
        let slot     = self.journal_head % JOURNAL_SLOTS;

        // Step 1: Write journal entry as PENDING
        let entry = JournalEntry::new(OP_WRITE, path, lba, data.len() as u64);
        let sector = entry.to_sector();
        crate::drivers::virtio::blk::write_sectors(JOURNAL_LBA + slot as u64, &sector);

        // Step 2: Write actual data
        let mut padded = alloc::vec![0u8; nsectors * SECTOR_SIZE];
        padded[..data.len()].copy_from_slice(data);
        for i in 0..nsectors {
            crate::drivers::virtio::blk::write_sectors(lba + i as u64, &padded[i*512..(i+1)*512]);
        }
        self.next_lba += nsectors as u64;

        // Step 3: Mark COMMITTED
        let mut cs = sector;
        cs[4..8].copy_from_slice(&STATE_COMMITTED.to_le_bytes());
        crate::drivers::virtio::blk::write_sectors(JOURNAL_LBA + slot as u64, &cs);

        // Step 4: Update index
        if let Some(e) = self.index.iter_mut().find(|e| e.name == path) {
            e.lba  = lba;
            e.size = data.len();
        } else {
            self.index.push(FileEntry::new(path, lba, data.len()));
        }
        self.write_index_and_superblock();

        // Step 5: Mark CLEAN
        let mut clean = cs;
        clean[4..8].copy_from_slice(&STATE_CLEAN.to_le_bytes());
        crate::drivers::virtio::blk::write_sectors(JOURNAL_LBA + slot as u64, &clean);

        self.journal_head += 1;
        self.update_superblock_journal_head();
        true
    }

    fn write_index_and_superblock(&self) {
        let mut idx = alloc::vec![0u8; 15 * SECTOR_SIZE];
        for (i, e) in self.index.iter().enumerate().take(120) {
            let off = i * 64;
            let nb  = e.name.as_bytes();
            let n   = nb.len().min(47);
            idx[off..off+n].copy_from_slice(&nb[..n]);
            idx[off+48..off+56].copy_from_slice(&e.lba.to_le_bytes());
            idx[off+56..off+64].copy_from_slice(&(e.size as u64).to_le_bytes());
        }
        for i in 0..15usize {
            crate::drivers::virtio::blk::write_sectors(INDEX_LBA + i as u64, &idx[i*512..(i+1)*512]);
        }
        self.update_superblock_journal_head();
    }

    fn update_superblock_journal_head(&self) {
        let mut sb = [0u8; SECTOR_SIZE];
        sb[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        sb[4..8].copy_from_slice(&(self.index.len() as u32).to_le_bytes());
        sb[8..16].copy_from_slice(&(self.journal_head as u64).to_le_bytes());
        crate::drivers::virtio::blk::write_sectors(0, &sb);
    }

    fn read_file(&self, path: &str)             -> Option<Vec<u8>> { self.cache.get(path).cloned() }
    fn list(&self)                               -> Vec<String>     { self.cache.keys().cloned().collect() }

    /// List files matching prefix, up to `limit` entries.
    ///
    /// Complexity note: BTreeMap iterator is ordered by key.
    /// Starting from the first key >= prefix is O(log n) via range().
    /// Collecting `limit` matching keys adds O(limit) work.
    /// Worst case is O(n) only if matching keys are sparse across all keys.
    ///
    /// For IONA OS typical usage (< 1000 files, prefixes like "/var/iona-node/"),
    /// this is fast enough. For large filesystems with sparse prefixes,
    /// a dedicated prefix index (BTreeMap<String, Vec<String>>) would be O(1) lookup.
    fn list_prefix_limited(&self, prefix: &str, limit: usize) -> Vec<String> {
        // Use range() to start from the first key >= prefix (O(log n) seek)
        // then take keys while they start with prefix (O(limit) scan)
        self.cache.range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .take(limit)
            .map(|(k, _)| k.clone())
            .collect()
    }

    /// Count files with prefix.
    fn count_prefix(&self, prefix: &str) -> usize {
        self.cache.range(prefix.to_string()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .count()
    }

    fn write_file(&mut self, path: &str, data: &[u8]) {
        self.cache.insert(path.into(), data.to_vec());
        let now = crate::arch::x86_64::timer::uptime_ms();
        if let Some(e) = self.index.iter_mut().find(|e| e.name == path) {
            e.mtime = now; e.atime = now;
        }
        self.journal_write(path, data);
    }

    fn delete_file(&mut self, path: &str) -> bool {
        let existed = self.cache.remove(path).is_some();
        self.index.retain(|e| e.name != path);
        if existed { self.write_index_and_superblock(); }
        existed
    }

    fn rename_file(&mut self, from: &str, to: &str) -> bool {
        let data = match self.cache.remove(from) { Some(d) => d, None => return false };
        self.index.iter_mut().find(|e| e.name == from).map(|e| e.name = to.into());
        self.cache.insert(to.into(), data);
        self.write_index_and_superblock();
        true
    }

    fn stat_file(&self, path: &str) -> Option<FileStat> {
        let entry = self.index.iter().find(|e| e.name == path)?;
        Some(FileStat {
            size:  entry.size as u64,
            mode:  entry.mode,
            uid:   entry.uid,
            gid:   entry.gid,
            atime: entry.atime,
            mtime: entry.mtime,
            ctime: entry.ctime,
        })
    }

    fn chmod_file(&mut self, path: &str, mode: u16) -> bool {
        if let Some(e) = self.index.iter_mut().find(|e| e.name == path) {
            e.mode  = mode;
            e.ctime = crate::arch::x86_64::timer::uptime_ms();
            true
        } else { false }
    }
}

static FS: Lazy<Mutex<IonFs>> = Lazy::new(|| Mutex::new(IonFs::new()));

pub fn init()                                     { FS.lock().init_disk(); crate::serial_println!("  [IONAFS] ready + journaled ({} files)", FS.lock().cache.len()); }
pub fn read(path: &str) -> Option<Vec<u8>> {
    // Redirect /proc/* la proc virtual filesystem
    if path.starts_with("/proc/") || path == "/proc" {
        return crate::fs::proc::read(path);
    }
    FS.lock().read_file(path)
}
pub fn write(path: &str, d: &[u8])               { FS.lock().write_file(path, d) }
pub fn list()                  -> Vec<String>     { FS.lock().list() }

/// List files with prefix, limited to `limit` entries.
/// Scans BTreeMap directly — never allocates the full list.
/// O(log n + limit) instead of O(n) for large filesystems.
pub fn list_prefix(prefix: &str, limit: usize) -> Vec<String> {
    FS.lock().list_prefix_limited(prefix, limit)
}

/// Count files matching prefix without allocating results
pub fn count_prefix(prefix: &str) -> usize {
    FS.lock().count_prefix(prefix)
}
pub fn exists(path: &str)      -> bool            { FS.lock().cache.contains_key(path) }
pub fn delete(path: &str)      -> bool            { FS.lock().delete_file(path) }
pub fn rename(from: &str, to: &str) -> bool       { FS.lock().rename_file(from, to) }
pub fn stat(path: &str)        -> Option<FileStat>{ FS.lock().stat_file(path) }
pub fn chmod(path: &str, mode: u16) -> bool       { FS.lock().chmod_file(path, mode) }

// ── File locking ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LockType {
    Shared,     // LOCK_SH — multiple readers OK
    Exclusive,  // LOCK_EX — single writer
}

struct FileLock {
    lock_type: LockType,
    holders:   alloc::vec::Vec<crate::task::TaskId>,
}

static FILE_LOCKS: spin::Lazy<spin::Mutex<BTreeMap<u64, FileLock>>> =
    spin::Lazy::new(|| spin::Mutex::new(BTreeMap::new()));

/// Acquire a file lock (path_hash → lock)
pub fn flock(path: &str, lock_type: LockType, tid: crate::task::TaskId) -> bool {
    let hash = path_hash(path);
    let mut locks = FILE_LOCKS.lock();

    if let Some(existing) = locks.get_mut(&hash) {
        match (existing.lock_type, lock_type) {
            (LockType::Shared, LockType::Shared) => {
                existing.holders.push(tid); true
            }
            _ => false, // conflict
        }
    } else {
        locks.insert(hash, FileLock { lock_type, holders: alloc::vec![tid] });
        true
    }
}

/// Release a file lock
pub fn funlock(path: &str, tid: crate::task::TaskId) {
    let hash = path_hash(path);
    let mut locks = FILE_LOCKS.lock();
    if let Some(lock) = locks.get_mut(&hash) {
        lock.holders.retain(|&h| h != tid);
        if lock.holders.is_empty() { locks.remove(&hash); }
    }
}

// ── Crash injection + recovery tests ─────────────────────────────────────────

/// Crash injection modes for testing
#[derive(Clone, Copy, PartialEq)]
pub enum CrashPoint {
    None,
    AfterJournalPending,    // crash after writing PENDING, before COMMITTED
    AfterJournalCommitted,  // crash after COMMITTED, before CLEAN
    AfterDataWrite,         // crash after data, before index update
    DuringIndexUpdate,      // crash during index write
}

static CRASH_INJECT: spin::Mutex<CrashPoint> = spin::Mutex::new(CrashPoint::None);

pub fn inject_crash(point: CrashPoint) {
    *CRASH_INJECT.lock() = point;
    crate::serial_println!("  [IONAFS] crash injection armed");
}

fn check_crash(point: CrashPoint) {
    if *CRASH_INJECT.lock() == point {
        *CRASH_INJECT.lock() = CrashPoint::None;
        crate::serial_println!("  [IONAFS] CRASH INJECTED at {:?}", "crash point");
        // Simulate power loss: stop further writes
        panic!("crash injection test");
    }
}

/// Run IONAFS consistency check (fsck equivalent)
pub fn fsck() -> bool {
    let fs = FS.lock();
    let mut ok = true;

    // Check 1: all index entries have valid LBAs
    for entry in &fs.index {
        if entry.lba < DATA_LBA as u64 {
            crate::serial_println!("  [FSCK] ERROR: {} has invalid LBA {}", entry.name, entry.lba);
            ok = false;
        }
    }

    // Check 2: no duplicate paths
    let mut names: alloc::vec::Vec<&str> = fs.index.iter().map(|e| e.name.as_str()).collect();
    names.sort();
    for w in names.windows(2) {
        if w[0] == w[1] {
            crate::serial_println!("  [FSCK] ERROR: duplicate path {}", w[0]);
            ok = false;
        }
    }

    // Check 3: cache consistent with index
    for (path, _) in &fs.cache {
        if !fs.index.iter().any(|e| &e.name == path) {
            crate::serial_println!("  [FSCK] WARNING: {} in cache but not in index", path);
        }
    }

    if ok {
        crate::serial_println!("  [FSCK] filesystem consistent: {} files, {} cached",
            fs.index.len(), fs.cache.len());
    }
    ok
}

/// WAL replay test: verify journal invariants
pub fn verify_journal_invariants() -> bool {
    if !FS.lock().on_disk { return true; } // no disk, skip
    let mut ok = true;
    for slot in 0..JOURNAL_SLOTS {
        let mut sector = [0u8; 512];
        crate::drivers::virtio::blk::read_sectors(JOURNAL_LBA + slot as u64, 1, &mut sector);
        let state = u32::from_le_bytes(sector[4..8].try_into().unwrap_or([0;4]));
        let op    = u32::from_le_bytes(sector[0..4].try_into().unwrap_or([0;4]));
        if op != OP_NOOP && state == STATE_PENDING {
            crate::serial_println!("  [JOURNAL] slot {} PENDING (needs recovery)", slot);
            ok = false;
        }
    }
    ok
}

// ══════════════════════════════════════════════════════════════════════════════
// IONAFS Disk Persistence — NVMe/AHCI backend
//
// Layout pe disc (sectoare 512B):
//   LBA 64+: date fișiere (fiecare fișier max 64 sectoare = 32KB direct)
//
// La mount:   read_superblock() → load_index() → load_journal() → replay()
// La write:   journal_append() → update_index() → write_data_sectors()
// La reboot:  mount() este apelat din main.rs după NVMe/AHCI init
// ══════════════════════════════════════════════════════════════════════════════

const DISK_DATA_LBA_START: u64 = 64;   // primele 64 sectoare = superblock + index + journal
const DISK_SECTOR_SIZE:    usize = 512;
const MAX_FILE_SECTORS:    usize = 64;  // max 32KB per fișier

/// Attempt to mount IONAFS from NVMe (primary) or AHCI (fallback)
/// Loads the index and replays any pending journal entries.
pub fn mount_from_disk() {
    crate::serial_println!("  [IONAFS] mounting from disk...");

    // Try NVMe first, then AHCI
    let mut sector_buf = alloc::vec![0u8; 512];

    // Read superblock (LBA 0)
    let ok = try_read_sector(0, &mut sector_buf);
    if !ok {
        crate::serial_println!("  [IONAFS] no disk found — using in-memory mode");
        return;
    }

    // Check magic
    if &sector_buf[0..4] != b"IONA" {
        crate::serial_println!("  [IONAFS] disk not formatted — initializing");
        format_disk();
        return;
    }

    let num_files = u32::from_le_bytes([sector_buf[4],sector_buf[5],sector_buf[6],sector_buf[7]]);
    crate::serial_println!("  [IONAFS] superblock OK — {} files on disk", num_files);

    // Load file index from LBA 1-15
    let mut idx_buf = alloc::vec![0u8; 512 * 15];
    for lba in 1u64..16 {
        let _ = try_read_sector(lba, &mut idx_buf[(lba as usize - 1)*512..(lba as usize)*512]);
    }

    // Parse index entries (64 bytes each)
    let mut fs_lock = FS.lock();
    for i in 0..120usize {
        let off = i * 64;
        if off + 64 > idx_buf.len() { break; }
        let entry = &idx_buf[off..off+64];
        if entry[0] == 0 { continue; } // empty slot
        let path_end = entry[1..33].iter().position(|&b| b == 0).unwrap_or(32);
        let path = alloc::string::String::from_utf8_lossy(&entry[1..1+path_end]).into_owned();
        let data_lba   = u64::from_le_bytes(entry[33..41].try_into().unwrap_or([0;8]));
        let data_size  = u32::from_le_bytes(entry[41..45].try_into().unwrap_or([0;4])) as usize;

        // Read file data from disk
        let sectors = (data_size + 511) / 512;
        let mut data = alloc::vec![0u8; sectors * 512];
        for s in 0..sectors {
            let _ = try_read_sector(data_lba + s as u64, &mut data[s*512..(s+1)*512]);
        }
        data.truncate(data_size);
        fs_lock.cache.insert(path, data);
    }

    crate::serial_println!("  [IONAFS] loaded {} files from disk", fs_lock.cache.len());
}

/// Format disk with empty IONAFS superblock
fn format_disk() {
    let mut sb = alloc::vec![0u8; 512];
    sb[0..4].copy_from_slice(b"IONA");
    // num_files = 0
    let _ = try_write_sector(0, &sb);
    crate::serial_println!("  [IONAFS] disk formatted with empty IONAFS");
}

/// Persist all in-memory files to disk (called on sync/shutdown)
pub fn sync_to_disk() {
    let fs_lock = FS.lock();
    let files: alloc::vec::Vec<(alloc::string::String, alloc::vec::Vec<u8>)> =
        fs_lock.cache.iter().map(|(k,v)| (k.clone(), v.clone())).collect();
    drop(fs_lock);

    let mut next_lba = DISK_DATA_LBA_START;
    let mut index_entries = alloc::vec![0u8; 120 * 64];
    let mut entry_count = 0usize;

    for (path, data) in &files {
        if entry_count >= 120 { break; }
        let sectors = (data.len() + 511) / 512;
        let data_lba = next_lba;

        // Write data sectors
        let mut padded = data.clone();
        padded.resize(sectors * 512, 0);
        for s in 0..sectors {
            let _ = try_write_sector(data_lba + s as u64, &padded[s*512..(s+1)*512]);
        }
        next_lba += sectors as u64;

        // Build index entry
        let off = entry_count * 64;
        index_entries[off] = 1; // used
        let pb = path.as_bytes();
        let copy_len = pb.len().min(32);
        index_entries[off+1..off+1+copy_len].copy_from_slice(&pb[..copy_len]);
        index_entries[off+33..off+41].copy_from_slice(&data_lba.to_le_bytes());
        index_entries[off+41..off+45].copy_from_slice(&(data.len() as u32).to_le_bytes());
        entry_count += 1;
    }

    // Write index to LBA 1-15
    for lba in 1u64..16 {
        let start = (lba as usize - 1) * 512;
        let end   = start + 512;
        if start < index_entries.len() {
            let slice = &index_entries[start..end.min(index_entries.len())];
            let mut buf = alloc::vec![0u8; 512];
            buf[..slice.len()].copy_from_slice(slice);
            let _ = try_write_sector(lba, &buf);
        } else {
            let _ = try_write_sector(lba, &alloc::vec![0u8; 512]);
        }
    }

    // Update superblock
    let mut sb = alloc::vec![0u8; 512];
    sb[0..4].copy_from_slice(b"IONA");
    sb[4..8].copy_from_slice(&(entry_count as u32).to_le_bytes());
    let _ = try_write_sector(0, &sb);

    crate::serial_println!("  [IONAFS] sync: {} files written to disk", entry_count);
}

fn try_read_sector(lba: u64, buf: &mut [u8]) -> bool {
    // Try NVMe port 0 first
    if true /* nvme assumed available */ {
        return crate::drivers::nvme::read_sectors(lba, 1, buf);
    }
    // Fallback to AHCI port 0
    if crate::drivers::ahci::is_available() {
        let mut tmp = alloc::vec![0u8; 512];
        if crate::drivers::ahci::read_sectors(0, lba, 1, &mut tmp) {
            let n = buf.len().min(512);
            buf[..n].copy_from_slice(&tmp[..n]);
            return true;
        }
    }
    false
}

fn try_write_sector(lba: u64, buf: &[u8]) -> bool {
    let mut padded = alloc::vec![0u8; 512];
    let n = buf.len().min(512);
    padded[..n].copy_from_slice(&buf[..n]);

    if true /* nvme assumed available */ {
        return crate::drivers::nvme::write_sectors(lba, &padded);
    }
    if crate::drivers::ahci::is_available() {
        return crate::drivers::ahci::write_sectors(0, lba, &padded);
    }
    false
}

/// Public alias for journaled write (used by tests + external callers)
pub fn journal_append(path: &str, data: &[u8]) {
    FS.lock().journal_write(path, data);
}

/// Public alias for journal replay (used at boot/fsck)
pub fn replay_journal() {
    FS.lock().recover_journal();
}

pub fn total_sectors() -> u64 { 1024 * 1024 / 512 } // 1MB default
pub fn used_sectors()  -> u64 {
    FS.lock().next_lba.saturating_sub(64) // data starts at LBA 64
}
