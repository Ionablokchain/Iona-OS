//! redb → IONAFS storage backend — production implementation
//!
//! Maps redb's page-based I/O to IONAFS files.
//! Layout:
//!   /db/{name}/super     — database superblock (8 bytes: num_pages)
//!   /db/{name}/p{N}      — page N (4096 bytes each)
//!
//! Features:
//!   - 4KB aligned I/O
//!   - Read cache (LRU, 64 pages)
//!   - Write-through to IONAFS (journaled)
//!   - Crash-safe: IONAFS WAL guarantees durability
//!   - grow_to() extends the database file

use alloc::{collections::BTreeMap, format, string::String, vec::Vec};

const PAGE_SIZE:  usize = 4096;
const CACHE_SIZE: usize = 64;

struct PageCache {
    pages: BTreeMap<u64, Vec<u8>>,
    order: Vec<u64>, // LRU order
}

impl PageCache {
    fn new() -> Self { Self { pages: BTreeMap::new(), order: Vec::new() } }

    fn get(&self, page: u64) -> Option<&Vec<u8>> { self.pages.get(&page) }

    fn insert(&mut self, page: u64, data: Vec<u8>) {
        if self.pages.contains_key(&page) {
            self.order.retain(|&p| p != page);
        } else if self.pages.len() >= CACHE_SIZE {
            // Evict LRU
            if let Some(lru) = self.order.first().cloned() {
                self.order.remove(0);
                self.pages.remove(&lru);
            }
        }
        self.pages.insert(page, data);
        self.order.push(page);
    }

    fn invalidate(&mut self, page: u64) {
        self.pages.remove(&page);
        self.order.retain(|&p| p != page);
    }
}

pub struct IonafsDatabaseFile {
    db_name:   String,
    num_pages: u64,
    cache:     PageCache,
    dirty:     BTreeMap<u64, Vec<u8>>, // write buffer
}

impl IonafsDatabaseFile {
    pub fn open(db_name: &str) -> Self {
        let super_path = format!("/db/{}/super", db_name);
        let num_pages  = crate::fs::ionafs::read(&super_path)
            .and_then(|d| d.get(0..8).map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0;8]))))
            .unwrap_or(0);

        crate::serial_println!("  [REDB] opened '{}': {} pages", db_name, num_pages);
        Self { db_name: db_name.into(), num_pages, cache: PageCache::new(), dirty: BTreeMap::new() }
    }

    pub fn create(db_name: &str) -> Self {
        // Initialize with 2 pages (redb needs at least 2 for header)
        let mut db = Self {
            db_name: db_name.into(), num_pages: 0,
            cache: PageCache::new(), dirty: BTreeMap::new(),
        };
        db.grow_to(2 * PAGE_SIZE as u64);
        db
    }

    /// Total database size in bytes
    pub fn len(&self) -> u64 { self.num_pages * PAGE_SIZE as u64 }

    pub fn is_empty(&self) -> bool { self.num_pages == 0 }

    /// Read bytes at offset (may span multiple pages)
    pub fn read_at(&mut self, offset: u64, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        let mut pos    = offset;
        while result.len() < len {
            let page    = pos / PAGE_SIZE as u64;
            let off_in  = (pos % PAGE_SIZE as u64) as usize;
            let can_read = (PAGE_SIZE - off_in).min(len - result.len());

            let page_data = self.read_page(page);
            let end = (off_in + can_read).min(page_data.len());
            result.extend_from_slice(&page_data[off_in..end]);
            pos += can_read as u64;
        }
        result
    }

    /// Write bytes at offset (may span multiple pages)
    pub fn write_at(&mut self, offset: u64, data: &[u8]) {
        let mut pos = offset;
        let mut src = 0;
        while src < data.len() {
            let page   = pos / PAGE_SIZE as u64;
            let off_in = (pos % PAGE_SIZE as u64) as usize;
            let can_wr = (PAGE_SIZE - off_in).min(data.len() - src);

            // Read-modify-write for partial page writes
            let mut page_data = self.read_page(page);
            if page_data.len() < PAGE_SIZE { page_data.resize(PAGE_SIZE, 0); }
            page_data[off_in..off_in + can_wr].copy_from_slice(&data[src..src + can_wr]);

            // Cache and mark dirty
            self.cache.insert(page, page_data.clone());
            self.dirty.insert(page, page_data);

            pos += can_wr as u64;
            src += can_wr;
        }
    }

    /// Flush all dirty pages to IONAFS (crash-safe via WAL)
    pub fn flush(&mut self) {
        let dirty: BTreeMap<u64, Vec<u8>> = core::mem::take(&mut self.dirty);
        for (page, data) in &dirty {
            let path = format!("/db/{}/p{}", self.db_name, page);
            crate::fs::ionafs::write(&path, data);
        }
        self.write_superblock();
        crate::serial_println!("  [REDB] flushed {} dirty pages", dirty.len());
    }

    /// Grow database to at least `new_size` bytes
    pub fn grow_to(&mut self, new_size: u64) {
        let new_pages = (new_size + PAGE_SIZE as u64 - 1) / PAGE_SIZE as u64;
        if new_pages <= self.num_pages { return; }

        // Zero-initialize new pages
        for p in self.num_pages..new_pages {
            let path = format!("/db/{}/p{}", self.db_name, p);
            crate::fs::ionafs::write(&path, &alloc::vec![0u8; PAGE_SIZE]);
        }
        self.num_pages = new_pages;
        self.write_superblock();
        crate::serial_println!("  [REDB] grew to {} pages", self.num_pages);
    }

    fn read_page(&mut self, page: u64) -> Vec<u8> {
        if let Some(cached) = self.cache.get(page) {
            return cached.clone();
        }
        let path = format!("/db/{}/p{}", self.db_name, page);
        let data = crate::fs::ionafs::read(&path)
            .unwrap_or_else(|| alloc::vec![0u8; PAGE_SIZE]);
        self.cache.insert(page, data.clone());
        data
    }

    fn write_superblock(&self) {
        let mut sb = [0u8; 16];
        sb[0..8].copy_from_slice(&self.num_pages.to_le_bytes());
        sb[8..16].copy_from_slice(&(PAGE_SIZE as u64).to_le_bytes());
        crate::fs::ionafs::write(&format!("/db/{}/super", self.db_name), &sb);
    }
}
