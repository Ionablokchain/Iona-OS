//! Slab allocator — O(1) fixed-size object allocation
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::{Lazy, Mutex};

const PAGE_SIZE: usize = 4096;
const PHYS_OFF:  u64   = 0xFFFF_8000_0000_0000;

pub struct SlabCache {
    obj_size:  usize,
    free_list: Vec<*mut u8>,
    pub total: usize,
    pub free:  usize,
}
unsafe impl Send for SlabCache {}

impl SlabCache {
    fn new(sz: usize) -> Self {
        Self { obj_size: (sz.max(8) + 15) & !15, free_list: Vec::new(), total: 0, free: 0 }
    }
    fn grow(&mut self) {
        let p = match crate::mm::buddy::alloc_page() { Some(p) => p, None => return };
        let v = (PHYS_OFF + p) as *mut u8;
        let n = PAGE_SIZE / self.obj_size;
        for i in 0..n { self.free_list.push(unsafe { v.add(i * self.obj_size) }); }
        self.total += n; self.free += n;
    }
    pub fn alloc(&mut self) -> Option<*mut u8> {
        if self.free_list.is_empty() { self.grow(); }
        let p = self.free_list.pop()?;
        self.free -= 1;
        unsafe { core::ptr::write_bytes(p, 0, self.obj_size); }
        Some(p)
    }
    pub fn free(&mut self, p: *mut u8) { self.free_list.push(p); self.free += 1; }
}

static SLAB: Lazy<Mutex<BTreeMap<String, SlabCache>>> = Lazy::new(|| {
    let mut m = BTreeMap::new();
    m.insert("task".into(),   SlabCache::new(256));
    m.insert("socket".into(), SlabCache::new(512));
    m.insert("file".into(),   SlabCache::new(128));
    m.insert("inode".into(),  SlabCache::new(192));
    m.insert("dentry".into(), SlabCache::new(96));
    m.insert("pipe".into(),   SlabCache::new(64));
    Mutex::new(m)
});

pub fn init() { let _ = &*SLAB; crate::serial_println!("  [SLAB] caches: task/socket/file/inode/dentry/pipe"); }
pub fn alloc(name: &str) -> Option<*mut u8> { SLAB.lock().get_mut(name)?.alloc() }
pub fn free(name: &str, p: *mut u8)         { if let Some(c) = SLAB.lock().get_mut(name) { c.free(p); } }

pub fn create_cache(name: &str, sz: usize)  { SLAB.lock().insert(name.into(), SlabCache::new(sz)); }
