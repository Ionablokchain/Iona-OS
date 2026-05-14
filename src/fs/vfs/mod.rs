//! Virtual File System — uniform interface over all filesystems
//!
//! Trait FileSystem + mount table + path resolution.
//! All syscalls go through VFS: open→read/write→close
use alloc::{boxed::Box, string::String, vec::Vec};
use spin::{Lazy, Mutex};

pub type Fd = usize;
pub type Result<T> = core::result::Result<T, FsError>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FsError { NotFound, NotDir, IsDir, PermDenied, Io, NoSpace, TooManyOpen, InvalidArg }

pub struct Stat {
    pub size:     u64,
    pub is_dir:   bool,
    pub is_file:  bool,
    pub mode:     u16,
}

/// Every filesystem implements this trait
pub trait FileSystem: Send + Sync {
    fn read(&self,  path: &str, buf: &mut [u8], offset: u64) -> Result<usize>;
    fn write(&self, path: &str, buf: &[u8],     offset: u64) -> Result<usize>;
    fn readdir(&self, path: &str)  -> Result<Vec<String>>;
    fn stat(&self,    path: &str)  -> Result<Stat>;
    fn create(&self,  path: &str)  -> Result<()>;
    fn remove(&self,  path: &str)  -> Result<()>;
    fn name(&self) -> &'static str;
}

struct MountEntry { prefix: String, fs: Box<dyn FileSystem> }

struct MountTable { entries: Vec<MountEntry> }

impl MountTable {
    fn new() -> Self { Self { entries: Vec::new() } }

    fn mount(&mut self, prefix: &str, fs: Box<dyn FileSystem>) {
        crate::serial_println!("  [VFS] mount {} → {}", prefix, fs.name());
        self.entries.push(MountEntry { prefix: prefix.into(), fs });
    }

    fn resolve<'a>(&'a self, path: &'a str) -> Option<(&'a dyn FileSystem, &'a str)> {
        // Find longest matching prefix
        let mut best_len = 0;
        let mut best_idx = None;
        for (i, e) in self.entries.iter().enumerate() {
            if path.starts_with(e.prefix.as_str()) && e.prefix.len() > best_len {
                best_len = e.prefix.len();
                best_idx = Some(i);
            }
        }
        let idx = best_idx?;
        let e   = &self.entries[idx];
        let rel = if best_len >= path.len() { "/" } else { &path[best_len..] };
        Some((e.fs.as_ref(), rel))
    }
}

static VFS: Lazy<Mutex<MountTable>> = Lazy::new(|| Mutex::new(MountTable::new()));

pub fn mount(prefix: &str, fs: Box<dyn FileSystem>) {
    VFS.lock().mount(prefix, fs);
}

pub fn read(path: &str, buf: &mut [u8], offset: u64) -> Result<usize> {
    let vfs = VFS.lock();
    let (fs, rel) = vfs.resolve(path).ok_or(FsError::NotFound)?;
    fs.read(rel, buf, offset)
}

pub fn write(path: &str, buf: &[u8], offset: u64) -> Result<usize> {
    let vfs = VFS.lock();
    let (fs, rel) = vfs.resolve(path).ok_or(FsError::NotFound)?;
    fs.write(rel, buf, offset)
}

pub fn readdir(path: &str) -> Result<Vec<String>> {
    let vfs = VFS.lock();
    let (fs, rel) = vfs.resolve(path).ok_or(FsError::NotFound)?;
    fs.readdir(rel)
}

pub fn stat(path: &str) -> Result<Stat> {
    let vfs = VFS.lock();
    let (fs, rel) = vfs.resolve(path).ok_or(FsError::NotFound)?;
    fs.stat(rel)
}

pub fn create(path: &str) -> Result<()> {
    let vfs = VFS.lock();
    let (fs, rel) = vfs.resolve(path).ok_or(FsError::NotFound)?;
    fs.create(rel)
}

pub fn exists(path: &str) -> bool { stat(path).is_ok() }
