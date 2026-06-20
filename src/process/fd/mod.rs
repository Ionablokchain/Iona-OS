//! Per-process file descriptor table
//!
//! Implements POSIX file descriptor management with:
//! - Reference‑counted tables (shared via CLONE_FILES)
//! - File descriptor flags (O_CLOEXEC, O_NONBLOCK)
//! - dup, dup2, dup3, fcntl system calls
//! - Integration with epoll (automatic removal on close)
//! - Secure defaults: fd 0=stdin, 1=stdout, 2=stderr
//! - Configurable maximum file descriptors
//! - Metrics for monitoring fd usage
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │                FdTable (Arc)                │
//! │  ┌─────────────────────────────────────────┐│
//! │  │  entries: Vec<Option<FdEntry>>         ││
//! │  │  refcount: AtomicUsize                  ││
//! │  │  flags: FdTableFlags                   ││
//! │  └─────────────────────────────────────────┘│
//! └─────────────────────────────────────────────┘
//!                      │
//!                      ▼
//! ┌─────────────────────────────────────────────┐
//! │              FdEntry (struct)               │
//! │  ┌─────────────────────────────────────────┐│
//! │  │  desc: FileDesc                        ││
//! │  │  flags: FdFlags (O_CLOEXEC, etc.)     ││
//! │  └─────────────────────────────────────────┘│
//! └─────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! let table = FdTable::new();
//! let fd = table.open(FileDesc::Serial, FdFlags::empty())?;
//! let dup_fd = table.dup(fd)?;
//! table.close(fd)?;
//! ```

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::{Mutex, MutexGuard};
use tracing::{debug, error, info, trace, warn};

use crate::task::TaskId;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Standard file descriptors.
pub const STDIN_FILENO: usize = 0;
pub const STDOUT_FILENO: usize = 1;
pub const STDERR_FILENO: usize = 2;

/// Default maximum number of file descriptors per process.
pub const DEFAULT_MAX_FD: usize = 1024;

/// Maximum file descriptors allowed by the system.
pub const MAX_FD_LIMIT: usize = 4096;

// -----------------------------------------------------------------------------
// File descriptor flags (fcntl F_GETFD/F_SETFD)
// -----------------------------------------------------------------------------

/// File descriptor flags (close‑on‑exec, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FdFlags {
    bits: u32,
}

impl FdFlags {
    /// Empty flags.
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    /// Close‑on‑exec flag.
    pub const fn cloexec(mut self) -> Self {
        self.bits |= 1;
        self
    }

    /// Check if close‑on‑exec is set.
    pub const fn is_cloexec(self) -> bool {
        (self.bits & 1) != 0
    }

    /// Convert to raw integer for fcntl.
    pub const fn as_u32(self) -> u32 {
        self.bits
    }

    /// Create from raw integer.
    pub const fn from_u32(bits: u32) -> Self {
        Self { bits: bits & 1 }
    }
}

// -----------------------------------------------------------------------------
// Open flags (O_* constants)
// -----------------------------------------------------------------------------

/// Open flags for `open()` and `fcntl(F_GETFL/F_SETFL)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenFlags {
    bits: u32,
}

impl OpenFlags {
    pub const fn empty() -> Self {
        Self { bits: 0 }
    }

    pub const fn read(self) -> Self {
        Self { bits: self.bits | 0x1 }
    }
    pub const fn write(self) -> Self {
        Self { bits: self.bits | 0x2 }
    }
    pub const fn rdwr(self) -> Self {
        Self { bits: self.bits | 0x3 }
    }
    pub const fn append(self) -> Self {
        Self { bits: self.bits | 0x400 }
    }
    pub const fn nonblock(self) -> Self {
        Self { bits: self.bits | 0x800 }
    }
    pub const fn cloexec(self) -> Self {
        Self { bits: self.bits | 0x80000 }
    }
    pub const fn create(self) -> Self {
        Self { bits: self.bits | 0x100 }
    }
    pub const fn truncate(self) -> Self {
        Self { bits: self.bits | 0x200 }
    }
    pub const fn exclusive(self) -> Self {
        Self { bits: self.bits | 0x80 }
    }

    pub const fn is_read(self) -> bool {
        (self.bits & 0x3) == 0x1
    }
    pub const fn is_write(self) -> bool {
        (self.bits & 0x3) == 0x2
    }
    pub const fn is_rdwr(self) -> bool {
        (self.bits & 0x3) == 0x3
    }
    pub const fn is_nonblock(self) -> bool {
        (self.bits & 0x800) != 0
    }
    pub const fn is_cloexec(self) -> bool {
        (self.bits & 0x80000) != 0
    }

    pub const fn as_u32(self) -> u32 {
        self.bits
    }

    pub const fn from_u32(bits: u32) -> Self {
        Self { bits: bits & 0x80F7F }
    }
}

// -----------------------------------------------------------------------------
// File descriptor types
// -----------------------------------------------------------------------------

/// Types of file descriptors supported by the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDesc {
    /// Serial port (stdout/stderr).
    Serial,
    /// Keyboard input (stdin).
    Keyboard,
    /// IONAFS file with path and current offset.
    IonafsFile {
        path: String,
        offset: u64,
    },
    /// TCP socket (socket ID).
    TcpSocket(u64),
    /// Pipe (read or write end).
    Pipe {
        read_end: bool,
        id: u64,
    },
    /// Device file (e.g., /dev/null).
    Dev(String),
    /// Proc file (e.g., /proc/self/status).
    Proc(String),
    /// Epoll instance.
    Epoll(u64),
    /// Eventfd (not yet implemented).
    Eventfd(u64),
    /// Signalfd (not yet implemented).
    Signalfd(u64),
    /// Timerfd (not yet implemented).
    Timerfd(u64),
}

impl FileDesc {
    /// Check if the descriptor is a socket.
    pub fn is_socket(&self) -> bool {
        matches!(self, FileDesc::TcpSocket(_))
    }

    /// Check if the descriptor is a pipe.
    pub fn is_pipe(&self) -> bool {
        matches!(self, FileDesc::Pipe { .. })
    }

    /// Check if the descriptor is a regular file.
    pub fn is_file(&self) -> bool {
        matches!(self, FileDesc::IonafsFile { .. })
    }

    /// Get the path (if a file).
    pub fn path(&self) -> Option<&str> {
        match self {
            FileDesc::IonafsFile { path, .. } => Some(path),
            FileDesc::Dev(path) => Some(path),
            FileDesc::Proc(path) => Some(path),
            _ => None,
        }
    }

    /// Get the socket ID (if a socket).
    pub fn socket_id(&self) -> Option<u64> {
        match self {
            FileDesc::TcpSocket(id) => Some(*id),
            _ => None,
        }
    }
}

// -----------------------------------------------------------------------------
// File descriptor entry
// -----------------------------------------------------------------------------

/// An entry in the file descriptor table.
#[derive(Debug, Clone)]
pub struct FdEntry {
    /// The file descriptor type.
    pub desc: FileDesc,
    /// File descriptor flags (O_CLOEXEC, etc.).
    pub flags: FdFlags,
    /// Open flags (O_NONBLOCK, O_APPEND, etc.).
    pub open_flags: OpenFlags,
}

impl FdEntry {
    /// Create a new entry.
    pub fn new(desc: FileDesc, flags: FdFlags, open_flags: OpenFlags) -> Self {
        Self {
            desc,
            flags,
            open_flags,
        }
    }
}

// -----------------------------------------------------------------------------
// File descriptor table
// -----------------------------------------------------------------------------

/// A file descriptor table (per-process or shared).
#[derive(Debug)]
pub struct FdTable {
    /// Entries indexed by file descriptor number.
    entries: Mutex<Vec<Option<FdEntry>>>,
    /// Maximum file descriptors allowed.
    max_fd: usize,
    /// Reference count for this table (shared via Arc).
    refcount: AtomicUsize,
}

impl FdTable {
    /// Create a new file descriptor table with default maximum.
    pub fn new() -> Self {
        Self::with_max(DEFAULT_MAX_FD)
    }

    /// Create a new file descriptor table with a custom maximum.
    pub fn with_max(max_fd: usize) -> Self {
        let max = max_fd.min(MAX_FD_LIMIT);
        let mut entries = Vec::with_capacity(max);
        entries.resize_with(max, || None);
        // Initialize stdin, stdout, stderr.
        if max > STDIN_FILENO {
            entries[STDIN_FILENO] = Some(FdEntry::new(
                FileDesc::Keyboard,
                FdFlags::empty(),
                OpenFlags::read(),
            ));
        }
        if max > STDOUT_FILENO {
            entries[STDOUT_FILENO] = Some(FdEntry::new(
                FileDesc::Serial,
                FdFlags::empty(),
                OpenFlags::write(),
            ));
        }
        if max > STDERR_FILENO {
            entries[STDERR_FILENO] = Some(FdEntry::new(
                FileDesc::Serial,
                FdFlags::empty(),
                OpenFlags::write(),
            ));
        }
        Self {
            entries: Mutex::new(entries),
            max_fd: max,
            refcount: AtomicUsize::new(1),
        }
    }

    /// Get the number of entries in the table (including empty slots).
    pub fn capacity(&self) -> usize {
        self.max_fd
    }

    /// Get the current number of open file descriptors.
    pub fn count(&self) -> usize {
        let entries = self.entries.lock();
        entries.iter().filter(|e| e.is_some()).count()
    }

    /// Get the reference count.
    pub fn refcount(&self) -> usize {
        self.refcount.load(Ordering::Relaxed)
    }

    /// Increment the reference count (for sharing).
    pub fn increment_refcount(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the reference count (for dropping).
    pub fn decrement_refcount(&self) -> usize {
        self.refcount.fetch_sub(1, Ordering::Relaxed) - 1
    }

    /// Open a new file descriptor.
    pub fn open(
        &self,
        desc: FileDesc,
        flags: FdFlags,
        open_flags: OpenFlags,
    ) -> Result<usize, FdError> {
        let mut entries = self.entries.lock();
        // Find the lowest available fd.
        for (fd, entry) in entries.iter_mut().enumerate() {
            if fd < 3 {
                // stdin, stdout, stderr cannot be replaced by default.
                // But they can be closed and replaced explicitly.
                // For simplicity, we allow it.
            }
            if entry.is_none() {
                *entry = Some(FdEntry::new(desc, flags, open_flags));
                trace!(fd, "fd opened");
                return Ok(fd);
            }
        }
        Err(FdError::TableFull)
    }

    /// Duplicate a file descriptor (dup/dup2/dup3).
    pub fn dup(&self, old_fd: usize, new_fd: Option<usize>, flags: FdFlags) -> Result<usize, FdError> {
        let mut entries = self.entries.lock();
        if old_fd >= entries.len() {
            return Err(FdError::InvalidFd(old_fd));
        }
        let old_entry = entries[old_fd].as_ref().ok_or(FdError::InvalidFd(old_fd))?;

        let target_fd = match new_fd {
            Some(fd) => {
                if fd >= entries.len() {
                    return Err(FdError::InvalidFd(fd));
                }
                // If target is open, close it first (dup2 semantics).
                if entries[fd].is_some() {
                    self.close_internal(&mut entries, fd)?;
                }
                fd
            }
            None => {
                // Find the lowest available fd.
                let mut found = None;
                for (fd, entry) in entries.iter().enumerate() {
                    if entry.is_none() && fd != old_fd {
                        found = Some(fd);
                        break;
                    }
                }
                found.ok_or(FdError::TableFull)?
            }
        };

        // Clone the entry with the new flags.
        let mut new_entry = old_entry.clone();
        new_entry.flags = flags;
        entries[target_fd] = Some(new_entry);
        trace!(old_fd, target_fd, "fd duplicated");
        Ok(target_fd)
    }

    /// Close a file descriptor.
    pub fn close(&self, fd: usize) -> Result<(), FdError> {
        let mut entries = self.entries.lock();
        self.close_internal(&mut entries, fd)
    }

    /// Internal close (assumes lock is already held).
    fn close_internal(&self, entries: &mut MutexGuard<'_, Vec<Option<FdEntry>>>, fd: usize) -> Result<(), FdError> {
        if fd >= entries.len() {
            return Err(FdError::InvalidFd(fd));
        }
        if entries[fd].is_none() {
            return Err(FdError::InvalidFd(fd));
        }
        // Notify epoll or other subsystems about fd closure.
        // If the fd is a socket, close the socket.
        if let Some(entry) = &entries[fd] {
            match &entry.desc {
                FileDesc::TcpSocket(id) => {
                    crate::net::socket_close(*id);
                }
                FileDesc::Pipe { read_end, id } => {
                    crate::process::pipe::close_pipe_end(*id, *read_end);
                }
                FileDesc::Epoll(id) => {
                    // Epoll instances are closed via epoll_close syscall.
                    // We just remove the reference.
                }
                _ => {}
            }
            // Remove from epoll watches.
            crate::syscall::epoll::epoll_remove_fd(fd);
        }
        entries[fd] = None;
        trace!(fd, "fd closed");
        Ok(())
    }

    /// Get a reference to a file descriptor entry.
    pub fn get(&self, fd: usize) -> Result<&FdEntry, FdError> {
        let entries = self.entries.lock();
        if fd >= entries.len() {
            return Err(FdError::InvalidFd(fd));
        }
        entries[fd].as_ref().ok_or(FdError::InvalidFd(fd))
    }

    /// Get a mutable reference to a file descriptor entry.
    pub fn get_mut(&self, fd: usize) -> Result<FdEntry, FdError> {
        let mut entries = self.entries.lock();
        if fd >= entries.len() {
            return Err(FdError::InvalidFd(fd));
        }
        entries[fd].clone().ok_or(FdError::InvalidFd(fd))
    }

    /// Set file descriptor flags (fcntl F_SETFD).
    pub fn set_fd_flags(&self, fd: usize, flags: FdFlags) -> Result<(), FdError> {
        let mut entries = self.entries.lock();
        if fd >= entries.len() {
            return Err(FdError::InvalidFd(fd));
        }
        let entry = entries[fd].as_mut().ok_or(FdError::InvalidFd(fd))?;
        entry.flags = flags;
        Ok(())
    }

    /// Set open flags (fcntl F_SETFL).
    pub fn set_open_flags(&self, fd: usize, flags: OpenFlags) -> Result<(), FdError> {
        let mut entries = self.entries.lock();
        if fd >= entries.len() {
            return Err(FdError::InvalidFd(fd));
        }
        let entry = entries[fd].as_mut().ok_or(FdError::InvalidFd(fd))?;
        entry.open_flags = flags;
        Ok(())
    }

    /// Get the file descriptor flags (fcntl F_GETFD).
    pub fn get_fd_flags(&self, fd: usize) -> Result<FdFlags, FdError> {
        let entry = self.get(fd)?;
        Ok(entry.flags)
    }

    /// Get the open flags (fcntl F_GETFL).
    pub fn get_open_flags(&self, fd: usize) -> Result<OpenFlags, FdError> {
        let entry = self.get(fd)?;
        Ok(entry.open_flags)
    }

    /// Duplicate a file descriptor with fcntl F_DUPFD.
    pub fn fcntl_dupfd(&self, fd: usize, min_fd: usize) -> Result<usize, FdError> {
        let mut entries = self.entries.lock();
        if fd >= entries.len() {
            return Err(FdError::InvalidFd(fd));
        }
        if entries[fd].is_none() {
            return Err(FdError::InvalidFd(fd));
        }
        let start = min_fd.max(0);
        for target in start..entries.len() {
            if target == fd {
                continue;
            }
            if entries[target].is_none() {
                let entry = entries[fd].clone().unwrap();
                entries[target] = Some(entry);
                trace!(fd, target, "fcntl F_DUPFD");
                return Ok(target);
            }
        }
        Err(FdError::TableFull)
    }

    /// Close all file descriptors marked with O_CLOEXEC.
    pub fn close_on_exec(&self) -> Vec<usize> {
        let mut entries = self.entries.lock();
        let mut closed = Vec::new();
        for (fd, entry) in entries.iter_mut().enumerate() {
            if let Some(e) = entry {
                if e.flags.is_cloexec() {
                    let _ = self.close_internal(&mut entries, fd);
                    closed.push(fd);
                }
            }
        }
        closed
    }

    /// Create a snapshot of the table (for forking).
    pub fn snapshot(&self) -> Self {
        let entries = self.entries.lock();
        let mut new_entries = Vec::with_capacity(self.max_fd);
        for entry in entries.iter() {
            new_entries.push(entry.clone());
        }
        Self {
            entries: Mutex::new(new_entries),
            max_fd: self.max_fd,
            refcount: AtomicUsize::new(1),
        }
    }

    /// Create a shared copy (increments refcount).
    pub fn shared_copy(&self) -> Arc<Self> {
        self.increment_refcount();
        Arc::new(self.clone())
    }
}

impl Clone for FdTable {
    fn clone(&self) -> Self {
        self.snapshot()
    }
}

// -----------------------------------------------------------------------------
// Error handling
// -----------------------------------------------------------------------------

/// Errors that can occur during file descriptor operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FdError {
    /// Invalid file descriptor.
    InvalidFd(usize),
    /// File descriptor table is full.
    TableFull,
    /// Permission denied.
    PermissionDenied,
    /// Operation not supported.
    Unsupported,
    /// File not found.
    NotFound,
    /// Invalid argument.
    InvalidArgument,
    /// I/O error.
    Io,
    /// Too many open files.
    TooManyOpenFiles,
}

impl fmt::Display for FdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFd(fd) => write!(f, "invalid file descriptor: {}", fd),
            Self::TableFull => write!(f, "file descriptor table full"),
            Self::PermissionDenied => write!(f, "permission denied"),
            Self::Unsupported => write!(f, "operation not supported"),
            Self::NotFound => write!(f, "file not found"),
            Self::InvalidArgument => write!(f, "invalid argument"),
            Self::Io => write!(f, "I/O error"),
            Self::TooManyOpenFiles => write!(f, "too many open files"),
        }
    }
}

// -----------------------------------------------------------------------------
// Global FD table registry
// -----------------------------------------------------------------------------

/// Mapping from task ID to its file descriptor table (Arc).
static FD_TABLES: spin::Mutex<BTreeMap<TaskId, Arc<FdTable>>> =
    spin::Mutex::new(BTreeMap::new());

/// Initialize a file descriptor table for a task.
pub fn init_for(tid: TaskId) {
    let table = Arc::new(FdTable::new());
    let mut tables = FD_TABLES.lock();
    tables.insert(tid, table);
    trace!(tid = tid.as_u64(), "fd table initialized");
}

/// Remove a task's file descriptor table.
pub fn remove_for(tid: TaskId) {
    let mut tables = FD_TABLES.lock();
    if let Some(table) = tables.remove(&tid) {
        // Drop the table (decrements refcount).
        drop(table);
        trace!(tid = tid.as_u64(), "fd table removed");
    }
}

/// Get a task's file descriptor table.
pub fn get_table(tid: TaskId) -> Option<Arc<FdTable>> {
    FD_TABLES.lock().get(&tid).cloned()
}

/// Open a file descriptor for a task.
pub fn open(tid: TaskId, desc: FileDesc, flags: FdFlags, open_flags: OpenFlags) -> Result<usize, FdError> {
    let table = get_table(tid).ok_or(FdError::InvalidArgument)?;
    table.open(desc, flags, open_flags)
}

/// Get a file descriptor entry for a task.
pub fn get(tid: TaskId, fd: usize) -> Result<FdEntry, FdError> {
    let table = get_table(tid).ok_or(FdError::InvalidArgument)?;
    table.get(fd).cloned()
}

/// Close a file descriptor for a task.
pub fn close(tid: TaskId, fd: usize) -> Result<(), FdError> {
    let table = get_table(tid).ok_or(FdError::InvalidArgument)?;
    table.close(fd)
}

/// Duplicate a file descriptor (dup).
pub fn dup(tid: TaskId, old_fd: usize, flags: FdFlags) -> Result<usize, FdError> {
    let table = get_table(tid).ok_or(FdError::InvalidArgument)?;
    table.dup(old_fd, None, flags)
}

/// Duplicate a file descriptor to a specific target (dup2/dup3).
pub fn dup2(tid: TaskId, old_fd: usize, new_fd: usize, flags: FdFlags) -> Result<usize, FdError> {
    let table = get_table(tid).ok_or(FdError::InvalidArgument)?;
    table.dup(old_fd, Some(new_fd), flags)
}

/// Share a file descriptor table between parent and child (CLONE_FILES).
pub fn share_fd_table(parent_tid: TaskId, child_tid: TaskId) {
    let tables = FD_TABLES.lock();
    if let Some(parent_table) = tables.get(&parent_tid) {
        // Increment refcount and insert the same table.
        parent_table.increment_refcount();
        drop(tables);
        let mut tables = FD_TABLES.lock();
        tables.insert(child_tid, parent_table.clone());
        trace!(parent_tid = parent_tid.as_u64(), child_tid = child_tid.as_u64(), "fd table shared");
    } else {
        // Parent doesn't have a table yet; create a new one.
        init_for(child_tid);
    }
}

/// Clone a file descriptor table independently (fork semantics).
pub fn clone_fd_table(parent_tid: TaskId, child_tid: TaskId) {
    let tables = FD_TABLES.lock();
    if let Some(parent_table) = tables.get(&parent_tid) {
        let child_table = Arc::new(parent_table.snapshot());
        drop(tables);
        let mut tables = FD_TABLES.lock();
        tables.insert(child_tid, child_table);
        trace!(parent_tid = parent_tid.as_u64(), child_tid = child_tid.as_u64(), "fd table cloned");
    } else {
        init_for(child_tid);
    }
}

/// Perform fcntl operations on a file descriptor.
pub fn fcntl(tid: TaskId, fd: usize, cmd: u32, arg: u64) -> Result<i64, FdError> {
    const F_DUPFD: u32 = 0;
    const F_GETFD: u32 = 1;
    const F_SETFD: u32 = 2;
    const F_GETFL: u32 = 3;
    const F_SETFL: u32 = 4;

    let table = get_table(tid).ok_or(FdError::InvalidArgument)?;

    match cmd {
        F_DUPFD => {
            let min_fd = arg as usize;
            let new_fd = table.fcntl_dupfd(fd, min_fd)?;
            Ok(new_fd as i64)
        }
        F_GETFD => {
            let flags = table.get_fd_flags(fd)?;
            Ok(flags.as_u32() as i64)
        }
        F_SETFD => {
            let flags = FdFlags::from_u32(arg as u32);
            table.set_fd_flags(fd, flags)?;
            Ok(0)
        }
        F_GETFL => {
            let flags = table.get_open_flags(fd)?;
            Ok(flags.as_u32() as i64)
        }
        F_SETFL => {
            let flags = OpenFlags::from_u32(arg as u32);
            table.set_open_flags(fd, flags)?;
            Ok(0)
        }
        _ => Err(FdError::Unsupported),
    }
}

// -----------------------------------------------------------------------------
// Epoll integration
// -----------------------------------------------------------------------------

/// Remove a file descriptor from all epoll instances (called on close).
#[allow(dead_code)]
pub fn epoll_remove_fd(fd: usize) {
    // This is implemented in the epoll module.
    // We call it from close_internal.
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Get the total number of open file descriptors across all tasks.
pub fn total_open_fds() -> usize {
    let tables = FD_TABLES.lock();
    tables.values().map(|t| t.count()).sum()
}

/// Get the number of active file descriptor tables.
pub fn active_tables() -> usize {
    FD_TABLES.lock().len()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fd_table_new() {
        let table = FdTable::new();
        assert_eq!(table.capacity(), DEFAULT_MAX_FD);
        assert_eq!(table.count(), 3);
        assert!(table.get(0).is_ok());
        assert!(table.get(1).is_ok());
        assert!(table.get(2).is_ok());
        assert!(table.get(3).is_err());
    }

    #[test]
    fn test_open_and_close() {
        let table = FdTable::new();
        let fd = table.open(FileDesc::Serial, FdFlags::empty(), OpenFlags::write()).unwrap();
        assert!(fd >= 3);
        assert_eq!(table.count(), 4);
        table.close(fd).unwrap();
        assert_eq!(table.count(), 3);
        assert!(table.get(fd).is_err());
    }

    #[test]
    fn test_dup() {
        let table = FdTable::new();
        let fd = table.open(FileDesc::Serial, FdFlags::empty(), OpenFlags::write()).unwrap();
        let dup_fd = table.dup(fd, None, FdFlags::cloexec()).unwrap();
        assert_ne!(fd, dup_fd);
        assert!(table.get(dup_fd).unwrap().flags.is_cloexec());
        table.close(fd).unwrap();
        assert!(table.get(dup_fd).is_ok());
        table.close(dup_fd).unwrap();
    }

    #[test]
    fn test_dup2() {
        let table = FdTable::new();
        let fd = table.open(FileDesc::Serial, FdFlags::empty(), OpenFlags::write()).unwrap();
        let target = 10;
        let result = table.dup(fd, Some(target), FdFlags::empty()).unwrap();
        assert_eq!(result, target);
        assert!(table.get(target).is_ok());
        table.close(fd).unwrap();
        assert!(table.get(target).is_ok());
    }

    #[test]
    fn test_fcntl_dupfd() {
        let table = FdTable::new();
        let fd = table.open(FileDesc::Serial, FdFlags::empty(), OpenFlags::write()).unwrap();
        let new_fd = table.fcntl_dupfd(fd, 5).unwrap();
        assert!(new_fd >= 5);
        table.close(fd).unwrap();
        table.close(new_fd).unwrap();
    }

    #[test]
    fn test_share_fd_table() {
        let parent = TaskId::from_u64(1);
        let child = TaskId::from_u64(2);
        init_for(parent);
        let fd = open(parent, FileDesc::Serial, FdFlags::empty(), OpenFlags::write()).unwrap();
        share_fd_table(parent, child);
        // Child should see the same fd.
        let child_entry = get(child, fd).unwrap();
        assert!(matches!(child_entry.desc, FileDesc::Serial));
        // Closing in parent should not close in child (shared table).
        close(parent, fd).unwrap();
        // Child still has it because the table is shared.
        assert!(get(child, fd).is_ok());
        // But if we close in child, it closes for both (shared table).
        close(child, fd).unwrap();
        assert!(get(parent, fd).is_err());
        remove_for(parent);
        remove_for(child);
    }

    #[test]
    fn test_clone_fd_table() {
        let parent = TaskId::from_u64(3);
        let child = TaskId::from_u64(4);
        init_for(parent);
        let fd = open(parent, FileDesc::Serial, FdFlags::empty(), OpenFlags::write()).unwrap();
        clone_fd_table(parent, child);
        // Child has a copy.
        assert!(get(child, fd).is_ok());
        // Closing in parent does not affect child.
        close(parent, fd).unwrap();
        assert!(get(child, fd).is_ok());
        // Closing in child removes its copy.
        close(child, fd).unwrap();
        assert!(get(child, fd).is_err());
        remove_for(parent);
        remove_for(child);
    }

    #[test]
    fn test_close_on_exec() {
        let table = FdTable::new();
        let fd1 = table.open(FileDesc::Serial, FdFlags::cloexec(), OpenFlags::write()).unwrap();
        let fd2 = table.open(FileDesc::Serial, FdFlags::empty(), OpenFlags::write()).unwrap();
        assert_eq!(table.count(), 5);
        let closed = table.close_on_exec();
        assert_eq!(closed, vec![fd1]);
        assert_eq!(table.count(), 4);
        assert!(table.get(fd1).is_err());
        assert!(table.get(fd2).is_ok());
        table.close(fd2).unwrap();
    }
}
