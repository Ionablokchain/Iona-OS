//! File stat, permissions, timestamps — POSIX stat struct + RTC timestamps
//!
//! Timestamps vin din RTC (Real Time Clock) via CMOS ports 0x70/0x71.

use x86_64::instructions::port::Port;

/// POSIX stat structure (simplified)
#[repr(C)]
pub struct Stat {
    pub st_dev:   u64,   // device ID
    pub st_ino:   u64,   // inode number
    pub st_mode:  u32,   // file type + permissions
    pub st_nlink: u32,   // number of hard links
    pub st_uid:   u32,   // user ID
    pub st_gid:   u32,   // group ID
    pub st_size:  u64,   // total size in bytes
    pub st_atime: u64,   // last access time (unix timestamp)
    pub st_mtime: u64,   // last modification time
    pub st_ctime: u64,   // last status change time
    pub st_blksize: u64, // block size
    pub st_blocks:  u64, // number of 512B blocks
}

/// File permission bits (mode)
pub const S_IFREG:  u32 = 0o100000; // regular file
pub const S_IFDIR:  u32 = 0o040000; // directory
pub const S_IFLNK:  u32 = 0o120000; // symbolic link
pub const S_IRWXU:  u32 = 0o000700; // user rwx
pub const S_IRUSR:  u32 = 0o000400; // user read
pub const S_IWUSR:  u32 = 0o000200; // user write
pub const S_IXUSR:  u32 = 0o000100; // user execute
pub const S_IRGRP:  u32 = 0o000040; // group read
pub const S_IROTH:  u32 = 0o000004; // other read

pub const MODE_FILE: u32 = S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH; // 0o100644
pub const MODE_DIR:  u32 = S_IFDIR | S_IRWXU | S_IRGRP | S_IROTH;            // 0o040755
pub const MODE_EXEC: u32 = S_IFREG | S_IRWXU | S_IRGRP | S_IROTH;            // 0o100755

/// Read current time from RTC (CMOS) as Unix timestamp approximation
/// CMOS ports: 0x70 = address, 0x71 = data
/// Registers: 0=sec, 2=min, 4=hour, 7=day, 8=month, 9=year
pub fn rtc_timestamp() -> u64 {
    unsafe {
        let mut addr: Port<u8> = Port::new(0x70);
        let mut data: Port<u8> = Port::new(0x71);

        let read_reg = |reg: u8| -> u8 {
            addr.write(reg);
            data.read()
        };

        let from_bcd = |v: u8| -> u64 { ((v >> 4) as u64) * 10 + (v & 0xF) as u64 };

        let sec   = from_bcd(read_reg(0x00));
        let min   = from_bcd(read_reg(0x02));
        let hour  = from_bcd(read_reg(0x04));
        let day   = from_bcd(read_reg(0x07));
        let month = from_bcd(read_reg(0x08));
        let year  = from_bcd(read_reg(0x09)) + 2000; // 2-digit year + 2000

        // Approximate Unix timestamp (ignores leap years, DST etc.)
        let days_since_epoch = (year - 1970) * 365 + (month - 1) * 30 + day;
        days_since_epoch * 86400 + hour * 3600 + min * 60 + sec
    }
}

/// File lock state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LockType {
    None,
    Shared,    // LOCK_SH — multiple readers allowed
    Exclusive, // LOCK_EX — single writer
}

/// In-memory file lock table
static FILE_LOCKS: spin::Lazy<spin::Mutex<alloc::collections::BTreeMap<alloc::string::String, (LockType, crate::task::TaskId)>>>
    = spin::Lazy::new(|| spin::Mutex::new(alloc::collections::BTreeMap::new()));

/// flock() — file locking
pub fn flock(path: &str, lock_type: LockType, tid: crate::task::TaskId) -> bool {
    let mut locks = FILE_LOCKS.lock();
    match locks.get(path) {
        None => {
            if lock_type != LockType::None {
                locks.insert(path.into(), (lock_type, tid));
            }
            true
        }
        Some(&(LockType::Shared, _)) => {
            // Can add another shared lock
            if lock_type == LockType::Shared { true }
            else if lock_type == LockType::None { locks.remove(path); true }
            else { false } // can't get exclusive when shared
        }
        Some(&(LockType::Exclusive, owner)) => {
            if owner == tid {
                // Same task — allow unlock
                if lock_type == LockType::None { locks.remove(path); }
                true
            } else {
                false // locked by another task
            }
        }
        _ => false,
    }
}
