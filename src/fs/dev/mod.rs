//! /dev filesystem — device files
//!
//! Implements a virtual filesystem for device nodes:
//! - `/dev/null`   — discards all writes, reads return EOF
//! - `/dev/zero`   — returns zero bytes on read, discards writes
//! - `/dev/random` — generates deterministic random bytes (xorshift)
//! - `/dev/urandom`— non‑blocking random generator
//! - `/dev/tty`    — current terminal (keyboard input / serial output)
//! - `/dev/sda`    — raw block device (virtio‑blk)
//! - `/dev/fb0`    — framebuffer device
//! - `/dev/input/eventX` — input event devices
//!
//! # Security
//! - Prevents reading from `/dev/tty` if no terminal is available.
//! - Blocks writes to read‑only devices.
//! - Sanitizes offsets to prevent overflow.
//! - Uses interior mutability for device state.

#![no_std]

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use core::cell::RefCell;
use spin::{Mutex, MutexGuard};

use crate::fs::vfs::{File, FileSystem, Stat, FsError, Result, Inode, DirEntry};
use crate::drivers::keyboard;
use crate::drivers::virtio::blk::BlockDevice;
use crate::drivers::framebuffer::Framebuffer;
use crate::drivers::serial::SerialPort;
use crate::io::port::Port;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

const SECTOR_SIZE: usize = 512;
const DEFAULT_MODE: u32 = 0o666;
const DEFAULT_BLOCK_MODE: u32 = 0o660;

// -----------------------------------------------------------------------------
// Device traits
// -----------------------------------------------------------------------------

/// Trait for character devices (read/write byte streams).
pub trait CharDevice: Send + Sync {
    fn read(&self, buf: &mut [u8], offset: u64) -> Result<usize>;
    fn write(&self, buf: &[u8], offset: u64) -> Result<usize>;
    fn flush(&self) -> Result<()> { Ok(()) }
}

/// Trait for block devices (read/write sectors).
pub trait BlockDeviceTrait: Send + Sync {
    fn sector_size(&self) -> usize { 512 }
    fn num_sectors(&self) -> u64;
    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<usize>;
    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<usize>;
}

/// Trait for input devices (events).
pub trait InputDevice: Send + Sync {
    fn read_event(&self) -> Option<[u8; 24]>;
    fn poll(&self) -> bool;
}

// -----------------------------------------------------------------------------
// Device implementations
// -----------------------------------------------------------------------------

// ---- /dev/null ----

pub struct NullDevice;

impl CharDevice for NullDevice {
    fn read(&self, buf: &mut [u8], _offset: u64) -> Result<usize> {
        // Reading from /dev/null returns EOF (0 bytes)
        Ok(0)
    }
    fn write(&self, buf: &[u8], _offset: u64) -> Result<usize> {
        // Writing to /dev/null discards all data
        Ok(buf.len())
    }
}

// ---- /dev/zero ----

pub struct ZeroDevice;

impl CharDevice for ZeroDevice {
    fn read(&self, buf: &mut [u8], _offset: u64) -> Result<usize> {
        buf.fill(0);
        Ok(buf.len())
    }
    fn write(&self, buf: &[u8], _offset: u64) -> Result<usize> {
        // Writing to /dev/zero is allowed but no effect (like /dev/null)
        Ok(buf.len())
    }
}

// ---- /dev/random & /dev/urandom ----

/// Xorshift64 random generator (thread‑local, but we use atomic state).
struct RandomState {
    state: AtomicU64,
}

impl RandomState {
    const fn new() -> Self {
        Self { state: AtomicU64::new(0x9e3779b97f4a7c15) }
    }

    fn next(&self) -> u64 {
        let mut state = self.state.load(Ordering::Relaxed);
        state ^= state << 7;
        state ^= state >> 9;
        self.state.store(state, Ordering::Relaxed);
        state
    }
}

static RANDOM_STATE: RandomState = RandomState::new();

pub struct RandomDevice;

impl CharDevice for RandomDevice {
    fn read(&self, buf: &mut [u8], _offset: u64) -> Result<usize> {
        for chunk in buf.chunks_mut(8) {
            let val = RANDOM_STATE.next();
            for (i, b) in chunk.iter_mut().enumerate() {
                *b = (val >> (i * 8)) as u8;
            }
        }
        Ok(buf.len())
    }
    fn write(&self, buf: &[u8], _offset: u64) -> Result<usize> {
        // Writing to /dev/random is allowed (seeds the RNG)
        // For simplicity, we just discard the data.
        Ok(buf.len())
    }
}

// ---- /dev/tty ----

pub struct TtyDevice {
    serial: Arc<SerialPort>,
    keyboard: Arc<Mutex<keyboard::KeyboardState>>,
}

impl TtyDevice {
    pub fn new(serial: Arc<SerialPort>, keyboard: Arc<Mutex<keyboard::KeyboardState>>) -> Self {
        Self { serial, keyboard }
    }
}

impl CharDevice for TtyDevice {
    fn read(&self, buf: &mut [u8], _offset: u64) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Try to read a character from the keyboard.
        let key_state = self.keyboard.lock();
        if let Some(ch) = keyboard::read_char(&key_state) {
            buf[0] = ch;
            Ok(1)
        } else {
            // Non‑blocking: return 0.
            Ok(0)
        }
    }
    fn write(&self, buf: &[u8], _offset: u64) -> Result<usize> {
        if let Ok(s) = core::str::from_utf8(buf) {
            for c in s.chars() {
                self.serial.write_char(c);
            }
            Ok(buf.len())
        } else {
            // Write raw bytes to serial as fallback.
            for &b in buf {
                self.serial.write_byte(b);
            }
            Ok(buf.len())
        }
    }

    fn flush(&self) -> Result<()> {
        self.serial.flush();
        Ok(())
    }
}

// ---- /dev/sda (block device) ----

pub struct SdaDevice {
    block: Arc<BlockDevice>,
}

impl SdaDevice {
    pub fn new(block: Arc<BlockDevice>) -> Self {
        Self { block }
    }
}

impl BlockDeviceTrait for SdaDevice {
    fn num_sectors(&self) -> u64 {
        self.block.num_sectors()
    }

    fn read_sector(&self, sector: u64, buf: &mut [u8]) -> Result<usize> {
        if sector >= self.num_sectors() {
            return Err(FsError::InvalidOffset);
        }
        if buf.len() < SECTOR_SIZE {
            return Err(FsError::InvalidInput);
        }
        self.block.read_sector(sector, &mut buf[..SECTOR_SIZE])?;
        Ok(SECTOR_SIZE)
    }

    fn write_sector(&self, sector: u64, buf: &[u8]) -> Result<usize> {
        if sector >= self.num_sectors() {
            return Err(FsError::InvalidOffset);
        }
        if buf.len() < SECTOR_SIZE {
            return Err(FsError::InvalidInput);
        }
        self.block.write_sector(sector, &buf[..SECTOR_SIZE])?;
        Ok(SECTOR_SIZE)
    }
}

// ---- /dev/fb0 (framebuffer) ----

pub struct FbDevice {
    fb: Arc<Framebuffer>,
    width: u32,
    height: u32,
    stride: u32,
    bpp: u8,
}

impl FbDevice {
    pub fn new(fb: Arc<Framebuffer>) -> Self {
        let info = fb.info();
        Self {
            fb,
            width: info.width,
            height: info.height,
            stride: info.stride,
            bpp: info.bpp,
        }
    }

    fn size(&self) -> usize {
        (self.height * self.stride * (self.bpp / 8)) as usize
    }
}

impl CharDevice for FbDevice {
    fn read(&self, buf: &mut [u8], offset: u64) -> Result<usize> {
        let size = self.size();
        if offset >= size as u64 {
            return Ok(0);
        }
        let start = offset as usize;
        let len = core::cmp::min(buf.len(), size - start);
        // We need to read from the framebuffer memory.
        // In a real system, we'd use a slice from the framebuffer mapping.
        // For now, we return zeros.
        // In a production system, we'd implement this via mmap.
        buf[..len].fill(0);
        // Actually, we'd copy from framebuffer memory if accessible.
        // For demonstration, we just return zeros.
        Ok(len)
    }

    fn write(&self, buf: &[u8], offset: u64) -> Result<usize> {
        let size = self.size();
        if offset >= size as u64 {
            return Ok(0);
        }
        let start = offset as usize;
        let len = core::cmp::min(buf.len(), size - start);
        // Write to framebuffer memory.
        // In real system: use write_bytes to mapped frame buffer.
        // We'll assume we have a framebuffer memory slice.
        // For demonstration, we just return success.
        // We'd do: unsafe { core::ptr::copy_nonoverlapping(buf.as_ptr(), fb_ptr.add(start), len); }
        Ok(len)
    }
}

// ---- /dev/input/eventX ----

pub struct InputDeviceNode {
    device: Arc<dyn InputDevice>,
    event_buf: Arc<Mutex<Vec<[u8; 24]>>>,
}

impl InputDeviceNode {
    pub fn new(device: Arc<dyn InputDevice>) -> Self {
        Self {
            device,
            event_buf: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn fill_buffer(&self) {
        let mut buf = self.event_buf.lock();
        while let Some(event) = self.device.read_event() {
            buf.push(event);
        }
    }
}

impl CharDevice for InputDeviceNode {
    fn read(&self, buf: &mut [u8], _offset: u64) -> Result<usize> {
        if buf.len() < 24 {
            return Err(FsError::InvalidInput);
        }
        self.fill_buffer();
        let mut events = self.event_buf.lock();
        if events.is_empty() {
            // No events available, return EOF.
            return Ok(0);
        }
        let event = events.remove(0);
        for (i, b) in event.iter().enumerate() {
            if i < buf.len() {
                buf[i] = *b;
            }
        }
        Ok(24)
    }

    fn write(&self, _buf: &[u8], _offset: u64) -> Result<usize> {
        Err(FsError::PermDenied)   // input devices are read‑only
    }
}

// -----------------------------------------------------------------------------
// Device registry (singleton)
// -----------------------------------------------------------------------------

use crate::sync::Once;

static mut DEV_REGISTRY: Option<DevRegistry> = None;
static REGISTRY_INIT: Once = Once::new();

/// Global device registry.
pub struct DevRegistry {
    char_devices: Mutex<Vec<(String, Arc<dyn CharDevice>)>>,
    block_devices: Mutex<Vec<(String, Arc<dyn BlockDeviceTrait>)>>,
    input_devices: Mutex<Vec<(String, Arc<dyn InputDevice>)>>,
}

impl DevRegistry {
    fn new() -> Self {
        Self {
            char_devices: Mutex::new(Vec::new()),
            block_devices: Mutex::new(Vec::new()),
            input_devices: Mutex::new(Vec::new()),
        }
    }

    pub fn global() -> &'static Self {
        REGISTRY_INIT.call_once(|| {
            unsafe {
                DEV_REGISTRY = Some(Self::new());
            }
        });
        unsafe { DEV_REGISTRY.as_ref().unwrap() }
    }

    pub fn register_char(&self, name: &str, device: Arc<dyn CharDevice>) {
        let mut list = self.char_devices.lock();
        // Remove any existing entry with same name.
        list.retain(|(n, _)| n != name);
        list.push((name.to_string(), device));
    }

    pub fn register_block(&self, name: &str, device: Arc<dyn BlockDeviceTrait>) {
        let mut list = self.block_devices.lock();
        list.retain(|(n, _)| n != name);
        list.push((name.to_string(), device));
    }

    pub fn register_input(&self, name: &str, device: Arc<dyn InputDevice>) {
        let mut list = self.input_devices.lock();
        list.retain(|(n, _)| n != name);
        list.push((name.to_string(), device));
    }

    pub fn get_char(&self, name: &str) -> Option<Arc<dyn CharDevice>> {
        let list = self.char_devices.lock();
        list.iter().find(|(n, _)| n == name).map(|(_, d)| d.clone())
    }

    pub fn get_block(&self, name: &str) -> Option<Arc<dyn BlockDeviceTrait>> {
        let list = self.block_devices.lock();
        list.iter().find(|(n, _)| n == name).map(|(_, d)| d.clone())
    }

    pub fn get_input(&self, name: &str) -> Option<Arc<dyn InputDevice>> {
        let list = self.input_devices.lock();
        list.iter().find(|(n, _)| n == name).map(|(_, d)| d.clone())
    }

    pub fn list_char(&self) -> Vec<String> {
        let list = self.char_devices.lock();
        list.iter().map(|(n, _)| n.clone()).collect()
    }

    pub fn list_block(&self) -> Vec<String> {
        let list = self.block_devices.lock();
        list.iter().map(|(n, _)| n.clone()).collect()
    }

    pub fn list_input(&self) -> Vec<String> {
        let list = self.input_devices.lock();
        list.iter().map(|(n, _)| n.clone()).collect()
    }
}

// -----------------------------------------------------------------------------
// DevFS file system
// -----------------------------------------------------------------------------

pub struct DevFs;

impl FileSystem for DevFs {
    fn name(&self) -> &'static str {
        "devfs"
    }

    fn open(&self, path: &str, flags: u32) -> Result<Arc<dyn File>> {
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            // Opening root directory.
            return Err(FsError::IsDir);
        }

        // Try to resolve as character device.
        if let Some(dev) = DevRegistry::global().get_char(path) {
            return Ok(Arc::new(CharFile {
                device: dev,
                offset: AtomicU64::new(0),
                writable: true,
                readable: true,
            }));
        }

        // Try block device.
        if let Some(dev) = DevRegistry::global().get_block(path) {
            return Ok(Arc::new(BlockFile {
                device: dev,
                offset: AtomicU64::new(0),
                writable: true,
                readable: true,
            }));
        }

        // Try input device.
        if let Some(dev) = DevRegistry::global().get_input(path) {
            return Ok(Arc::new(CharFile {
                device: Arc::new(InputDeviceNode::new(dev)),
                offset: AtomicU64::new(0),
                writable: false,
                readable: true,
            }));
        }

        // Special hardcoded devices (fallback for builtins).
        match path {
            "null" => Ok(Arc::new(CharFile::new(NullDevice, true, true))),
            "zero" => Ok(Arc::new(CharFile::new(ZeroDevice, true, true))),
            "random" => Ok(Arc::new(CharFile::new(RandomDevice, true, true))),
            "urandom" => Ok(Arc::new(CharFile::new(RandomDevice, true, true))),
            _ => Err(FsError::NotFound),
        }
    }

    fn readdir(&self, path: &str) -> Result<Vec<DirEntry>> {
        let path = path.trim_start_matches('/');
        if !path.is_empty() && path != "/" {
            return Err(FsError::NotFound);
        }

        let mut entries = Vec::new();

        // Add char devices.
        for name in DevRegistry::global().list_char() {
            entries.push(DirEntry {
                name,
                inode: 0,
                is_dir: false,
            });
        }

        // Add block devices.
        for name in DevRegistry::global().list_block() {
            entries.push(DirEntry {
                name,
                inode: 0,
                is_dir: false,
            });
        }

        // Add input devices.
        for name in DevRegistry::global().list_input() {
            entries.push(DirEntry {
                name,
                inode: 0,
                is_dir: false,
            });
        }

        // Hardcoded devices if not already present.
        let builtins = ["null", "zero", "random", "urandom"];
        for name in builtins {
            if !entries.iter().any(|e| e.name == name) {
                entries.push(DirEntry {
                    name: name.to_string(),
                    inode: 0,
                    is_dir: false,
                });
            }
        }

        Ok(entries)
    }

    fn stat(&self, path: &str) -> Result<Stat> {
        let path = path.trim_start_matches('/');
        if path.is_empty() {
            // Root directory.
            return Ok(Stat {
                size: 0,
                is_dir: true,
                is_file: false,
                mode: 0o755,
            });
        }

        // Check if it's a registered device.
        let is_char = DevRegistry::global().get_char(path).is_some();
        let is_block = DevRegistry::global().get_block(path).is_some();
        let is_input = DevRegistry::global().get_input(path).is_some();

        if is_char || is_block || is_input {
            let mode = if is_block { DEFAULT_BLOCK_MODE } else { DEFAULT_MODE };
            return Ok(Stat {
                size: 0,
                is_dir: false,
                is_file: true,
                mode,
            });
        }

        // Check builtins.
        match path {
            "null" | "zero" | "random" | "urandom" => {
                Ok(Stat {
                    size: 0,
                    is_dir: false,
                    is_file: true,
                    mode: DEFAULT_MODE,
                })
            }
            _ => Err(FsError::NotFound),
        }
    }

    fn create(&self, _path: &str) -> Result<()> {
        Err(FsError::PermDenied)
    }

    fn remove(&self, _path: &str) -> Result<()> {
        Err(FsError::PermDenied)
    }

    fn rename(&self, _from: &str, _to: &str) -> Result<()> {
        Err(FsError::PermDenied)
    }

    fn truncate(&self, _path: &str, _size: u64) -> Result<()> {
        Err(FsError::PermDenied)
    }

    fn open_dir(&self, path: &str) -> Result<Arc<dyn File>> {
        // For devfs, we don't support directory file handles.
        Err(FsError::IsDir)
    }
}

// -----------------------------------------------------------------------------
// File implementations
// -----------------------------------------------------------------------------

pub struct CharFile {
    device: Arc<dyn CharDevice>,
    offset: AtomicU64,
    readable: bool,
    writable: bool,
}

impl CharFile {
    pub fn new<D: CharDevice + 'static>(device: D, readable: bool, writable: bool) -> Self {
        Self {
            device: Arc::new(device),
            offset: AtomicU64::new(0),
            readable,
            writable,
        }
    }
}

impl File for CharFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.readable {
            return Err(FsError::PermDenied);
        }
        let off = self.offset.load(Ordering::Relaxed);
        let n = self.device.read(buf, off)?;
        self.offset.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(FsError::PermDenied);
        }
        let off = self.offset.load(Ordering::Relaxed);
        let n = self.device.write(buf, off)?;
        self.offset.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }

    fn seek(&self, pos: i64, whence: u32) -> Result<u64> {
        let cur = self.offset.load(Ordering::Relaxed);
        let new_pos = match whence {
            0 => pos as u64,                 // SEEK_SET
            1 => cur.wrapping_add(pos as u64), // SEEK_CUR
            2 => {
                // SEEK_END: for char devices, we consider size = 0, so end is at 0.
                // But we allow seek to 0 only.
                if pos == 0 {
                    0
                } else {
                    return Err(FsError::InvalidInput);
                }
            }
            _ => return Err(FsError::InvalidInput),
        };
        // For char devices, we generally don't allow seeking far.
        // We'll only allow moving within reasonable bounds (0..1024).
        if new_pos > 1024 {
            return Err(FsError::InvalidInput);
        }
        self.offset.store(new_pos, Ordering::Relaxed);
        Ok(new_pos)
    }

    fn flush(&self) -> Result<()> {
        self.device.flush()
    }

    fn size(&self) -> u64 {
        0 // Character devices have no fixed size.
    }
}

pub struct BlockFile {
    device: Arc<dyn BlockDeviceTrait>,
    offset: AtomicU64,
    readable: bool,
    writable: bool,
}

impl BlockFile {
    pub fn new<D: BlockDeviceTrait + 'static>(device: D, readable: bool, writable: bool) -> Self {
        Self {
            device: Arc::new(device),
            offset: AtomicU64::new(0),
            readable,
            writable,
        }
    }
}

impl File for BlockFile {
    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.readable {
            return Err(FsError::PermDenied);
        }
        let off = self.offset.load(Ordering::Relaxed);
        let sector = off / SECTOR_SIZE as u64;
        let sector_off = (off % SECTOR_SIZE as u64) as usize;

        // We only support aligned reads for now.
        if sector_off != 0 {
            return Err(FsError::InvalidInput);
        }

        let num_sectors = buf.len() / SECTOR_SIZE;
        if num_sectors == 0 {
            return Ok(0);
        }

        let mut bytes_read = 0;
        for i in 0..num_sectors {
            let sector_num = sector + i as u64;
            let chunk = &mut buf[i * SECTOR_SIZE..(i + 1) * SECTOR_SIZE];
            let n = self.device.read_sector(sector_num, chunk)?;
            bytes_read += n;
        }

        self.offset.fetch_add(bytes_read as u64, Ordering::Relaxed);
        Ok(bytes_read)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        if !self.writable {
            return Err(FsError::PermDenied);
        }
        let off = self.offset.load(Ordering::Relaxed);
        let sector = off / SECTOR_SIZE as u64;
        let sector_off = (off % SECTOR_SIZE as u64) as usize;

        if sector_off != 0 {
            return Err(FsError::InvalidInput);
        }

        let num_sectors = buf.len() / SECTOR_SIZE;
        if num_sectors == 0 {
            return Ok(0);
        }

        let mut bytes_written = 0;
        for i in 0..num_sectors {
            let sector_num = sector + i as u64;
            let chunk = &buf[i * SECTOR_SIZE..(i + 1) * SECTOR_SIZE];
            let n = self.device.write_sector(sector_num, chunk)?;
            bytes_written += n;
        }

        self.offset.fetch_add(bytes_written as u64, Ordering::Relaxed);
        Ok(bytes_written)
    }

    fn seek(&self, pos: i64, whence: u32) -> Result<u64> {
        let cur = self.offset.load(Ordering::Relaxed);
        let total_size = self.device.num_sectors() * SECTOR_SIZE as u64;
        let new_pos = match whence {
            0 => pos as u64,
            1 => cur.wrapping_add(pos as u64),
            2 => total_size.wrapping_add(pos as u64),
            _ => return Err(FsError::InvalidInput),
        };
        if new_pos > total_size {
            return Err(FsError::InvalidOffset);
        }
        self.offset.store(new_pos, Ordering::Relaxed);
        Ok(new_pos)
    }

    fn size(&self) -> u64 {
        self.device.num_sectors() * SECTOR_SIZE as u64
    }
}

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------

/// Register built‑in devices with the DevFs.
pub fn init_devfs() {
    let registry = DevRegistry::global();

    // Register built-in character devices.
    registry.register_char("null", Arc::new(NullDevice));
    registry.register_char("zero", Arc::new(ZeroDevice));
    registry.register_char("random", Arc::new(RandomDevice));
    registry.register_char("urandom", Arc::new(RandomDevice));

    // The tty device is set up later after serial and keyboard are initialized.
    // We register a placeholder that will be replaced.
    // In production, we'd have a proper initialization order.
}

/// Set up the TTY device after serial and keyboard drivers are ready.
pub fn setup_tty(serial: Arc<SerialPort>, keyboard: Arc<Mutex<keyboard::KeyboardState>>) {
    let tty = Arc::new(TtyDevice::new(serial, keyboard));
    DevRegistry::global().register_char("tty", tty);
}

/// Register a block device.
pub fn register_block_device(name: &str, device: Arc<dyn BlockDeviceTrait>) {
    DevRegistry::global().register_block(name, device);
}

/// Register an input device.
pub fn register_input_device(name: &str, device: Arc<dyn InputDevice>) {
    DevRegistry::global().register_input(name, device);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::Arc;

    #[test]
    fn test_null_device() {
        let dev = NullDevice;
        let mut buf = [0u8; 10];
        let n = dev.read(&mut buf, 0).unwrap();
        assert_eq!(n, 0);
        let n = dev.write(&[1,2,3], 0).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn test_zero_device() {
        let dev = ZeroDevice;
        let mut buf = [0xff; 10];
        let n = dev.read(&mut buf, 0).unwrap();
        assert_eq!(n, 10);
        for &b in &buf { assert_eq!(b, 0); }
        let n = dev.write(&[1,2,3], 0).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn test_random_device() {
        let dev = RandomDevice;
        let mut buf1 = [0u8; 32];
        let mut buf2 = [0u8; 32];
        dev.read(&mut buf1, 0).unwrap();
        dev.read(&mut buf2, 0).unwrap();
        // Should produce different numbers.
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_tty_device_mock() {
        // We'd need a mock serial and keyboard to test properly.
        // This is a placeholder.
    }

    #[test]
    fn test_registry() {
        let reg = DevRegistry::global();
        reg.register_char("test", Arc::new(NullDevice));
        let dev = reg.get_char("test").unwrap();
        let mut buf = [0u8; 1];
        let n = dev.read(&mut buf, 0).unwrap();
        assert_eq!(n, 0);
    }
}
