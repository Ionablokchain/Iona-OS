//! /dev filesystem — device files
//! /dev/null, /dev/zero, /dev/random, /dev/sda, /dev/tty
use alloc::{string::String, vec::Vec};
use crate::fs::vfs::{FileSystem, Stat, FsError, Result};

pub struct DevFs;

impl FileSystem for DevFs {
    fn name(&self) -> &'static str { "devfs" }

    fn read(&self, path: &str, buf: &mut [u8], _offset: u64) -> Result<usize> {
        match path {
            "/null" | "null"   => Ok(0),
            "/zero" | "zero"   => { buf.fill(0); Ok(buf.len()) }
            "/random" | "random" => {
                // Pseudo-random from TSC
                let tsc: u64;
                unsafe { core::arch::asm!("rdtsc", out("rax") tsc, options(nostack)); }
                for (i, b) in buf.iter_mut().enumerate() {
                    *b = ((tsc.wrapping_add(i as u64).wrapping_mul(6364136223846793005)) >> 32) as u8;
                }
                Ok(buf.len())
            }
            "/tty" | "tty"     => {
                // Read from keyboard
                if let Some(ch) = crate::drivers::keyboard::read_char() {
                    buf[0] = ch; Ok(1)
                } else { Ok(0) }
            }
            "/sda" | "sda"     => {
                // Read from virtio-blk (raw block device)
                if buf.len() >= 512 {
                    crate::drivers::virtio::blk::read_sectors(0, 1, &mut buf[..512]);
                    Ok(512)
                } else { Ok(0) }
            }
            _ => Err(FsError::NotFound),
        }
    }

    fn write(&self, path: &str, buf: &[u8], _offset: u64) -> Result<usize> {
        match path {
            "/null" | "null" => Ok(buf.len()),
            "/tty"  | "tty"  => {
                if let Ok(s) = core::str::from_utf8(buf) {
                    crate::io::serial::_print(format_args!("{}", s));
                }
                Ok(buf.len())
            }
            _ => Err(FsError::PermDenied),
        }
    }

    fn readdir(&self, _: &str) -> Result<Vec<String>> {
        Ok(alloc::vec!["null".into(), "zero".into(), "random".into(), "tty".into(), "sda".into(), "fb0".into()])
    }

    fn stat(&self, path: &str) -> Result<Stat> {
        let is_dir = path == "/" || path.is_empty();
        Ok(Stat { size: 0, is_dir, is_file: !is_dir, mode: 0o666 })
    }

    fn create(&self, _: &str) -> Result<()> { Err(FsError::PermDenied) }
    fn remove(&self, _: &str) -> Result<()> { Err(FsError::PermDenied) }
}
