//! Kernel ring buffer — dmesg equivalent
//! Accessible from userspace via /proc/kmsg syscall
use alloc::{collections::VecDeque, string::String};
use spin::{Lazy, Mutex};

const RING_CAPACITY: usize = 4096; // messages

pub struct KernelLog {
    ring:    VecDeque<String>,
    dropped: u64,
}

impl KernelLog {
    fn new() -> Self { Self { ring: VecDeque::new(), dropped: 0 } }

    fn push(&mut self, msg: String) {
        if self.ring.len() >= RING_CAPACITY {
            self.ring.pop_front();
            self.dropped += 1;
        }
        self.ring.push_back(msg);
    }

    fn drain(&mut self) -> alloc::vec::Vec<String> {
        self.ring.drain(..).collect()
    }

    fn tail(&self, n: usize) -> alloc::vec::Vec<&str> {
        let skip = self.ring.len().saturating_sub(n);
        self.ring.iter().skip(skip).map(|s| s.as_str()).collect()
    }
}

static KLOG: Lazy<Mutex<KernelLog>> = Lazy::new(|| Mutex::new(KernelLog::new()));

pub fn klog(msg: &str) {
    let uptime = crate::arch::x86_64::timer::uptime_ms();
    let entry  = alloc::format!("[{:8}.{:03}] {}", uptime/1000, uptime%1000, msg);
    // Print to serial
    crate::io::serial::_print(format_args!("{}
", entry));
    // Store in ring buffer
    KLOG.lock().push(entry);
}

pub fn read_kmsg(buf: &mut [u8]) -> usize {
    let log    = KLOG.lock();
    let msgs   = log.tail(100);
    let mut pos = 0;
    for msg in msgs {
        let bytes = msg.as_bytes();
        let n     = bytes.len().min(buf.len() - pos);
        if n == 0 { break; }
        buf[pos..pos+n].copy_from_slice(&bytes[..n]);
        pos += n;
        if pos < buf.len() { buf[pos] = b'\n'; pos += 1; }
    }
    pos
}

/// Expose for /proc/kmsg
pub fn kmsg_size() -> usize { KLOG.lock().ring.iter().map(|s| s.len() + 1).sum() }
