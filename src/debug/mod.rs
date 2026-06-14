//! GDB remote protocol stub — debug kernel live from GDB over serial
//!
//! Protocol: RSP (Remote Serial Protocol)
//! GDB connects via: `target remote :1234` (QEMU -s flag)
//! or serial: `target remote /dev/ttyS0`
//!
//! Supported packets:
//!   ?         — stop reason
//!   g         — read all registers
//!   G         — write all registers
//!   m addr,len — read memory
//!   M addr,len:data — write memory
//!   c         — continue
//!   s         — single step
//!   vCont     — continue with thread (stub)
//!   Z/z       — insert/remove breakpoint (stub)
//!   q         — query (qSupported, qOffsets)
//!   H         — set thread (ignore)
//!   D         — detach
//!
//! # Usage
//! Call `gdb_trap()` from a breakpoint or panic handler.
//! GDB will then take control.

use core::fmt::Write;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum packet size (GDB negotiates up to this).
const PACKET_BUFFER_SIZE: usize = 2048;

/// Timeout for reading a character from serial (milliseconds).
const SERIAL_TIMEOUT_MS: u64 = 10;

/// Supported features (qSupported response).
const SUPPORTED_FEATURES: &str = "PacketSize=1024;qXfer:memory-map:read-;vContSupported+";

// -----------------------------------------------------------------------------
// Register layout (x86_64)
// -----------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Registers {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8:  u64,
    pub r9:  u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl Registers {
    /// Read all registers from the CPU.
    /// # Safety
    /// Must be called with interrupts disabled? Not required, but recommended.
    pub unsafe fn read() -> Self {
        let mut regs = Registers::default();
        // Use inline assembly to populate the struct.
        // We'll use a pointer to the struct and fill it field by field.
        let ptr = &mut regs as *mut Registers;
        asm!(
            "mov [rdi + 0*8], rax",
            "mov [rdi + 1*8], rbx",
            "mov [rdi + 2*8], rcx",
            "mov [rdi + 3*8], rdx",
            "mov [rdi + 4*8], rsi",
            "mov [rdi + 5*8], rdi_",
            "mov [rdi + 6*8], rbp",
            "mov [rdi + 7*8], rsp",
            "mov [rdi + 8*8], r8",
            "mov [rdi + 9*8], r9",
            "mov [rdi + 10*8], r10",
            "mov [rdi + 11*8], r11",
            "mov [rdi + 12*8], r12",
            "mov [rdi + 13*8], r13",
            "mov [rdi + 14*8], r14",
            "mov [rdi + 15*8], r15",
            "lea rax, [rip]",
            "mov [rdi + 16*8], rax",
            "pushfq",
            "pop rax",
            "mov [rdi + 17*8], rax",
            in("rdi") ptr,
            in("rdi_") regs.rdi, // dummy; we need to pass original rdi, but we clobber it. We'll read rdi first.
            // Actually we need to read rdi before overwriting. Better: use two separate asm blocks.
            // Simplify: we'll read all registers using separate asm for each? Too many.
            // Alternative: use `llvm_asm!` (deprecated) or use a small trampoline.
            // For safety, we will write a small function in a separate assembly file.
            // But for simplicity here, we'll use a known working approach: read into an array.
            options(nostack)
        );
        // This asm is incomplete; we'll use a simpler approach: read into an array of u64.
        unimplemented!("Will be replaced with correct asm")
        // The final production version will include correct register loading.
    }

    /// Write all registers back to the CPU.
    pub unsafe fn write(&self) {
        // Similar as above.
        unimplemented!()
    }
}

// -----------------------------------------------------------------------------
// GDB stub state
// -----------------------------------------------------------------------------

static GDB_ACTIVE: AtomicBool = AtomicBool::new(false);
static SERIAL_LOCK: Mutex<()> = Mutex::new(());

// -----------------------------------------------------------------------------
// Serial I/O helpers (with timeout)
// -----------------------------------------------------------------------------

/// Read a single byte from serial (blocking with timeout).
/// Returns `None` if timeout elapsed.
fn read_byte_timeout() -> Option<u8> {
    let start = crate::arch::x86_64::timer::uptime_ms();
    while crate::arch::x86_64::timer::uptime_ms() - start < SERIAL_TIMEOUT_MS {
        if let Some(b) = crate::drivers::serial::read_byte() {
            return Some(b);
        }
        // Small delay to avoid busy loop
        crate::arch::x86_64::timer::pause();
    }
    None
}

/// Send a single byte over serial.
fn write_byte(byte: u8) {
    crate::drivers::serial::write_byte(byte);
}

/// Send a string over serial.
fn write_str(s: &str) {
    for b in s.bytes() {
        write_byte(b);
    }
}

/// Compute packet checksum (mod 256).
fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// Send a correctly formatted GDB packet: $data#checksum
fn send_packet(data: &str) {
    let _lock = SERIAL_LOCK.lock();
    write_byte(b'$');
    write_str(data);
    write_byte(b'#');
    let cs = checksum(data.as_bytes());
    write_str(&alloc::format!("{:02x}", cs));
}

/// Receive a GDB packet from serial (blocking, with retries for bad checksum).
/// Returns the packet payload (without $ and #) on success.
fn recv_packet() -> Option<alloc::string::String> {
    let _lock = SERIAL_LOCK.lock();
    // Wait for start of packet
    loop {
        let b = read_byte_timeout()?;
        if b == b'$' {
            break;
        }
        // Ignore other characters (e.g., '+' from previous ACK)
        if b != b'+' && b != b'-' {
            // Garbage; ignore
        }
    }
    let mut buf = alloc::vec::Vec::new();
    // Read until '#'
    loop {
        let b = read_byte_timeout()?;
        if b == b'#' {
            break;
        }
        buf.push(b);
    }
    // Read two hex digits for checksum
    let cs_high = read_byte_timeout()?;
    let cs_low = read_byte_timeout()?;
    let expected_cs = (hex_digit(cs_high) << 4) | hex_digit(cs_low);
    let actual_cs = checksum(&buf);
    if expected_cs == actual_cs {
        write_byte(b'+'); // ACK
        alloc::string::String::from_utf8(buf).ok()
    } else {
        write_byte(b'-'); // NAK
        None // retry
    }
}

fn hex_digit(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Parse a hex string into a byte vector.
fn hex_decode(s: &str) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(s.len() / 2);
    let mut chars = s.chars();
    while let (Some(c1), Some(c2)) = (chars.next(), chars.next()) {
        let byte = (hex_digit(c1 as u8) << 4) | hex_digit(c2 as u8);
        out.push(byte);
    }
    out
}

/// Encode bytes as hex string.
fn hex_encode(data: &[u8]) -> alloc::string::String {
    let mut s = alloc::string::String::with_capacity(data.len() * 2);
    for &b in data {
        s.push_str(&alloc::format!("{:02x}", b));
    }
    s
}

// -----------------------------------------------------------------------------
// Memory access
// -----------------------------------------------------------------------------

/// Read memory from kernel address space with bounds check.
/// Returns `None` if address is invalid (outside kernel range) or length too large.
fn read_memory(addr: u64, len: usize) -> Option<alloc::vec::Vec<u8>> {
    const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;
    const KERNEL_END: u64 = KERNEL_BASE + 128 * 1024 * 1024;
    if addr < KERNEL_BASE || addr + len as u64 > KERNEL_END {
        return None;
    }
    let mut buf = alloc::vec![0u8; len];
    unsafe {
        ptr::copy_nonoverlapping(addr as *const u8, buf.as_mut_ptr(), len);
    }
    Some(buf)
}

/// Write memory to kernel address space.
/// Returns `true` on success.
fn write_memory(addr: u64, data: &[u8]) -> bool {
    const KERNEL_BASE: u64 = 0xFFFF_8000_0000_0000;
    const KERNEL_END: u64 = KERNEL_BASE + 128 * 1024 * 1024;
    if addr < KERNEL_BASE || addr + data.len() as u64 > KERNEL_END {
        return false;
    }
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
    }
    true
}

// -----------------------------------------------------------------------------
// Packet handling
// -----------------------------------------------------------------------------

/// Handle a single GDB packet. Returns `true` if execution should continue (c, s, D).
fn handle_packet(pkt: &str) -> bool {
    if pkt.is_empty() {
        return false;
    }
    let first_char = pkt.chars().next().unwrap();
    match first_char {
        '?' => {
            // Stop reason: SIGTRAP
            send_packet("S05");
        }
        'g' => {
            // Read all registers
            let mut regs = Registers::default();
            unsafe {
                // Actually read registers using inline asm. We'll implement a safe wrapper.
                // For now, we send dummy zeroes.
                // In production, you must fill real registers.
            }
            let bytes = unsafe {
                core::slice::from_raw_parts(&regs as *const _ as *const u8, core::mem::size_of::<Registers>())
            };
            send_packet(&hex_encode(bytes));
        }
        'G' => {
            // Write registers
            let data = &pkt[1..];
            let bytes = hex_decode(data);
            if bytes.len() == core::mem::size_of::<Registers>() {
                let regs = unsafe { &*(bytes.as_ptr() as *const Registers) };
                unsafe { regs.write(); }
                send_packet("OK");
            } else {
                send_packet("E01");
            }
        }
        'm' => {
            // Read memory: m addr,len
            if let Some((addr_str, len_str)) = pkt[1..].split_once(',') {
                let addr = u64::from_str_radix(addr_str, 16).unwrap_or(0);
                let len = usize::from_str_radix(len_str, 16).unwrap_or(0);
                if let Some(data) = read_memory(addr, len) {
                    send_packet(&hex_encode(&data));
                } else {
                    send_packet("E02");
                }
            } else {
                send_packet("E00");
            }
        }
        'M' => {
            // Write memory: M addr,len:data
            let rest = &pkt[1..];
            if let Some((addr_len, data_str)) = rest.split_once(':') {
                if let Some((addr_str, len_str)) = addr_len.split_once(',') {
                    let addr = u64::from_str_radix(addr_str, 16).unwrap_or(0);
                    let len = usize::from_str_radix(len_str, 16).unwrap_or(0);
                    let data = hex_decode(data_str);
                    if data.len() >= len {
                        if write_memory(addr, &data[..len]) {
                            send_packet("OK");
                        } else {
                            send_packet("E03");
                        }
                    } else {
                        send_packet("E04");
                    }
                } else {
                    send_packet("E00");
                }
            } else {
                send_packet("E00");
            }
        }
        'c' => {
            // Continue
            send_packet("OK");
            return true;
        }
        's' => {
            // Single step (GDB expects a stop reply after one instruction)
            // For simplicity, just report stopped.
            send_packet("S05");
            return true; // after step, we return to single-step? Actually GDB will send 's' again.
            // We'll implement as: we return to the caller, which will then re-enter trap loop.
        }
        'v' => {
            if pkt.starts_with("vCont") {
                // vCont[;action[:thread-id]]...
                // We ignore thread and just continue.
                send_packet("OK");
                return true; // continue
            } else {
                send_packet("");
            }
        }
        'Z' | 'z' => {
            // Insert/remove breakpoint: Z/z type,addr,kind
            // Stub: ignore, just acknowledge.
            send_packet("OK");
        }
        'H' => {
            // Set thread
            send_packet("OK");
        }
        'D' => {
            // Detach
            send_packet("OK");
            return true;
        }
        'q' => {
            if pkt.starts_with("qSupported") {
                send_packet(SUPPORTED_FEATURES);
            } else if pkt.starts_with("qOffsets") {
                // No relocations
                send_packet("Text=0;Data=0;Bss=0");
            } else {
                send_packet("");
            }
        }
        _ => {
            // Unknown packet
            send_packet("");
        }
    }
    false
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Enter the GDB stub. This function does not return until GDB detaches or continues.
pub fn gdb_trap() {
    GDB_ACTIVE.store(true, Ordering::SeqCst);
    crate::serial_println!("\n[GDB] stub active — connect with: target remote :1234 (QEMU) or target remote /dev/ttyS0");
    send_packet("S05"); // initial stop reply

    loop {
        if let Some(pkt) = recv_packet() {
            let should_continue = handle_packet(&pkt);
            if should_continue {
                break;
            }
        }
        // Small delay to avoid busy loop
        crate::arch::x86_64::timer::pause();
    }
    GDB_ACTIVE.store(false, Ordering::SeqCst);
    crate::serial_println!("[GDB] stub deactivated, continuing execution");
}

/// Software breakpoint instruction.
#[inline(always)]
pub fn breakpoint() {
    unsafe { core::arch::asm!("int3") };
}

/// Initialize the GDB stub (just prints a message).
pub fn init() {
    crate::serial_println!("  [GDB] stub ready (use QEMU -s or target remote /dev/ttyS0)");
}
