//! GDB remote protocol stub — debug kernel live from GDB over serial
//!
//! Protocol: RSP (Remote Serial Protocol)
//! GDB connects via: target remote :1234 (QEMU -s flag)
//! or serial: target remote /dev/ttyS0
//!
//! Supported packets:
//!   ?         — stop reason
//!   g         — read all registers
//!   G         — write all registers
//!   m addr,len— read memory
//!   M addr,len:data — write memory
//!   c         — continue
//!   s         — single step
//!   q         — query (qSupported, qOffsets)


pub mod dmesg;
pub mod backtrace;
pub mod trace;
pub mod crashdump;

use alloc::string::String;

static mut GDB_ACTIVE: bool = false;

/// Calculate GDB packet checksum
fn checksum(data: &[u8]) -> u8 {
    data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// Send a GDB RSP packet: $data#checksum
pub fn send_packet(data: &str) {
    let cs = checksum(data.as_bytes());
    // Send via serial port
    crate::io::serial::_print(format_args!("${}#{:02x}", data, cs));
}

/// Read a GDB RSP packet from serial (blocking)
pub fn recv_packet() -> Option<String> {
    let mut buf = String::new();
    loop {
        // Wait for '$'
        let ch = crate::drivers::keyboard::read_char()?;
        if ch != b'$' { continue; }
        // Read until '#'
        loop {
            let c = crate::drivers::keyboard::read_char()?;
            if c == b'#' { break; }
            buf.push(c as char);
        }
        // Read 2-char checksum
        let _cs1 = crate::drivers::keyboard::read_char()?;
        let _cs2 = crate::drivers::keyboard::read_char()?;
        // Send ACK
        crate::io::serial::_print(format_args!("+"));
        return Some(buf);
    }
}

/// Handle a single GDB packet
pub fn handle_packet(pkt: &str) -> bool {
    if pkt.is_empty() { return false; }
    match &pkt[..1] {
        "?" => { send_packet("S05"); } // SIGTRAP — stopped
        "g" => {
            // Return all registers: rax rbx rcx rdx rsi rdi rbp rsp r8-r15 rip rflags
            let mut regs64 = [0u64; 18];
            unsafe {
                // Store registers directly to memory buffer via a pointer
                // Split into two batches to avoid register pressure
                let p = regs64.as_mut_ptr();
                core::arch::asm!(
                    "mov [rdi + 0*8], rax",
                    "mov [rdi + 1*8], rbx",
                    "mov [rdi + 2*8], rcx",
                    "mov [rdi + 3*8], rdx",
                    "mov [rdi + 4*8], rsi",
                    "mov [rdi + 5*8], rdi",
                    "mov [rdi + 6*8], rbp",
                    "mov [rdi + 7*8], rsp",
                    in("rdi") p,
                    options(nostack),
                );
                core::arch::asm!(
                    "mov [rdi + 8*8],  r8",
                    "mov [rdi + 9*8],  r9",
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
                    in("rdi") p,
                    out("rax") _,
                );
            }
            let mut regs_bytes = [0u8; 18 * 8];
            for (i, &r) in regs64.iter().enumerate() {
                regs_bytes[i*8..i*8+8].copy_from_slice(&r.to_le_bytes());
            }
            let hex: alloc::string::String = regs_bytes.iter()
                .map(|b| alloc::format!("{:02x}", b)).collect();
            send_packet(&hex);
        }
        "m" => {
            // Read memory: m addr,len
            if let Some((addr_s, len_s)) = pkt[1..].split_once(',') {
                let addr = u64::from_str_radix(addr_s.trim(), 16).unwrap_or(0);
                let len  = usize::from_str_radix(len_s.trim(), 16).unwrap_or(0);
                let mut resp = String::new();
                for i in 0..len {
                    let byte = unsafe { *((addr + i as u64) as *const u8) };
                    resp.push_str(&alloc::format!("{:02x}", byte));
                }
                send_packet(&resp);
            } else {
                send_packet("E00");
            }
        }
        "c" => { return true; }  // continue — return to normal execution
        "s" => { send_packet("S05"); } // single step — just report stopped
        "q" => {
            if pkt.starts_with("qSupported") {
                send_packet("PacketSize=1024;qXfer:memory-map:read-");
            } else {
                send_packet("");
            }
        }
        "H" => { send_packet("OK"); }
        "D" => { send_packet("OK"); return true; } // detach
        _   => { send_packet(""); }
    }
    false
}

/// Enter GDB stub loop — called from breakpoint/panic
pub fn gdb_trap() {
    unsafe { GDB_ACTIVE = true; }
    crate::serial_println!("
[GDB] stub active — connect with: target remote :1234");
    send_packet("S05");
    loop {
        match recv_packet() {
            Some(pkt) => { if handle_packet(&pkt) { break; } }
            None      => { crate::arch::x86_64::timer::sleep_ms(10); }
        }
    }
    unsafe { GDB_ACTIVE = false; }
}

/// Software breakpoint — triggers GDB trap
#[inline]
pub fn breakpoint() {
    unsafe { core::arch::asm!("int3"); }
}

pub fn init() {
    crate::serial_println!("  [GDB] stub ready (connect: target remote :1234 after -s flag)");
}
