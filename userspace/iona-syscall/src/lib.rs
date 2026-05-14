//! IONA OS Syscall Library — înlocuiește tokio/std pentru userspace
//!
//! Aceasta este biblioteca de syscalls pentru procesele userspace care rulează
//! pe IONA OS Kernel. Înlocuiește:
//!   - tokio  → kernel scheduler + sys_sleep (37) + sys_yield (24)
//!   - std::net → sys_tcp_connect (310) + sys_tcp_send (311) + sys_tcp_recv (312)
//!   - std::fs → iona_fs_read (302) + iona_fs_write (303)
//!   - println! → sys_write (1) pe fd=1
//!
//! Toate syscall-urile folosesc instrucțiunea SYSCALL (ring 3 → ring 0).
//! Convenție: rax=nr, rdi=a1, rsi=a2, rdx=a3, r10=a4, r8=a5

#![no_std]
#![feature(naked_functions)]
#![allow(unused_parens)]

extern crate alloc;

use alloc::vec::Vec;
use alloc::string::String;

// ── Simple bump allocator for userspace no_std binaries ──────────────────────

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicUsize, Ordering};

const HEAP_SIZE: usize = 1024 * 1024; // 1 MB heap

#[repr(C, align(16))]
struct BumpHeap {
    data: [u8; HEAP_SIZE],
}

static mut HEAP: BumpHeap = BumpHeap { data: [0; HEAP_SIZE] };
static HEAP_POS: AtomicUsize = AtomicUsize::new(0);

pub struct IonaBumpAlloc;

unsafe impl GlobalAlloc for IonaBumpAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align = layout.align();
        let size = layout.size();
        loop {
            let pos = HEAP_POS.load(Ordering::Relaxed);
            let aligned = (pos + align - 1) & !(align - 1);
            let new_pos = aligned + size;
            if new_pos > HEAP_SIZE {
                return core::ptr::null_mut();
            }
            if HEAP_POS.compare_exchange(pos, new_pos, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                return unsafe { HEAP.data.as_mut_ptr().add(aligned) };
            }
        }
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Bump allocator: no deallocation
    }
}

/// Use this in your main.rs: `#[global_allocator] static ALLOC: iona_syscall::IonaBumpAlloc = iona_syscall::IonaBumpAlloc;`

// ── Syscall numbers ───────────────────────────────────────────────────────────
pub mod nr {
    pub const READ:          u64 = 0;
    pub const WRITE:         u64 = 1;
    pub const GETPID:        u64 = 20;
    pub const YIELD:         u64 = 24;
    pub const NANOSLEEP:     u64 = 35;
    pub const EXIT:          u64 = 60;
    pub const KILL:          u64 = 62;

    // IONA-specific
    pub const WASM_SPAWN:    u64 = 300;
    pub const IPC_SEND:      u64 = 301;
    pub const FS_READ:       u64 = 302;
    pub const FS_WRITE:      u64 = 303;
    pub const GET_UPTIME:    u64 = 304;
    pub const LOG:           u64 = 305;

    pub const GET_TID:       u64 = 306;
    pub const IPC_RECV:      u64 = 307;
    pub const WASM_KILL:     u64 = 308;
    pub const WASM_STATUS:   u64 = 309;

    // Network syscalls
    pub const TCP_CONNECT:   u64 = 310;
    pub const TCP_SEND:      u64 = 311;
    pub const TCP_RECV:      u64 = 312;
    pub const TCP_CLOSE:     u64 = 313;
    pub const TCP_LISTEN:    u64 = 314;
    pub const TCP_ACCEPT:    u64 = 315;
    pub const UDP_BIND:      u64 = 316;
    pub const UDP_SEND:      u64 = 317;
    pub const UDP_RECV:      u64 = 318;

    // Process
    pub const SPAWN_ELF:     u64 = 320;
    pub const WAIT_PID:      u64 = 321;
    pub const GET_CHAIN_RPC: u64 = 322;

    // Extended
    pub const FS_LIST:       u64 = 330;
    pub const FS_STAT:       u64 = 331;
    pub const PROC_LIST:     u64 = 332;
    pub const MEM_STATS:     u64 = 333;
    pub const NET_GET_IP:    u64 = 334;
    pub const READ_KMSG:     u64 = 335;
    pub const GET_ARGV:      u64 = 336;
    pub const SWAP_STATS:    u64 = 337;

    // GUI syscalls
    pub const GUI_CREATE_WINDOW:  u64 = 350;
    pub const GUI_DESTROY_WINDOW: u64 = 351;
    pub const GUI_DRAW_PIXELS:    u64 = 352;
    pub const GUI_SET_TITLE:      u64 = 353;
    pub const GUI_POLL_EVENT:     u64 = 354;
    pub const GUI_FLUSH:          u64 = 355;
}

// ── Raw syscall wrapper ───────────────────────────────────────────────────────

#[inline(always)]
pub unsafe fn syscall0(nr: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall1(nr: u64, a1: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall2(nr: u64, a1: u64, a2: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2, in("rdx") a3,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall4(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall5(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    ret
}

#[inline(always)]
pub unsafe fn syscall6(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> u64 {
    let ret: u64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr => ret,
        in("rdi") a1, in("rsi") a2, in("rdx") a3, in("r10") a4, in("r8") a5, in("r9") a6,
        lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    ret
}

// ── Wrapped syscalls — API idiomatică Rust ────────────────────────────────────

/// Scrie pe stdout (fd=1) sau stderr (fd=2)
pub fn write(fd: u64, data: &[u8]) -> usize {
    unsafe {
        syscall3(nr::WRITE, fd, data.as_ptr() as u64, data.len() as u64) as usize
    }
}

/// Citește de la stdin (fd=0) — tastatura
pub fn read(fd: u64, buf: &mut [u8]) -> usize {
    unsafe {
        syscall3(nr::READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64) as usize
    }
}

/// Cedează CPU-ul voluntar (cooperative yield)
pub fn yield_cpu() {
    unsafe { syscall0(nr::YIELD); }
}

/// Sleep în milisecunde
pub fn sleep_ms(ms: u64) {
    unsafe { syscall1(nr::NANOSLEEP, ms); }
}

/// Termină procesul
pub fn exit(code: i32) -> ! {
    unsafe { syscall1(nr::EXIT, code as u64); }
    loop {}
}

/// Uptime în milisecunde de la boot
pub fn uptime_ms() -> u64 {
    unsafe { syscall0(nr::GET_UPTIME) }
}

/// TID-ul procesului curent
pub fn get_tid() -> u64 {
    unsafe { syscall0(nr::GET_TID) }
}

/// Log pe serial al kernelului (vizibil în QEMU output)
pub fn klog(msg: &str) {
    unsafe {
        syscall2(nr::LOG, msg.as_ptr() as u64, msg.len() as u64);
    }
}

// ── IONAFS ───────────────────────────────────────────────────────────────────

pub fn fs_read(path: &str) -> Option<Vec<u8>> {
    let mut buf = alloc::vec![0u8; 1024 * 1024]; // max 1MB
    let n = unsafe {
        syscall3(nr::FS_READ, path.as_ptr() as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
    };
    if n == u64::MAX { None } else { buf.truncate(n as usize); Some(buf) }
}

pub fn fs_write(path: &str, data: &[u8]) {
    let path_cstr = alloc::format!("{}\0", path);
    unsafe {
        syscall3(nr::FS_WRITE,
            path_cstr.as_ptr() as u64,
            data.as_ptr() as u64,
            data.len() as u64);
    }
}

// ── IPC ───────────────────────────────────────────────────────────────────────

pub fn ipc_send(to_tid: u64, data: &[u8]) {
    unsafe {
        syscall3(nr::IPC_SEND, to_tid, data.as_ptr() as u64, data.len() as u64);
    }
}

pub fn ipc_recv() -> Option<Vec<u8>> {
    let mut buf = alloc::vec![0u8; 65536];
    let n = unsafe {
        syscall2(nr::IPC_RECV, buf.as_mut_ptr() as u64, buf.len() as u64)
    };
    if n == 0 { None } else { buf.truncate(n as usize); Some(buf) }
}

// ── WASM ─────────────────────────────────────────────────────────────────────

pub fn wasm_spawn(bytecode: &[u8]) -> u64 {
    unsafe {
        syscall2(nr::WASM_SPAWN, bytecode.as_ptr() as u64, bytecode.len() as u64)
    }
}

pub fn wasm_kill(tid: u64) -> bool {
    unsafe { syscall1(nr::WASM_KILL, tid) == 0 }
}

// ── Network TCP ───────────────────────────────────────────────────────────────

#[repr(C)]
pub struct SockAddr {
    pub ip:   [u8; 4],
    pub port: u16,
}

/// Deschide o conexiune TCP. Returnează socket fd sau u64::MAX la eroare.
pub fn tcp_connect(ip: [u8; 4], port: u16) -> u64 {
    let addr = SockAddr { ip, port };
    unsafe {
        syscall2(nr::TCP_CONNECT,
            &addr as *const SockAddr as u64,
            core::mem::size_of::<SockAddr>() as u64)
    }
}

/// Trimite date pe un socket TCP
pub fn tcp_send(fd: u64, data: &[u8]) -> usize {
    unsafe {
        syscall3(nr::TCP_SEND, fd, data.as_ptr() as u64, data.len() as u64) as usize
    }
}

/// Primește date de pe un socket TCP (non-blocking: returnează 0 dacă nu e nimic)
pub fn tcp_recv(fd: u64, buf: &mut [u8]) -> usize {
    unsafe {
        syscall3(nr::TCP_RECV, fd, buf.as_mut_ptr() as u64, buf.len() as u64) as usize
    }
}

/// Închide un socket TCP
pub fn tcp_close(fd: u64) {
    unsafe { syscall1(nr::TCP_CLOSE, fd); }
}

/// Ascultă pe un port TCP (server). Returnează fd sau u64::MAX.
pub fn tcp_listen(port: u16) -> u64 {
    unsafe { syscall1(nr::TCP_LISTEN, port as u64) }
}

/// Acceptă o conexiune pe un server socket. Returnează fd sau u64::MAX.
pub fn tcp_accept(server_fd: u64) -> u64 {
    unsafe { syscall1(nr::TCP_ACCEPT, server_fd) }
}

/// Citește URL-ul chain RPC din configurația kernelului
pub fn get_chain_rpc_url(buf: &mut [u8]) -> usize {
    unsafe {
        syscall2(nr::GET_CHAIN_RPC, buf.as_mut_ptr() as u64, buf.len() as u64) as usize
    }
}

// ── Convenience output ────────────────────────────────────────────────────────

pub fn println(s: &str) { write(1, s.as_bytes()); write(1, b"\n"); }
pub fn print(s: &str)   { write(1, s.as_bytes()); }
pub fn eprintln(s: &str) { write(2, s.as_bytes()); write(2, b"\n"); }
pub fn write_stdout(data: &[u8]) { write(1, data); }
pub fn read_stdin(buf: &mut [u8]) -> usize { read(0, buf) }

// ── Macros ────────────────────────────────────────────────────────────────────

#[macro_export]
macro_rules! sys_println {
    () => { $crate::write(1, b"\n"); };
    ($($arg:tt)*) => {{
        use alloc::format;
        let s = format!($($arg)*) + "\n";
        $crate::write(1, s.as_bytes());
    }};
}

#[macro_export]
macro_rules! sys_print {
    ($($arg:tt)*) => {{
        use alloc::format;
        let s = format!($($arg)*);
        $crate::write(1, s.as_bytes());
    }};
}

// ── Entry point runtime ───────────────────────────────────────────────────────

/// Entry point pentru procese userspace IONA OS.
/// Apelat de _start, apelează main(), apoi sys_exit.
pub fn run_main<F: FnOnce() -> i32>(main: F) -> ! {
    let code = main();
    exit(code)
}

pub fn udp_bind(port: u16) -> u64 {
    unsafe { syscall1(nr::UDP_BIND, port as u64) }
}

pub fn udp_sendto(fd: u64, data: &[u8], ip: [u8; 4], port: u16) -> usize {
    let _ = port;
    unsafe {
        syscall4(nr::UDP_SEND, fd, data.as_ptr() as u64, data.len() as u64,
            (ip[0] as u64) << 24 | (ip[1] as u64) << 16 | (ip[2] as u64) << 8 | ip[3] as u64) as usize
    }
}

pub fn udp_recvfrom(fd: u64, buf: &mut [u8]) -> (usize, [u8; 4], u16) {
    let mut addr = [0u8; 6];
    let n = unsafe {
        syscall4(nr::UDP_RECV, fd, buf.as_mut_ptr() as u64, buf.len() as u64,
            addr.as_mut_ptr() as u64) as usize
    };
    let ip = [addr[0], addr[1], addr[2], addr[3]];
    let port = u16::from_be_bytes([addr[4], addr[5]]);
    (n, ip, port)
}

// ── GUI functions ─────────────────────────────────────────────────────────────

/// Create a native window, returns window ID
pub fn gui_create_window(title: &str, x: i32, y: i32, w: u32, h: u32) -> u32 {
    unsafe {
        syscall6(nr::GUI_CREATE_WINDOW,
            title.as_ptr() as u64, title.len() as u64,
            x as u64, y as u64, w as u64, h as u64) as u32
    }
}

/// Destroy window
pub fn gui_destroy_window(wid: u32) {
    unsafe { syscall1(nr::GUI_DESTROY_WINDOW, wid as u64); }
}

/// Draw pixel buffer into window at (x, y) with size (w × h)
/// pixels: ARGB 32bpp, row-major
pub fn gui_draw_pixels(wid: u32, x: u16, y: u16, w: u16, h: u16, pixels: &[u32]) {
    unsafe {
        syscall6(nr::GUI_DRAW_PIXELS,
            wid as u64, x as u64, y as u64, w as u64, h as u64,
            pixels.as_ptr() as u64);
    }
}

/// Update window title
pub fn gui_set_title(wid: u32, title: &str) {
    unsafe { syscall3(nr::GUI_SET_TITLE, wid as u64, title.as_ptr() as u64, title.len() as u64); }
}

/// Poll next GUI event for window. Returns bytes written (0 = no event)
pub fn gui_poll_event(wid: u32, buf: &mut [u8]) -> usize {
    unsafe {
        syscall3(nr::GUI_POLL_EVENT, wid as u64, buf.as_mut_ptr() as u64, buf.len() as u64) as usize
    }
}

/// Flush window (mark as needing redraw)
pub fn gui_flush(wid: u32) {
    unsafe { syscall1(nr::GUI_FLUSH, wid as u64); }
}

/// Fill window with solid color
pub fn gui_fill(wid: u32, w: u16, h: u16, r: u8, g: u8, b: u8) {
    let pixel = ((r as u32) << 16) | ((g as u32) << 8) | b as u32;
    let pixels = alloc::vec![pixel; (w as usize) * (h as usize)];
    gui_draw_pixels(wid, 0, 0, w, h, &pixels);
    gui_flush(wid);
}

// ── Filesystem extended ──────────────────────────────────────────────────────

pub fn fs_list(path: &str) -> Vec<String> {
    let mut buf = alloc::vec![0u8; 65536];
    let n = unsafe {
        syscall3(nr::FS_LIST, path.as_ptr() as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
    } as usize;
    if n == 0 || n == u64::MAX as usize { return Vec::new(); }
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
    text.split('\n').filter(|s| !s.is_empty()).map(String::from).collect()
}

pub fn fs_stat(path: &str) -> Option<String> {
    let mut buf = alloc::vec![0u8; 256];
    let n = unsafe {
        syscall3(nr::FS_STAT, path.as_ptr() as u64, buf.as_mut_ptr() as u64, buf.len() as u64)
    } as usize;
    if n == 0 || n == u64::MAX as usize { return None; }
    Some(String::from(core::str::from_utf8(&buf[..n]).unwrap_or("0")))
}

// ── Process management ────────────────────────────────────────────────────────

pub struct ProcInfo {
    pub pid:     u64,
    pub name:    String,
    pub state:   String,
    pub cpu_pct: f64,
}

pub fn proc_list() -> Vec<ProcInfo> {
    let mut buf = alloc::vec![0u8; 65536];
    let n = unsafe {
        syscall2(nr::PROC_LIST, buf.as_mut_ptr() as u64, buf.len() as u64)
    } as usize;
    if n == 0 || n == u64::MAX as usize { return Vec::new(); }
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
    let mut result = Vec::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.splitn(4, '\t').collect();
        if parts.len() >= 3 {
            result.push(ProcInfo {
                pid: parts[0].parse().unwrap_or(0),
                name: String::from(parts[1]),
                state: String::from(parts[2]),
                cpu_pct: if parts.len() > 3 { parts[3].parse().unwrap_or(0.0) } else { 0.0 },
            });
        }
    }
    result
}

pub fn mem_stats() -> (u64, u64) {
    let mut buf = [0u64; 2];
    unsafe { syscall2(nr::MEM_STATS, buf.as_mut_ptr() as u64, 16); }
    (buf[0], buf[1])
}

pub fn net_get_ip() -> String {
    let mut buf = alloc::vec![0u8; 64];
    let n = unsafe {
        syscall2(nr::NET_GET_IP, buf.as_mut_ptr() as u64, buf.len() as u64)
    } as usize;
    if n == 0 || n == u64::MAX as usize { return String::from("0.0.0.0"); }
    String::from(core::str::from_utf8(&buf[..n]).unwrap_or("0.0.0.0"))
}

pub fn read_kmsg(buf: &mut [u8]) -> usize {
    unsafe { syscall2(nr::READ_KMSG, buf.as_mut_ptr() as u64, buf.len() as u64) as usize }
}

pub fn argv() -> Vec<String> {
    let mut buf = alloc::vec![0u8; 4096];
    let n = unsafe {
        syscall2(nr::GET_ARGV, buf.as_mut_ptr() as u64, buf.len() as u64)
    } as usize;
    if n == 0 || n == u64::MAX as usize { return Vec::new(); }
    let text = core::str::from_utf8(&buf[..n]).unwrap_or("");
    text.split('\0').filter(|s| !s.is_empty()).map(String::from).collect()
}

pub fn kill(pid: u64, sig: u8) {
    unsafe { syscall2(nr::KILL, pid, sig as u64); }
}

// ── Process spawn / wait ─────────────────────────────────────────────────────

/// Spawn an ELF binary from IONAFS path.
/// Returns process ID on success, or u64::MAX on error.
pub fn spawn_elf(path: &str, args: &[&str]) -> Result<u64, &'static str> {
    // Build args as null-terminated list
    let mut args_buf: alloc::vec::Vec<u64> = args.iter()
        .map(|a| a.as_ptr() as u64)
        .collect();
    let pid = unsafe {
        syscall3(
            nr::SPAWN_ELF,
            path.as_ptr() as u64,
            args_buf.as_ptr() as u64,
            args.len() as u64,
        )
    };
    if pid == u64::MAX { Err("spawn_elf: exec failed") } else { Ok(pid) }
}

/// Wait for a process to exit. Returns exit code.
pub fn waitpid(pid: u64) -> u64 {
    unsafe { syscall1(nr::WAIT_PID, pid) }
}

/// Swap memory statistics: returns (total_pages, used_pages)
pub fn swap_stats() -> (u64, u64) {
    let mut buf = [0u64; 2];
    unsafe { syscall2(nr::SWAP_STATS, buf.as_mut_ptr() as u64, 16); }
    (buf[0], buf[1])
}
