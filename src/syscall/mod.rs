//! Syscall interface — SYSCALL/SYSRET via MSR (x86_64 fast path)
//!
//! Convenție argumente:
//!   rax = syscall number
//!   rdi = arg1,  rsi = arg2,  rdx = arg3
//!   r10 = arg4,  r8  = arg5,  r9  = arg6
//!   rcx = rip de return (salvat de hw)
//!   r11 = rflags (salvat de hw)

pub mod user_access;
use alloc::string::String;

use x86_64::registers::model_specific::{Efer, EferFlags, Msr};

const IA32_STAR:  u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_FMASK: u32 = 0xC000_0084;


// ── errno constants (Linux ABI compatible) ──────────────────────────────────
pub const EPERM:   u64 = 1;
pub const ENOENT:  u64 = 2;
pub const ESRCH:   u64 = 3;
pub const EINTR:   u64 = 4;
pub const EIO:     u64 = 5;
pub const EBADF:   u64 = 9;
pub const ENOMEM:  u64 = 12;
pub const EACCES:  u64 = 13;
pub const EFAULT:  u64 = 14;
pub const EINVAL:  u64 = 22;
pub const ENOTSUP: u64 = 95;
pub const ENOSYS:  u64 = 38;
pub const ENOEXEC: u64 = 8;
pub const ENOTTY:  u64 = 25;
pub const ENOTDIR: u64 = 20;
pub const ESPIPE:  u64 = 29;

/// Return negative errno (Linux convention)
#[inline(always)]
pub fn sys_err(e: u64) -> u64 { (-(e as i64)) as u64 }

/// Validate userspace pointer — must not point into kernel
#[inline]
fn validate_user_ptr(ptr: u64, len: u64) -> bool {
    if ptr == 0 { return false; }
    if ptr >= 0x8000_0000_0000 { return false; }
    if len > 0 && ptr.saturating_add(len) > 0x8000_0000_0000 { return false; }
    true
}

pub fn init() {
    unsafe {
        // Activăm SYSCALL/SYSRET în EFER
        Efer::write(Efer::read() | EferFlags::SYSTEM_CALL_EXTENSIONS);

        // STAR: upper 32 bits = CS/SS pentru kernel (bits 47:32) și user (bits 63:48)
        let kcs = crate::arch::x86_64::gdt::KERNEL_CS;
        let ucs = crate::arch::x86_64::gdt::USER_CS & !3;
        let star = ((ucs as u64 - 8) << 48) | ((kcs as u64) << 32);
        Msr::new(IA32_STAR).write(star);

        // LSTAR = adresa entry point
        Msr::new(IA32_LSTAR).write(syscall_entry as *const () as u64);

        // FMASK: dezactivăm IF la syscall entry
        Msr::new(IA32_FMASK).write(0x200);
    }
}

/// Entry point — naked, apelat direct de CPU la instrucțiunea SYSCALL
#[naked]
pub unsafe extern "C" fn syscall_entry() {
    core::arch::naked_asm!(
        "swapgs",
        // Kernel stack pointer este în GS:0 (setat la task switch)
        "mov   gs:8, rsp",
        "mov   rsp, gs:0",
        // Salvăm contextul complet
        "push  rcx",
        "push  r11",
        "push  rbp",
        "push  rdi",
        "push  rsi",
        "push  rdx",
        "push  r10",
        "push  r8",
        "push  r9",
        // Apelăm handler Rust: fn syscall_dispatch(nr, a1, a2, a3, a4, a5) -> u64
        // rax=nr deja, rdi/rsi/rdx/r10/r8/r9 = args
        "mov   rdi, rax",
        "mov   rsi, [rsp+24]",   // arg1 (rdi original)
        "mov   rdx, [rsp+32]",   // arg2 (rsi)
        "mov   rcx, [rsp+40]",   // arg3 (rdx)
        "mov   r8,  [rsp+48]",   // arg4 (r10)
        "mov   r9,  [rsp+56]",   // arg5 (r8)
        "sti",                   // re-activăm întreruperile în kernel
        "call  {dispatch}",
        "cli",                   // dezactivăm la ieșire
        // rax = valoarea de return
        "pop   r9",
        "pop   r8",
        "pop   r10",
        "pop   rdx",
        "pop   rsi",
        "pop   rdi",
        "pop   rbp",
        "pop   r11",
        "pop   rcx",
        "mov   rsp, gs:8",
        "swapgs",
        "sysretq",
        dispatch = sym syscall_dispatch,
    )
}

/// Dispatch principal — apelat din syscall_entry
#[no_mangle]
pub extern "C" fn syscall_dispatch(
    number: u64,
    a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
) -> u64 {
    // ── Seccomp check ─────────────────────────────────────────────────────
    {
        let tid    = crate::arch::x86_64::percpu::current_tid();
        let action = crate::security::seccomp::check_syscall(tid, number);
        if action != crate::security::seccomp::SeccompAction::Allow {
            return crate::security::seccomp::apply_action(tid, number, action);
        }
    }

    match number {
        0  => sys_read(a1, a2 as *mut u8, a3),
        1  => sys_write(a1, a2 as *const u8, a3),
        35 => sys_nanosleep(a1),
        60 => sys_exit(a1 as i32),
        300 => iona_wasm_spawn(a1 as *const u8, a2),
        301 => iona_ipc_send(a1, a2 as *const u8, a3),
        302 => iona_fs_read(a1 as *const u8, a2 as *mut u8, a3),
        303 => iona_fs_write(a1 as *const u8, a2 as *const u8, a3),
        304 => crate::arch::x86_64::timer::uptime_ms(),
        305 => iona_log(a1 as *const u8, a2),
        306 => sys_get_tid(),
        307 => iona_ipc_recv(a1 as *mut u8, a2),
        308 => iona_wasm_kill(a1),
        309 => iona_wasm_status(a1),
        // Network syscalls
        310 => sys_tcp_connect(a1 as *const u8, a2),
        311 => sys_tcp_send(a1, a2 as *const u8, a3),
        312 => sys_tcp_recv(a1, a2 as *mut u8, a3),
        313 => sys_tcp_close(a1),
        314 => sys_tcp_listen(a1 as u16),
        315 => sys_tcp_accept(a1),
        // Config
        322 => sys_get_chain_rpc(a1 as *mut u8, a2),

        // Spawn / wait (userspace process management)
        320 => sys_spawn_elf(a1 as *const u8, a2 as *const u64, a3),
        321 => sys_waitpid_user(a1),

        // Extended IONA syscalls
        330 => sys_fs_list(a1 as *const u8, a2 as *mut u8, a3),
        331 => sys_fs_stat(a1 as *const u8, a2 as *mut u8, a3),
        332 => sys_proc_list(a1 as *mut u8, a2),
        333 => sys_mem_stats(a1 as *mut u8, a2),
        334 => sys_net_get_ip(a1 as *mut u8, a2),
        335 => sys_read_kmsg(a1 as *mut u8, a2),
        336 => sys_get_argv(a1 as *mut u8, a2),
        337 => sys_swap_stats(a1 as *mut u8, a2),
        400 => sys_consensus_tick(a1, a2, a3, a4),
        500 => sys_fs_snapshot(a1, a2),
        501 => sys_fs_restore(a1, a2),
        // Process
        57  => sys_fork(),
        59  => sys_exec(a1 as *const u8, a2),
        61  => sys_waitpid(a1 as i64),
        // mmap
        9   => sys_mmap(a1, a2 as usize, a3 as u32, a4 as u32, a5 as i64, 0),
        11  => sys_munmap(a1, a2 as usize),
        // Signals
        13  => sys_sigaction(a1 as u8, a2),
        62  => sys_kill(a1, a2 as u8),
        // FD
        2   => sys_open(a1 as *const u8, a2 as u32),
        3   => sys_close(a1 as usize),
        4   => sys_stat(a1 as *const u8, a2 as *mut u8, a3),
        5   => sys_fstat(a1 as usize, a2 as *mut u8),
        78  => sys_getdents(a1 as usize, a2 as *mut u8, a3),
        // Debug
        // pipe
        22  => sys_pipe(a1 as *mut u64),
        // futex
        202 => sys_futex(a1, a2 as u32, a3 as u32, a4),
        // epoll
        213 => sys_epoll_create(),
        233 => sys_epoll_ctl(a1, a2 as u32, a3 as usize, a4 as *const u8),
        232 => sys_epoll_wait(a1, a2 as *mut u8, a3 as usize, a4 as i64),
        // UDP
        316 => sys_udp_bind(a1 as u16),
        317 => sys_udp_sendto(a1, a2 as *const u8, a3, a4 as *const u8, a5 as u16),
        318 => sys_udp_recvfrom(a1, a2 as *mut u8, a3, a4 as *mut u8),
        // yield
        24  => { crate::sched::SCHEDULER.lock().block_current_task(); 0 },
        319 => sys_gdb_trap(),
        // Power
        169 => sys_shutdown(),
        // clone() — pthreads
        56  => sys_clone(a1, a2, a3, a4),
        // execve with argv/envp
        // (same number as exec, but now with full args)

        // ── Additional POSIX syscalls ──────────────────────────────────────
        8   => sys_lseek(a1, a2 as i64, a3 as u32),
        12  => sys_sigreturn(),
        16  => sys_ioctl(a1, a2, a3),
        20  => sys_writev(a1, a2, a3),
        32  => 0, // dup
        33  => sys_dup(a1),
        34  => sys_pause(),
        38  => sys_setitimer(a1 as u32, a2, a3),
        40  => sys_dup2(a1, a2),
        72  => sys_fcntl(a1, a2 as u32, a3),
        82  => sys_rename(a1, a2),
        85  => sys_creat(a1, a2 as u32),
        100 => sys_getdents64(a1, a2, a3),
        158 => sys_sched_getaffinity(a1, a2, a3),
        204 => sys_sched_yield(),
        228 => sys_clock_gettime(a1 as u32, a2),
        96  => sys_gettimeofday(a1, a2),
        218 => sys_set_tid_address(a1),
        234 => sys_tgkill(a1, a2, a3),
        28  => sys_madvise(a1, a2, a3 as u32),
        350 => sys_gui_create_window(a1, a2, a3 as u64, a4 as u64, a5 as u64, 0u64),
        351 => sys_gui_destroy_window(a1),
        352 => sys_gui_draw_pixels(a1, a2, a3 as u64, a4 as u64, a5 as u64, 0u64, 0),
        353 => sys_gui_set_title(a1, a2, a3),
        354 => sys_gui_poll_event(a1, a2, a3),
        355 => sys_gui_flush(a1),
        186 => sys_get_tid(), // gettid
        // Shared memory IPC
        65  => crate::mm::shm::shmget(a1, a2 as usize, a3 as u32).unwrap_or(u64::MAX),
        66  => crate::mm::shm::shmat(a1, a2).unwrap_or(u64::MAX),
        67  => if crate::mm::shm::shmdt(a1) { 0 } else { u64::MAX },
        _   => sys_err(ENOSYS),
    }
}

fn sys_write(fd: u64, buf: *const u8, len: u64) -> u64 {
    // fd 1 = stdout → serial + terminal
    // fd 2 = stderr → serial only
    // fd other → EBADF
    if fd > 2 { return sys_err(EBADF); }
    if fd == 1 || fd == 2 {
        let slice = unsafe { core::slice::from_raw_parts(buf, len as usize) };
        if let Ok(s) = core::str::from_utf8(slice) {
            crate::io::serial::_print(format_args!("{}", s));
        }
        len
    } else { u64::MAX }
}

fn sys_read(fd: u64, buf_ptr: *mut u8, len: u64) -> u64 {
    // fd 0 = stdin (PS/2 keyboard buffer)
    // fd 1/2 = stdout/stderr (write-only)
    if fd != 0 { return sys_err(EBADF); }
    if len == 0 { return 0; }
    // Drain keyboard buffer — return available chars up to len
    let mut written = 0u64;
    let max = len.min(256) as usize;
    unsafe {
        let slice = core::slice::from_raw_parts_mut(buf_ptr, max);
        // Read from serial/keyboard ring buffer if available
        for b in slice.iter_mut() {
            if let Some(ch) = crate::io::serial::try_read_byte() {
                *b = ch; written += 1;
            } else { break; }
        }
    }
    written
}

fn sys_exit(code: i32) -> u64 {
    crate::sched::exit_current(code);
    0
}

fn sys_nanosleep(secs: u64) -> u64 {
    crate::arch::x86_64::timer::sleep_ms(secs.saturating_mul(1000));
    0
}

fn iona_wasm_spawn(ptr: *const u8, len: u64) -> u64 {
    let bytes = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
    crate::wasm::spawn_module(bytes).unwrap_or(u64::MAX)
}

fn iona_ipc_send(to: u64, ptr: *const u8, len: u64) -> u64 {
    let data = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
    crate::process::ipc::send(to, data);
    0
}

fn iona_fs_read(path: *const u8, buf: *mut u8, len: u64) -> u64 {
    let p   = unsafe { cstr_to_str(path) };
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len as usize) };
    match crate::fs::ionafs::read(p) {
        Some(data) => { let n = data.len().min(out.len()); out[..n].copy_from_slice(&data[..n]); n as u64 }
        None => u64::MAX,
    }
}

fn iona_fs_write(path: *const u8, data: *const u8, len: u64) -> u64 {
    let p = unsafe { cstr_to_str(path) };
    let d = unsafe { core::slice::from_raw_parts(data, len as usize) };
    crate::fs::ionafs::write(p, d);
    0
}

fn iona_log(ptr: *const u8, len: u64) -> u64 {
    let msg = unsafe { core::slice::from_raw_parts(ptr, len as usize) };
    if let Ok(s) = core::str::from_utf8(msg) {
        crate::serial_println!("[USPACE] {}", s);
    }
    0
}

fn sys_get_tid() -> u64 {
    // Read TID from per-CPU data (GS:16) — no lock needed, always correct
    crate::arch::x86_64::percpu::current_tid()
}

fn iona_ipc_recv(buf: *mut u8, buf_len: u64) -> u64 {
    let tid = sys_get_tid();
    match crate::process::ipc::recv(tid) {
        None    => 0,
        Some(data) => {
            let n = data.len().min(buf_len as usize);
            unsafe { core::slice::from_raw_parts_mut(buf, n).copy_from_slice(&data[..n]); }
            n as u64
        }
    }
}

fn iona_wasm_kill(tid: u64) -> u64 {
    // Signal the WASM task to exit:
    //   1. Send SIGKILL to the kernel task running the WASM module
    //   2. Update supervisor state to Stopped
    //   3. Remove seccomp policy for the tid
    crate::signal::send(tid, crate::signal::Signal::SIGKILL);
    crate::wasm::supervisor::report_crash(tid, "killed by iona_wasm_kill");
    crate::security::seccomp::remove_policy(tid);
    crate::serial_println!("[WASM] kill tid={}", tid);
    0
}

fn iona_wasm_status(tid: u64) -> u64 {
    // 0=running, 1=stopped, 2=crashed
    // Verificăm în scheduler dacă task-ul mai există
    let sched = crate::sched::SCHEDULER.lock();
    let exists = sched.stats().current_tid == Some(tid)
        || { drop(sched); false };
    if exists { 0 } else { 1 }
}

// ── Network syscalls ─────────────────────────────────────────────────────────

#[repr(C)]
struct SockAddr { ip: [u8; 4], port: u16 }

fn sys_tcp_connect(addr_ptr: *const u8, addr_len: u64) -> u64 {
    if addr_len < 6 { return u64::MAX; }
    let addr = unsafe { &*(addr_ptr as *const SockAddr) };
    crate::net::tcp_connect(addr.ip, addr.port)
}

fn sys_tcp_send(fd: u64, buf: *const u8, len: u64) -> u64 {
    let data = unsafe { core::slice::from_raw_parts(buf, len as usize) };
    crate::net::tcp_send(fd, data) as u64
}

fn sys_tcp_recv(fd: u64, buf: *mut u8, len: u64) -> u64 {
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len as usize) };
    crate::net::tcp_recv(fd, out) as u64
}

fn sys_tcp_close(fd: u64) -> u64 {
    crate::net::tcp_close(fd);
    0
}

fn sys_tcp_listen(port: u16) -> u64 {
    crate::net::tcp_listen(port)
}

fn sys_tcp_accept(server_fd: u64) -> u64 {
    crate::net::tcp_accept(server_fd)
}

fn sys_get_chain_rpc(buf: *mut u8, buf_len: u64) -> u64 {
    // Citim din kernel config (stocat în global)
    let url = crate::net::CHAIN_RPC_URL.lock();
    let bytes = url.as_bytes();
    let n = bytes.len().min(buf_len as usize);
    unsafe { core::slice::from_raw_parts_mut(buf, n).copy_from_slice(&bytes[..n]); }
    n as u64
}

pub unsafe fn cstr_to_str<'a>(ptr: *const u8) -> &'a str {
    let mut len = 0;
    while *ptr.add(len) != 0 { len += 1; }
    core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len))
}

// ── New syscall implementations ───────────────────────────────────────────────

fn sys_fork() -> u64 {
    let tid = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    match crate::process::fork::do_fork(tid) {
        Some(child) => child,
        None        => u64::MAX,
    }
}

fn sys_exec(path: *const u8, argv_ptr: u64) -> u64 {
    let p   = unsafe { cstr_to_str(path) };
    let tid = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);

    // Parse argv from userspace pointer array (NULL-terminated)
    let mut argv: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    if argv_ptr != 0 {
        let mut pp = argv_ptr as *const *const u8;
        for _ in 0..128 {
            let arg_ptr = unsafe { *pp };
            if arg_ptr.is_null() { break; }
            argv.push(unsafe { cstr_to_str(arg_ptr) }.into());
            pp = unsafe { pp.add(1) };
        }
    }
    let argv_refs: alloc::vec::Vec<&str> = argv.iter().map(|s| s.as_str()).collect();

    match crate::fs::ionafs::read(p) {
        Some(elf) => match crate::process::fork::do_exec_with_args(tid, &elf, &argv_refs, &[]) {
            Ok(()) => 0,
            Err(_) => u64::MAX,
        },
        None => u64::MAX,
    }
}

fn sys_waitpid(child: i64) -> u64 {
    let parent = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    match crate::process::fork::do_waitpid(parent, child as u64) {
        Some(code) => code as u64,
        None       => u64::MAX,
    }
}

fn sys_mmap(addr: u64, len: usize, prot: u32, flags: u32, fd: i64, offset: u64) -> u64 {
    let tid = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    crate::process::mmap::mmap(tid, addr, len, prot, flags, fd, offset)
}

fn sys_munmap(addr: u64, len: usize) -> u64 {
    let tid = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    if crate::process::mmap::munmap(tid, addr, len) { 0 } else { u64::MAX }
}

fn sys_sigaction(sig: u8, handler: u64) -> u64 {
    let tid = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    crate::signal::set_handler(tid, sig, handler);
    0
}

fn sys_kill(tid: u64, sig: u8) -> u64 {
    if let Some(s) = num_to_signal(sig) {
        crate::signal::send(tid, s);
        0
    } else { u64::MAX }
}

fn num_to_signal(n: u8) -> Option<crate::signal::Signal> {
    match n {
        1  => Some(crate::signal::Signal::SIGHUP),
        2  => Some(crate::signal::Signal::SIGINT),
        9  => Some(crate::signal::Signal::SIGKILL),
        11 => Some(crate::signal::Signal::SIGSEGV),
        15 => Some(crate::signal::Signal::SIGTERM),
        17 => Some(crate::signal::Signal::SIGCHLD),
        _  => None,
    }
}

fn sys_open(path: *const u8, _flags: u32) -> u64 {
    let p   = unsafe { cstr_to_str(path) };
    let tid = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    let desc = if p.starts_with("/proc") {
        crate::process::fd::FileDesc::Proc(p.into())
    } else if p.starts_with("/dev") {
        crate::process::fd::FileDesc::Dev(p.into())
    } else {
        crate::process::fd::FileDesc::IonasFs { path: p.into(), offset: 0 }
    };
    match crate::process::fd::open(tid, desc) {
        Some(fd) => fd as u64,
        None     => u64::MAX,
    }
}

fn sys_close(fd: usize) -> u64 {
    let tid = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    crate::process::fd::close(tid, fd);
    0
}

fn sys_stat(path: *const u8, _buf: *mut u8, _len: u64) -> u64 {
    let p = unsafe { cstr_to_str(path) };
    match crate::fs::vfs::stat(p) {
        Ok(_)  => 0,
        Err(_) => u64::MAX,
    }
}

fn sys_fstat(fd: usize, _buf: *mut u8) -> u64 {
    let tid = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    match crate::process::fd::get_clone(tid, fd) {
        Some(_) => 0,
        None    => u64::MAX,
    }
}

fn sys_getdents(_fd: usize, _buf: *mut u8, _len: u64) -> u64 {
    // List directory entries — simplified
    0
}

fn sys_gdb_trap() -> u64 {
    crate::debug::gdb_trap();
    0
}

fn sys_shutdown() -> u64 {
    crate::acpi::power::shutdown();
}

fn sys_pipe(fds_ptr: *mut u64) -> u64 {
    let tid = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    let (rid, wid) = crate::process::pipe::create();
    // Open read and write ends as file descriptors
    let read_fd  = crate::process::fd::open(tid, crate::process::fd::FileDesc::Pipe { read_end: true,  id: rid });
    let write_fd = crate::process::fd::open(tid, crate::process::fd::FileDesc::Pipe { read_end: false, id: wid });
    match (read_fd, write_fd) {
        (Some(r), Some(w)) => {
            unsafe { fds_ptr.write(r as u64); fds_ptr.add(1).write(w as u64); }
            0
        }
        _ => u64::MAX,
    }
}

fn sys_futex(addr: u64, op: u32, val: u32, timeout_ms: u64) -> u64 {
    let result = match op & 0x7F {
        0 | 128 => crate::process::futex::futex_wait(addr, val, timeout_ms),
        1 | 129 => crate::process::futex::futex_wake(addr, val),
        _       => -1i64,
    };
    result as u64
}

fn sys_epoll_create() -> u64 {
    crate::process::epoll::epoll_create()
}

fn sys_epoll_ctl(eid: u64, op: u32, fd: usize, event_ptr: *const u8) -> u64 {
    let event = unsafe { *(event_ptr as *const crate::process::epoll::EpollEvent) };
    crate::process::epoll::epoll_ctl(eid, op, fd, event) as u64
}

fn sys_epoll_wait(eid: u64, events_ptr: *mut u8, max_events: usize, timeout_ms: i64) -> u64 {
    let tid    = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    let events = unsafe {
        core::slice::from_raw_parts_mut(
            events_ptr as *mut crate::process::epoll::EpollEvent, max_events
        )
    };
    crate::process::epoll::epoll_wait(eid, tid, events, timeout_ms) as u64
}

fn sys_udp_bind(port: u16) -> u64 {
    crate::net::udp::udp_bind(port)
}

fn sys_udp_sendto(fd: u64, buf: *const u8, len: u64, addr: *const u8, port: u16) -> u64 {
    let data    = unsafe { core::slice::from_raw_parts(buf, len as usize) };
    let ip: [u8;4] = if addr.is_null() { [0;4] } else {
        unsafe { *(addr as *const [u8;4]) }
    };
    crate::net::udp::udp_sendto(fd, data, ip, port) as u64
}

fn sys_udp_recvfrom(fd: u64, buf: *mut u8, len: u64, addr_out: *mut u8) -> u64 {
    let out = unsafe { core::slice::from_raw_parts_mut(buf, len as usize) };
    let (n, ip, port) = crate::net::udp::udp_recvfrom(fd, out);
    if !addr_out.is_null() {
        unsafe {
            core::slice::from_raw_parts_mut(addr_out, 4).copy_from_slice(&ip);
            (addr_out.add(4) as *mut u16).write_unaligned(port);
        }
    }
    n as u64
}

fn sys_clone(flags: u64, child_sp: u64, _ptid_ptr: u64, tls: u64) -> u64 {
    let parent_tid = crate::sched::SCHEDULER.lock().current_tid().unwrap_or(0);
    // Apply seccomp check
    let action = crate::security::seccomp::check_syscall(parent_tid, 56);
    if action != crate::security::seccomp::SeccompAction::Allow {
        return u64::MAX;
    }
    match crate::process::clone::do_clone(parent_tid, flags, child_sp, tls) {
        Some(child) => child,
        None        => u64::MAX,
    }
}

fn sys_shutdown_socket(fd: u64, how: u32) -> u64 {
    crate::net::tcp_shutdown(fd, how);
    0
}

pub fn sys_open_compat(_path_user: u64, _flags: u32, _mode: u32) -> u64 {
    // Simplified open — map to FS read fd
    // Full implementation: allocate FD, track open files
    0
}

// ── Additional POSIX syscalls ─────────────────────────────────────────────────
fn sys_lseek(_fd: u64, _offset: i64, _whence: u32) -> u64 {
    // Stub: lseek not yet implemented
    sys_err(ESPIPE)
}

fn sys_sigreturn() -> u64 {
    // Stub: sigreturn not yet implemented
    0
}

fn sys_fcntl(fd: u64, cmd: u32, arg: u64) -> u64 {
    match cmd {
        0 => { // F_DUPFD - stub
            sys_err(EBADF)
        }
        1 => fd, // F_GETFD — return fd flags (0 = no FD_CLOEXEC)
        2 => 0,  // F_SETFD — ignore for now
        3 => 0,  // F_GETFL — return file flags (0 = O_RDWR)
        4 => 0,  // F_SETFL — ignore
        _ => sys_err(EINVAL),
    }
}

fn sys_rename(old_user: u64, new_user: u64) -> u64 {
    let old = match crate::syscall::user_access::copy_cstr_from_user(old_user) { Ok(s) => s, Err(_) => return sys_err(EFAULT) };
    let new = match crate::syscall::user_access::copy_cstr_from_user(new_user) { Ok(s) => s, Err(_) => return sys_err(EFAULT) };
    match crate::fs::ionafs::rename(&old, &new) { true => 0, false => sys_err(ENOENT) }
}

fn sys_creat(path_user: u64, mode: u32) -> u64 {
    let path = match crate::syscall::user_access::copy_cstr_from_user(path_user) { Ok(s) => s, Err(_) => return sys_err(EFAULT) };
    crate::fs::ionafs::write(&path, &[]);
    // Return fd 0 as placeholder — full implementation: allocate FD
    0
}

fn sys_pause() -> u64 {
    // Block until any signal arrives — simplified: sleep 1s
    crate::arch::x86_64::timer::sleep_ms(1000);
    sys_err(EINTR) // pause returns -EINTR when interrupted by signal
}

fn sys_setitimer(_which: u32, _new_val: u64, _old_val: u64) -> u64 {
    // Interval timer — simplified: acknowledge but don't arm
    0
}


fn sys_ioctl(fd: u64, req: u64, arg: u64) -> u64 {
    const TIOCGWINSZ: u64 = 0x5413;
    const TCGETS:     u64 = 0x5401;
    const TCSETS:     u64 = 0x5402;
    const TCSETSW:    u64 = 0x5403;
    const FIONREAD:   u64 = 0x541B;
    match req {
        TIOCGWINSZ => {
            // struct winsize: ws_row, ws_col, ws_xpixel, ws_ypixel (each u16)
            if arg != 0 {
                unsafe {
                    let ws = arg as *mut u16;
                    *ws         = 24;    // rows
                    *ws.add(1)  = 88;    // cols
                    *ws.add(2)  = 720;   // xpixel
                    *ws.add(3)  = 420;   // ypixel
                }
                0
            } else { sys_err(EFAULT) }
        }
        TCGETS | TCSETS | TCSETSW => 0,   // terminal attrs — accept silently
        FIONREAD => 0,                     // bytes available to read = 0
        _ => sys_err(EINVAL),
    }
}

fn sys_writev(fd: u64, iov_ptr: u64, iovcnt: u64) -> u64 {
    // struct iovec { iov_base: *const u8, iov_len: usize } — 16 bytes on x86_64
    if iovcnt == 0 || iov_ptr == 0 { return 0; }
    let mut total = 0u64;
    for i in 0..iovcnt.min(16) {
        let base_ptr = (iov_ptr + i * 16) as *const u64;
        let (base, len) = unsafe { (*base_ptr as *const u8, *base_ptr.add(1) as u64) };
        if base.is_null() || len == 0 { continue; }
        total += sys_write(fd, base, len);
    }
    total
}

fn sys_dup(old_fd: u64) -> u64 {
    // Simple: fds 0-2 always valid — return next free fd (3)
    if old_fd <= 2 { 3 } else { sys_err(EBADF) }
}

fn sys_dup2(old_fd: u64, new_fd: u64) -> u64 {
    let tid = crate::arch::x86_64::percpu::current_tid();
    if crate::process::fd::dup2(tid, old_fd as usize, new_fd as usize) { new_fd } else { sys_err(EBADF) }
}

fn sys_getdents64(fd: u64, dirp: u64, count: u64) -> u64 {
    // Simplified: list files in current directory via IONAFS
    // Returns ENOTDIR for non-directory fds
    sys_err(ENOTDIR)
}

fn sys_madvise(_addr: u64, _len: u64, _advice: u32) -> u64 { 0 }  // no-op

fn sys_clock_gettime(clk_id: u32, tp_user: u64) -> u64 {
    let ms = crate::arch::x86_64::timer::uptime_ms();
    let sec  = ms / 1000;
    let nsec = (ms % 1000) * 1_000_000;
    if !crate::syscall::user_access::check_user_range(tp_user, 16) { return sys_err(EFAULT); }
    let _ = crate::syscall::user_access::put_user_u64(tp_user,     sec);
    let _ = crate::syscall::user_access::put_user_u64(tp_user + 8, nsec);
    0
}

fn sys_gettimeofday(tv_user: u64, _tz_user: u64) -> u64 {
    let ms = crate::arch::x86_64::timer::uptime_ms();
    if tv_user != 0 {
        if !crate::syscall::user_access::check_user_range(tv_user, 16) { return sys_err(EFAULT); }
        let _ = crate::syscall::user_access::put_user_u64(tv_user,     ms / 1000);
        let _ = crate::syscall::user_access::put_user_u64(tv_user + 8, (ms % 1000) * 1000);
    }
    0
}

fn sys_sched_yield() -> u64 { crate::sched::SCHEDULER.lock().block_current_task(); 0 }
fn sys_sched_getaffinity(_pid: u64, _cpusetsize: u64, _mask_user: u64) -> u64 { 0 }

fn sys_set_tid_address(tidptr: u64) -> u64 {
    crate::arch::x86_64::percpu::current_tid() as u64
}

fn sys_tgkill(_tgid: u64, tid: u64, sig: u64) -> u64 {
    crate::signal::send(tid, crate::signal::Signal::SIGKILL); // simplified
    0
}

// ── GUI syscalls (350-356) ──────────────────────────────────────────────────
fn sys_gui_create_window(title_ptr: u64, title_len: u64, x: u64, y: u64, w: u64, h: u64) -> u64 {
    if !validate_user_ptr(title_ptr, title_len) { return sys_err(EFAULT); }
    let title = {
        let mut buf = alloc::vec![0u8; title_len as usize];
        match crate::syscall::user_access::copy_from_user(&mut buf, title_ptr) {
            Ok(_) => String::from_utf8_lossy(&buf).into_owned(),
            Err(_) => return sys_err(EFAULT),
        }
    };
    let tid = crate::arch::x86_64::percpu::current_tid();
    let wid = crate::gui::wm::create_window(
        &title, x as i32, y as i32, w as u32, h as u32, tid);
    crate::gui::ipc::register_window(wid);
    wid as u64
}

fn sys_gui_destroy_window(wid: u64) -> u64 {
    crate::gui::ipc::unregister_window(wid as u32);
    crate::gui::wm::close_window(wid as u32);
    0
}

fn sys_gui_draw_pixels(wid: u64, x: u64, y: u64, w: u64, h: u64,
                        pixels_ptr: u64, pixels_len: u64) -> u64 {
    if !validate_user_ptr(pixels_ptr, pixels_len * 4) { return sys_err(EFAULT); }
    let raw = {
        let mut buf = alloc::vec![0u8; pixels_len as usize * 4];
        match crate::syscall::user_access::copy_from_user(&mut buf, pixels_ptr) {
            Ok(_) => buf, Err(_) => return sys_err(EFAULT),
        }
    };
    // Convert &[u8] to &[u32]
    let pixels: alloc::vec::Vec<u32> = raw.chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0],c[1],c[2],c[3]]))
        .collect();
    crate::gui::wm::update_pixels(wid as u32, x as u16, y as u16, w as u16, h as u16, &pixels);
    0
}

fn sys_gui_set_title(wid: u64, title_ptr: u64, title_len: u64) -> u64 {
    if !validate_user_ptr(title_ptr, title_len) { return sys_err(EFAULT); }
    let title = {
        let mut buf = alloc::vec![0u8; title_len as usize];
        match crate::syscall::user_access::copy_from_user(&mut buf, title_ptr) {
            Ok(_) => String::from_utf8_lossy(&buf).into_owned(),
            Err(_) => return sys_err(EFAULT),
        }
    };
    crate::gui::wm::set_title(wid as u32, title);
    0
}

fn sys_gui_poll_event(wid: u64, buf_ptr: u64, buf_len: u64) -> u64 {
    if !validate_user_ptr(buf_ptr, buf_len) { return sys_err(EFAULT); }
    match crate::gui::ipc::poll_window_event(wid as u32) {
        None => 0,
        Some(ev) => {
            let n = ev.len().min(buf_len as usize);
            let _ = crate::syscall::user_access::copy_to_user(buf_ptr, &ev[..n]);
            n as u64
        }
    }
}

fn sys_gui_flush(wid: u64) -> u64 {
    // Mark window as dirty — will be redrawn next frame
    crate::gui::desktop::mark_dirty();
    0
}

// ── Syscall 400: Consensus tick — advance kernel BFT engine ──────────────────
fn sys_consensus_tick(height: u64, round: u64, step: u64, cert_ptr: u64) -> u64 {
    // Delegate to kernel Tendermint engine
    crate::consensus::engine::advance_tick(height, round, step as u8, cert_ptr as u32)
}

// ── Syscall 500-502: IONAFS snapshot/restore/rollback ─────────────────────
fn sys_fs_snapshot(path_ptr: u64, path_len: u64) -> u64 {
    let path = {
        let mut buf = alloc::vec![0u8; path_len as usize];
        match crate::syscall::user_access::copy_from_user(&mut buf, path_ptr) {
            Ok(_) => alloc::string::String::from_utf8_lossy(&buf).into_owned(),
            Err(_) => return sys_err(EFAULT),
        }
    };
    // Write all IONAFS files to a zip-like archive
    let files = crate::fs::ionafs::list();
    let mut archive: alloc::vec::Vec<u8> = alloc::vec![];
    for file_path in &files {
        if let Some(data) = crate::fs::ionafs::read(file_path) {
            // Simple format: [path_len:2][path][data_len:4][data]
            let pb = file_path.as_bytes();
            archive.extend_from_slice(&(pb.len() as u16).to_le_bytes());
            archive.extend_from_slice(pb);
            archive.extend_from_slice(&(data.len() as u32).to_le_bytes());
            archive.extend_from_slice(&data);
        }
    }
    crate::fs::ionafs::write(&path, &archive);
    crate::fs::ionafs::sync_to_disk();
    archive.len() as u64
}

fn sys_fs_restore(path_ptr: u64, path_len: u64) -> u64 {
    let path = {
        let mut buf = alloc::vec![0u8; path_len as usize];
        match crate::syscall::user_access::copy_from_user(&mut buf, path_ptr) {
            Ok(_) => alloc::string::String::from_utf8_lossy(&buf).into_owned(),
            Err(_) => return sys_err(EFAULT),
        }
    };
    let archive = match crate::fs::ionafs::read(&path) {
        Some(d) => d, None => return sys_err(ENOENT),
    };
    let mut i = 0usize;
    let mut restored = 0u64;
    while i + 6 <= archive.len() {
        let plen = u16::from_le_bytes([archive[i], archive[i+1]]) as usize; i += 2;
        if i + plen > archive.len() { break; }
        let file_path = alloc::string::String::from_utf8_lossy(&archive[i..i+plen]).into_owned(); i += plen;
        if i + 4 > archive.len() { break; }
        let dlen = u32::from_le_bytes(archive[i..i+4].try_into().unwrap_or([0;4])) as usize; i += 4;
        if i + dlen > archive.len() { break; }
        crate::fs::ionafs::write(&file_path, &archive[i..i+dlen]); i += dlen;
        restored += 1;
    }
    crate::fs::ionafs::sync_to_disk();
    restored
}

/// Returnează statistici swap: (total_pages, used_pages)
fn sys_swap_stats(buf_ptr: u64, _len: u64) -> u64 {
    use crate::syscall::user_access::copy_to_user;
    // IONA OS nu are swap implementat — returnăm 0/0
    let total: u64 = 0;
    let used:  u64 = 0;
    let data   = [total.to_le_bytes(), used.to_le_bytes()].concat();
    let _ = copy_to_user(buf_ptr, &data);
    0
}

// ── Spawn ELF (syscall 320) ──────────────────────────────────────────────────
fn sys_spawn_elf(path_ptr: *const u8, argv_ptr: *const u64, argc: u64) -> u64 {
    use crate::syscall::user_access::{copy_cstr_from_user, copy_from_user, check_user_range};
    let path = match unsafe { copy_cstr_from_user(path_ptr as u64) } {
        Ok(p) => p,
        Err(_) => return u64::MAX,
    };

    // Copy argv strings from userspace
    let mut args_owned: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
    if argc > 0 && argc <= 64 && check_user_range(argv_ptr as u64, argc * 8) {
        for i in 0..argc {
            let ptr_addr = argv_ptr as u64 + i * 8;
            let mut ptr_buf = [0u8; 8];
            if copy_from_user(&mut ptr_buf, ptr_addr).is_ok() {
                let str_ptr = u64::from_le_bytes(ptr_buf);
                if let Ok(s) = unsafe { copy_cstr_from_user(str_ptr) } {
                    args_owned.push(s);
                }
            }
        }
    }
    let args_refs: alloc::vec::Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();

    // Fork a new process and exec the ELF
    let current_tid = crate::sched::SCHEDULER.lock()
        .current_tid().unwrap_or(crate::task::TaskId(0));

    match crate::process::fork::do_fork(current_tid) {
        Some(child_tid) => {
            // In child context: exec the ELF
            // do_execve loads ELF, sets up stack, activates address space
            match crate::process::exec::do_execve(child_tid, &path, &args_refs, &[]) {
                Ok(_sp) => {
                    crate::serial_println!("  [SYSCALL] spawn_elf: '{}' → child tid={}", path, child_tid.0);
                    child_tid.0 as u64
                }
                Err(e) => {
                    crate::serial_println!("  [SYSCALL] spawn_elf: '{}' exec failed: {}", path, e);
                    u64::MAX
                }
            }
        }
        None => {
            crate::serial_println!("  [SYSCALL] spawn_elf: fork failed for '{}'", path);
            u64::MAX
        }
    }
}

// ── Waitpid userspace (syscall 321) ─────────────────────────────────────────
fn sys_waitpid_user(pid: u64) -> u64 {
    // Block current task until pid task exits
    // Simplified: poll with yield until task is gone from scheduler
    let max_wait_ms = 30_000u64;
    let start = crate::arch::x86_64::timer::uptime_ms();
    loop {
        let alive = crate::sched::SCHEDULER.lock()
            .stats().total_tasks > 0; // simplified check
        if !alive { return 0; }
        let elapsed = crate::arch::x86_64::timer::uptime_ms().saturating_sub(start);
        if elapsed > max_wait_ms { return u64::MAX; }
        crate::sched::yield_now();
    }
}

// ── FS list (syscall 330) ────────────────────────────────────────────────────
fn sys_fs_list(path_ptr: *const u8, buf_ptr: *mut u8, buf_len: u64) -> u64 {
    use crate::syscall::user_access::{copy_cstr_from_user, copy_to_user};
    let path = match unsafe { copy_cstr_from_user(path_ptr as u64) } {
        Ok(p) => p,
        Err(_) => return u64::MAX,
    };
    let prefix = if path.ends_with('/') { path.clone() } else { alloc::format!("{}/", path) };
    let files = crate::fs::ionafs::list_prefix(&prefix, 256);
    let mut result = alloc::string::String::new();
    for f in &files {
        let name = f.trim_start_matches(&prefix);
        if !name.is_empty() && !name.contains('/') {
            if !result.is_empty() { result.push('\n'); }
            result.push_str(name);
        }
    }
    let bytes = result.as_bytes();
    let n = bytes.len().min(buf_len as usize);
    let _ = unsafe { copy_to_user(buf_ptr as u64, &bytes[..n]) };
    n as u64
}

// ── FS stat (syscall 331) ────────────────────────────────────────────────────
fn sys_fs_stat(path_ptr: *const u8, buf_ptr: *mut u8, buf_len: u64) -> u64 {
    use crate::syscall::user_access::{copy_cstr_from_user, copy_to_user};
    let path = match unsafe { copy_cstr_from_user(path_ptr as u64) } {
        Ok(p) => p,
        Err(_) => return u64::MAX,
    };
    match crate::fs::ionafs::stat(&path) {
        Some(st) => {
            let info = alloc::format!("size={}", st.size);
            let bytes = info.as_bytes();
            let n = bytes.len().min(buf_len as usize);
            let _ = unsafe { copy_to_user(buf_ptr as u64, &bytes[..n]) };
            n as u64
        }
        None => 0,
    }
}

// ── Proc list (syscall 332) ──────────────────────────────────────────────────
fn sys_proc_list(buf_ptr: *mut u8, buf_len: u64) -> u64 {
    use crate::syscall::user_access::copy_to_user;
    let stats = crate::sched::SCHEDULER.lock().stats();
    let info = alloc::format!("0\tkernel\tRunning\t0.0\n1\tgui\tRunning\t0.0\n");
    let bytes = info.as_bytes();
    let n = bytes.len().min(buf_len as usize);
    let _ = unsafe { copy_to_user(buf_ptr as u64, &bytes[..n]) };
    n as u64
}

// ── Mem stats (syscall 333) ──────────────────────────────────────────────────
fn sys_mem_stats(buf_ptr: *mut u8, _buf_len: u64) -> u64 {
    use crate::syscall::user_access::copy_to_user;
    let stats = { let (t,u) = crate::memory::frame_alloc::stats(); (t as u64, u as u64) };
    let data = [stats.0.to_le_bytes(), stats.1.to_le_bytes()].concat();
    let _ = unsafe { copy_to_user(buf_ptr as u64, &data) };
    0
}

// ── Net get IP (syscall 334) ─────────────────────────────────────────────────
fn sys_net_get_ip(buf_ptr: *mut u8, buf_len: u64) -> u64 {
    use crate::syscall::user_access::copy_to_user;
    let ip = b"10.0.2.15";
    let n = ip.len().min(buf_len as usize);
    let _ = unsafe { copy_to_user(buf_ptr as u64, &ip[..n]) };
    n as u64
}

// ── Read kmsg (syscall 335) ──────────────────────────────────────────────────
fn sys_read_kmsg(buf_ptr: *mut u8, buf_len: u64) -> u64 {
    use crate::syscall::user_access::copy_to_user;
    // Return structured kernel log from ring buffer
    let log = crate::io::klog::drain_to_string(buf_len as usize);
    let bytes = if log.is_empty() {
        b"[IONA OS] No messages in ring buffer
".to_vec()
    } else {
        log.into_bytes()
    };
    let n = bytes.len().min(buf_len as usize);
    let _ = unsafe { copy_to_user(buf_ptr as u64, &bytes[..n]) };
    n as u64
}

// ── Get argv (syscall 336) ───────────────────────────────────────────────────
fn sys_get_argv(buf_ptr: *mut u8, _buf_len: u64) -> u64 {
    use crate::syscall::user_access::copy_to_user;
    let argv = b"\0";
    let _ = unsafe { copy_to_user(buf_ptr as u64, argv) };
    1
}

// ── Swap stats (syscall 337) ─────────────────────────────────────────────────
fn sys_swap_stats(buf_ptr: *mut u8, _len: u64) -> u64 {
    use crate::syscall::user_access::copy_to_user;
    // IONA OS does not implement swap — return 0/0
    let data = [0u64.to_le_bytes(), 0u64.to_le_bytes()].concat();
    let _ = unsafe { copy_to_user(buf_ptr as u64, &data) };
    0
}

/// Check iona-node health via IONAFS state file
pub fn check_node_health() -> bool {
    // Check if iona-node has written a recent heartbeat
    match crate::fs::ionafs::read("/var/iona-node/heartbeat") {
        Some(data) => {
            let ts_bytes: [u8; 8] = data[..8].try_into().unwrap_or([0u8;8]);
            let last_hb = u64::from_le_bytes(ts_bytes);
            let now = crate::arch::x86_64::timer::uptime_ms();
            let elapsed = now.saturating_sub(last_hb);
            elapsed < 60_000 // healthy if heartbeat within 60s
        }
        None => false // no heartbeat file = not running
    }
}
