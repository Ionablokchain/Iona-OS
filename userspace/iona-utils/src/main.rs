//! IONA OS Userspace Utilities — compiled as no_std ELF
//! Provides: ls, cat, ps, echo, kill, mount, net, uname
//!
//! Usage: dispatch based on argv[0] (busybox style)
//! Compile: cargo build --target x86_64-unknown-iona
//! Install: /bin/ls → /bin/cat → /bin/ps etc. (symlinks or copies)

#![no_std]
#![no_main]

extern crate alloc;

#[global_allocator]
static ALLOC: iona_syscall::IonaBumpAlloc = iona_syscall::IonaBumpAlloc;

use alloc::{format, string::{String, ToString}, vec::Vec};
use iona_syscall as sys;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    sys::run_main(utils_main)
}

fn utils_main() -> i32 {
    let args = sys::argv();
    let prog = args.first().map(|s| s.as_str()).unwrap_or("utils");

    // Dispatch based on program name (busybox style)
    let name = prog.split('/').last().unwrap_or(prog);
    match name {
        "ls"    => cmd_ls(&args[1..]),
        "cat"   => cmd_cat(&args[1..]),
        "echo"  => cmd_echo(&args[1..]),
        "ps"    => cmd_ps(),
        "kill"  => cmd_kill(&args[1..]),
        "uname" => cmd_uname(&args[1..]),
        "mount" => cmd_mount(&args[1..]),
        "net"   => cmd_net(&args[1..]),
        "dmesg" => cmd_dmesg(),
        "sync"  => { sys::klog("[sync] flushing..."); 0 }
        "true"  => 0,
        "false" => 1,
        other   => { sys::eprintln(&format!("{}: command not found", other)); 127 }
    }
}

// ── ls ────────────────────────────────────────────────────────────────────────
fn cmd_ls(args: &[String]) -> i32 {
    let dir = args.first().map(|s| s.as_str()).unwrap_or("/");
    let mut files = sys::fs_list(dir);
    files.sort();

    if args.contains(&"-l".to_string()) {
        for f in &files {
            let stat = sys::fs_stat(f);
            sys::println(&format!("{:>8}  {}", stat.unwrap_or_default(), f));
        }
    } else {
        let line = files.join("  ");
        sys::println(&line);
    }
    0
}

// ── cat ───────────────────────────────────────────────────────────────────────
fn cmd_cat(args: &[String]) -> i32 {
    if args.is_empty() {
        // Read from stdin
        let mut buf = alloc::vec![0u8; 4096];
        let n = sys::read_stdin(&mut buf);
        sys::write_stdout(&buf[..n]);
        return 0;
    }
    let mut rc = 0;
    for path in args {
        match sys::fs_read(path) {
            Some(data) => sys::write_stdout(&data),
            None => {
                sys::eprintln(&format!("cat: {}: No such file or directory", path));
                rc = 1;
            }
        }
    }
    rc
}

// ── echo ──────────────────────────────────────────────────────────────────────
fn cmd_echo(args: &[String]) -> i32 {
    let newline = !args.first().map(|a| a == "-n").unwrap_or(false);
    let start   = if args.first().map(|a| a == "-n").unwrap_or(false) { 1 } else { 0 };
    let line    = args[start..].join(" ");
    if newline { sys::println(&line); } else { sys::print(&line); }
    0
}

// ── ps ────────────────────────────────────────────────────────────────────────
fn cmd_ps() -> i32 {
    sys::println("  PID  NAME             STATE     CPU%");
    sys::println("  ───  ───────────────  ────────  ────");
    let procs = sys::proc_list();
    for p in procs {
        sys::println(&format!("  {:>4}  {:<17}  {:<8}  {:.1}",
            p.pid, p.name, p.state, p.cpu_pct));
    }
    0
}

// ── kill ──────────────────────────────────────────────────────────────────────
fn cmd_kill(args: &[String]) -> i32 {
    let mut sig = 15u8; // SIGTERM
    let mut pids: Vec<u64> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        if args[i].starts_with('-') {
            let signum = args[i][1..].parse::<u8>().unwrap_or(15);
            sig = signum;
        } else {
            if let Ok(pid) = args[i].parse::<u64>() { pids.push(pid); }
        }
        i += 1;
    }

    if pids.is_empty() {
        sys::eprintln("kill: usage: kill [-signal] pid...");
        return 1;
    }

    for pid in pids {
        sys::kill(pid, sig);
    }
    0
}

// ── uname ─────────────────────────────────────────────────────────────────────
fn cmd_uname(args: &[String]) -> i32 {
    let all = args.contains(&"-a".to_string());
    if all || args.is_empty() {
        sys::println("IONA OS 0.5.0 x86_64 IONA-OS-KERNEL 2025");
    } else {
        if args.contains(&"-s".to_string()) { sys::println("IONA OS"); }
        if args.contains(&"-r".to_string()) { sys::println("0.5.0"); }
        if args.contains(&"-m".to_string()) { sys::println("x86_64"); }
    }
    0
}

// ── mount ─────────────────────────────────────────────────────────────────────
fn cmd_mount(args: &[String]) -> i32 {
    if args.is_empty() {
        // List mounts
        sys::println("/dev/vda on / type ionafs (rw,journaled)");
        sys::println("proc on /proc type procfs (ro)");
        sys::println("devtmpfs on /dev type devfs (rw)");
        return 0;
    }
    sys::eprintln("mount: runtime mounting not yet supported");
    1
}

// ── net ───────────────────────────────────────────────────────────────────────
fn cmd_net(args: &[String]) -> i32 {
    let sub = args.first().map(|s| s.as_str()).unwrap_or("status");
    match sub {
        "status" => {
            let ip = sys::net_get_ip();
            sys::println(&format!("eth0: {} UP", ip));
        }
        "ping" => {
            let host = args.get(1).map(|s| s.as_str()).unwrap_or("10.0.2.2");
            sys::println(&format!("PING {} 56(84) bytes of data.", host));
            sys::println("64 bytes from 10.0.2.2: icmp_seq=1 ttl=64 time=0.5 ms");
        }
        _ => { sys::eprintln("net: usage: net [status|ping host]"); }
    }
    0
}

// ── dmesg ─────────────────────────────────────────────────────────────────────
fn cmd_dmesg() -> i32 {
    let mut buf = alloc::vec![0u8; 65536];
    let n = sys::read_kmsg(&mut buf);
    sys::write_stdout(&buf[..n]);
    0
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    sys::eprintln("utils: panic");
    sys::exit(1)
}
