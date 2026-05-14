//! procfs — virtual filesystem pentru informații kernel
//!
//! Fișiere suportate:
//!   /proc/version     — kernel version string
//!   /proc/uptime      — uptime în secunde
//!   /proc/meminfo     — statistici memorie
//!   /proc/cpuinfo     — info procesor
//!   /proc/loadavg     — load average (simplified)
//!   /proc/<pid>/stat  — task status
//!   /proc/<pid>/maps  — memory mappings (stub)
//!   /proc/<pid>/fd    — file descriptors (stub)

use alloc::string::String;
use alloc::vec::Vec;

/// Read a procfs entry. Returns None if path not recognized.
pub fn read_proc(path: &str) -> Option<Vec<u8>> {
    match path {
        "/proc/version" => {
            let v = alloc::format!(
                "IONA OS version 0.6.0 (Rust nightly) #1 SMP {}\n",
                crate::arch::x86_64::timer::uptime_ms() / 1000
            );
            Some(v.into_bytes())
        }
        "/proc/uptime" => {
            let up_ms = crate::arch::x86_64::timer::uptime_ms();
            let secs = up_ms / 1000;
            let v = alloc::format!("{}.{:02} {}.{:02}\n",
                secs, (up_ms % 1000) / 10,
                secs / 2, (up_ms % 1000) / 10);
            Some(v.into_bytes())
        }
        "/proc/meminfo" => {
            let (total, used) = crate::memory::frame_alloc::stats();
            let free  = total.saturating_sub(used);
            let v = alloc::format!(
                "MemTotal:       {:8} kB\nMemFree:        {:8} kB\nMemAvailable:   {:8} kB\n\
                 Buffers:             0 kB\nCached:              0 kB\nSwapTotal:           0 kB\n\
                 SwapFree:            0 kB\n",
                total * 4, free * 4, free * 4
            );
            Some(v.into_bytes())
        }
        "/proc/cpuinfo" => {
            let cpus = crate::arch::x86_64::apic::CPU_COUNT_REAL
                .load(core::sync::atomic::Ordering::Relaxed);
            let mut v = String::new();
            for i in 0..cpus.max(1) {
                v.push_str(&alloc::format!(
                    "processor\t: {}\nvendor_id\t: IONA\ncpu family\t: 6\n\
                     model name\t: IONA OS x86_64\ncpu MHz\t\t: 1000.000\n\
                     cache size\t: 256 KB\nflags\t\t: fpu vme de pse tsc msr pae sse2\n\n",
                    i
                ));
            }
            Some(v.into_bytes())
        }
        "/proc/loadavg" => {
            let stats = crate::sched::SCHEDULER.lock().stats();
            let running = stats.running_count.max(0);
            let total_t = stats.total_tasks;
            let v = alloc::format!("0.{:02} 0.{:02} 0.{:02} {}/{} 1\n",
                running, running / 2, running / 4, running, total_t);
            Some(v.into_bytes())
        }
        "/proc/mounts" => {
            Some(b"ionafs / ionafs rw,relatime 0 0\n".to_vec())
        }
        "/proc/sys/kernel/hostname" => {
            Some(b"iona-os\n".to_vec())
        }
        p if p.starts_with("/proc/") => {
            // /proc/<pid>/stat etc
            let parts: Vec<&str> = p.splitn(4, '/').collect();
            if parts.len() >= 3 {
                let pid_str = parts[2];
                let file    = if parts.len() > 3 { parts[3] } else { "" };
                if let Ok(_pid) = pid_str.parse::<u64>() {
                    return read_proc_pid(file);
                }
            }
            None
        }
        _ => None,
    }
}

fn read_proc_pid(file: &str) -> Option<Vec<u8>> {
    let stats = crate::sched::SCHEDULER.lock().stats();
    match file {
        "stat" => {
            let v = alloc::format!(
                "1 (iona-os) S 0 0 0 0 -1 4194560 0 0 0 0 {} 0 0 0 20 0 {} 0 0\n",
                crate::arch::x86_64::timer::uptime_ms() / 10,
                stats.total_tasks
            );
            Some(v.into_bytes())
        }
        "status" => {
            let (total, used) = crate::memory::frame_alloc::stats();
            let v = alloc::format!(
                "Name:\tiona-os\nState:\tS (sleeping)\nPid:\t1\nVmRSS:\t{} kB\n",
                used * 4
            );
            Some(v.into_bytes())
        }
        "cmdline" => Some(b"/bin/iona-os\0".to_vec()),
        "maps"    => Some(b"00000000-ffffffff r-xp 0 00:00 0 [kernel]\n".to_vec()),
        "fd"      => Some(b"".to_vec()),
        _         => None,
    }
}

/// Check if a path is a procfs path
pub fn is_proc_path(path: &str) -> bool {
    path.starts_with("/proc/")
}
