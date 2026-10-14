//! WASM host functions — the complete set of kernel functions exposed to
//! WASM modules.
//!
//! # Function catalogue
//!
//! | Group    | Functions |
//! |----------|-----------|
//! | I/O      | `log_write` |
//! | Storage  | `storage_get`, `storage_set` |
//! | Events   | `emit_event` |
//! | Network  | `tcp_connect`, `tcp_send`, `tcp_recv`, `tcp_close`, `udp_bind`, `udp_sendto`, `udp_recvfrom` |
//! | IPC      | `ipc_send`, `ipc_recv` |
//! | FS       | `fs_read`, `fs_write`, `fs_exists`, `fs_delete` |
//! | System   | `get_uptime_ms`, `get_chain_rpc`, `spawn_module` |
//!
//! All functions are registered via [`register_all`].
//!
//! # Security model
//!
//! A WASM module is **untrusted code**. Every host function in this module:
//!
//! 1. **Validates pointers and lengths.** `ptr`/`len` arguments are treated
//!    as unsigned 32-bit offsets and must lie entirely within the module's
//!    linear memory. Negative values, overflowed ranges, and out-of-bounds
//!    ranges yield [`errno::EBADPTR`]. **No host function can panic on
//!    malformed input.**
//! 2. **Bounds allocations.** Calls that need a kernel-side buffer cap it at
//!    [`MAX_HOST_IO_BYTES`]; a larger `len`/`cap` yields
//!    [`errno::EOVERFLOW`]. This closes the "ask for 2 GiB" DoS vector.
//! 3. **Sandboxes the filesystem.** The `fs_*` functions resolve paths
//!    relative to a per-module root (`/wasm/<tid>/`). Absolute paths, `..`,
//!    `.`, empty segments, and NUL bytes are rejected with
//!    [`errno::EACCES`].
//! 4. **Validates IP octets.** `tcp_connect`, `udp_bind`, `udp_sendto`
//!    reject octets outside `0..=255` and a zero port on `connect`/`sendto`.
//!
//! # Error codes
//!
//! Functions returning `i32` use the [`errno`] constants (all negative).
//! Functions returning `i64` (file descriptors, task IDs) return `-1` on
//! error. Non-negative return values are byte counts, entry counts, or
//! handle values, as documented on each function.
//!
//! # Storage persistence
//!
//! `storage_set` mutates [`WasmState::storage`] only. It does **not** touch
//! the filesystem. The previous version called `ionafs::write` on every set,
//! turning an O(1) map update into an O(disk) operation.
//!
//! Persisting the map is the caller's responsibility — e.g. serialize it to
//! `/wasm/<tid>/kv.dat` at module shutdown and load it back on next start.
//!
//! # Untrusted code envelope
//!
//! `spawn_module` currently has no rate limit. A malicious module can spawn
//! unbounded child modules and exhaust task slots. Callers deploying
//! untrusted code should gate this function behind a policy layer (e.g. a
//! per-module spawn counter) or omit it from the linker entirely.

use alloc::string::String;
use alloc::vec::Vec;

use wasmi::{Caller, Linker};

use crate::wasm::WasmState;

// ── Limits ────────────────────────────────────────────────────────────────

/// Maximum number of bytes a single host call will copy into or out of
/// WASM linear memory.
pub const MAX_HOST_IO_BYTES: usize = 8 * 1024 * 1024;

/// Maximum length of a module-supplied path, in bytes.
pub const MAX_PATH_BYTES: usize = 4096;

/// Maximum length of a storage key, in bytes.
pub const MAX_STORAGE_KEY_BYTES: usize = 1024;

/// Maximum length of a storage value, in bytes.
pub const MAX_STORAGE_VALUE_BYTES: usize = 256 * 1024;

/// Maximum length of an event topic, in bytes.
pub const MAX_EVENT_TOPIC_BYTES: usize = 256;

/// Maximum length of an event payload, in bytes.
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 256 * 1024;

/// Name of the memory export every module must provide.
pub const MEMORY_EXPORT: &str = "memory";

/// Per-module filesystem root prefix.
pub const WASM_FS_ROOT: &str = "/wasm";

// ── Error codes ───────────────────────────────────────────────────────────

/// Negative `i32` error codes returned to WASM.
pub mod errno {
    /// Malformed input (invalid UTF-8, NUL byte in a string, etc.).
    pub const EPROTO: i32 = -1;
    /// Pointer or length out of bounds, or overflowed.
    pub const EBADPTR: i32 = -2;
    /// Invalid argument (bad IP octet, zero port on connect, etc.).
    pub const EINVAL: i32 = -3;
    /// Underlying I/O failure.
    pub const EIO: i32 = -4;
    /// Key, path, or file not found.
    pub const ENOTFOUND: i32 = -5;
    /// Sandbox violation or permission denied.
    pub const EACCES: i32 = -6;
    /// Kernel allocation failed.
    pub const ENOMEM: i32 = -7;
    /// A size limit was exceeded.
    pub const EOVERFLOW: i32 = -8;
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Fetch the module's exported linear memory.
fn memory_of(caller: &Caller<WasmState>) -> Option<wasmi::Memory> {
    caller.get_export(MEMORY_EXPORT).and_then(|e| e.into_memory())
}

/// Validate a `(ptr, len)` pair against a memory of `size` bytes.
///
/// Rejects negative values, overflow, and out-of-bounds ranges. Returns the
/// checked `Range<usize>` on success.
fn check_range(size: usize, ptr: i32, len: i32) -> Result<core::ops::Range<usize>, i32> {
    if ptr < 0 || len < 0 {
        return Err(errno::EBADPTR);
    }
    let start = ptr as usize;
    let len = len as usize;
    let end = start.checked_add(len).ok_or(errno::EBADPTR)?;
    if end > size {
        return Err(errno::EBADPTR);
    }
    Ok(start..end)
}

/// Copy `len` bytes out of WASM memory at `ptr`.
fn read_bytes(
    mem: &wasmi::Memory,
    caller: &Caller<WasmState>,
    ptr: i32,
    len: i32,
    limit: usize,
) -> Result<Vec<u8>, i32> {
    if len < 0 || (len as usize) > limit {
        return Err(errno::EOVERFLOW);
    }
    let size = mem.data(caller).len();
    let range = check_range(size, ptr, len)?;
    Ok(mem.data(caller)[range].to_vec())
}

/// Copy `src` into WASM memory at `ptr`, up to `capacity` bytes.
///
/// Returns the number of bytes actually written (`min(src.len(), capacity)`).
fn write_bytes(
    mem: &wasmi::Memory,
    caller: &mut Caller<WasmState>,
    ptr: i32,
    capacity: i32,
    src: &[u8],
) -> Result<usize, i32> {
    let size = mem.data(&*caller).len();
    let range = check_range(size, ptr, capacity)?;
    let cap = range.len();
    let n = src.len().min(cap);
    mem.data_mut(caller)[range.start..range.start + n].copy_from_slice(&src[..n]);
    Ok(n)
}

/// Validate a module-supplied path and resolve it into the module's
/// sandboxed root (`/wasm/<tid>/`).
///
/// Rejects: empty paths, NUL bytes, absolute paths, and any `.`/`..`
/// segment. Returns the absolute path on success.
fn sandbox_path(tid: u64, raw: &[u8]) -> Result<String, i32> {
    if raw.len() > MAX_PATH_BYTES {
        return Err(errno::EOVERFLOW);
    }
    let s = core::str::from_utf8(raw).map_err(|_| errno::EPROTO)?;
    if s.is_empty() {
        return Err(errno::EINVAL);
    }
    if s.contains('\0') || s.starts_with('/') {
        return Err(errno::EACCES);
    }
    for seg in s.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(errno::EACCES);
        }
    }
    Ok(alloc::format!("{WASM_FS_ROOT}/{tid}/{s}"))
}

/// Convert four `i32` octets into a validated IPv4 address.
fn ip_from_octets(o: [i32; 4]) -> Result<[u8; 4], i32> {
    let mut out = [0u8; 4];
    for (i, &x) in o.iter().enumerate() {
        if !(0..=255).contains(&x) {
            return Err(errno::EINVAL);
        }
        out[i] = x as u8;
    }
    Ok(out)
}

/// Validate a port argument. `allow_zero` controls whether port 0 is
/// accepted (valid for `bind`, not for `connect`/`sendto`).
fn check_port(port: i32, allow_zero: bool) -> Result<u16, i32> {
    if !(0..=65535).contains(&port) {
        return Err(errno::EINVAL);
    }
    if !allow_zero && port == 0 {
        return Err(errno::EINVAL);
    }
    Ok(port as u16)
}

// ── Registration ──────────────────────────────────────────────────────────

/// Register every host function.
pub fn register_all(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    register_io(linker)?;
    register_storage(linker)?;
    register_events(linker)?;
    register_network(linker)?;
    register_ipc(linker)?;
    register_fs(linker)?;
    register_system(linker)?;
    Ok(())
}

// ── I/O ───────────────────────────────────────────────────────────────────

/// Register `log_write(ptr, len)` — appends a UTF-8 string to the module's
/// log buffer and mirrors it to the serial console.
///
/// On invalid UTF-8, the call is dropped (no return value).
fn register_io(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        "env",
        "log_write",
        |caller: Caller<WasmState>, ptr: i32, len: i32| {
            let Some(mem) = memory_of(&caller) else { return };
            let bytes = match read_bytes(&mem, &caller, ptr, len, MAX_HOST_IO_BYTES) {
                Ok(b) => b,
                Err(_) => return,
            };
            let Ok(msg) = core::str::from_utf8(&bytes) else { return };
            let tid = caller.data().tid;
            crate::serial_println!("[WASM:{tid}] {msg}");
            caller.data_mut().log_buf.push(msg.into());
        },
    )?;
    Ok(())
}

// ── Storage ───────────────────────────────────────────────────────────────

/// Register `storage_get` and `storage_set`.
///
/// Both operate purely on [`WasmState::storage`]; persistence is the
/// caller's responsibility (see module docs).
fn register_storage(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    // storage_get(key_ptr, key_len, value_ptr, value_capacity) -> bytes written
    //                                                           | ENOTFOUND
    linker.func_wrap(
        "env",
        "storage_get",
        |caller: Caller<WasmState>, kp: i32, kl: i32, vp: i32, vc: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            let key = match read_bytes(&mem, &caller, kp, kl, MAX_STORAGE_KEY_BYTES) {
                Ok(k) => k,
                Err(e) => return e,
            };
            let value = match caller.data().storage.get(&key) {
                Some(v) => v.clone(),
                None => return errno::ENOTFOUND,
            };
            match write_bytes(&mut { caller }, &mem, vp, vc, &value) {
                Ok(n) => n as i32,
                Err(e) => e,
            }
        },
    )?;

    // storage_set(key_ptr, key_len, value_ptr, value_len) -> 0 | errno
    linker.func_wrap(
        "env",
        "storage_set",
        |mut caller: Caller<WasmState>, kp: i32, kl: i32, vp: i32, vl: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            let key = match read_bytes(&mem, &caller, kp, kl, MAX_STORAGE_KEY_BYTES) {
                Ok(k) => k,
                Err(e) => return e,
            };
            let val = match read_bytes(&mem, &caller, vp, vl, MAX_STORAGE_VALUE_BYTES) {
                Ok(v) => v,
                Err(e) => return e,
            };
            caller.data_mut().storage.insert(key, val);
            0
        },
    )?;
    Ok(())
}

// ── Events ────────────────────────────────────────────────────────────────

/// Register `emit_event(topic_ptr, topic_len, payload_ptr, payload_len)`.
///
/// Appends the event to [`WasmState::events`] and mirrors it to the serial
/// console.
fn register_events(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    linker.func_wrap(
        "env",
        "emit_event",
        |caller: Caller<WasmState>, tp: i32, tl: i32, dp: i32, dl: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            let topic_bytes =
                match read_bytes(&mem, &caller, tp, tl, MAX_EVENT_TOPIC_BYTES) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
            let topic = match core::str::from_utf8(&topic_bytes) {
                Ok(s) => s.to_string(),
                Err(_) => return errno::EPROTO,
            };
            let payload =
                match read_bytes(&mem, &caller, dp, dl, MAX_EVENT_PAYLOAD_BYTES) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
            let tid = caller.data().tid;
            crate::serial_println!("[WASM:{tid}] event: {topic}");
            caller.data_mut().events.push((topic, payload));
            0
        },
    )?;
    Ok(())
}

// ── Network ───────────────────────────────────────────────────────────────

/// Register TCP and UDP host functions.
///
/// **Note on egress:** none of these functions enforce an egress policy.
/// A module can connect to any IP and port reachable by the kernel. Callers
/// deploying untrusted code should filter at the network layer or omit the
/// network host functions from the linker.
fn register_network(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    // tcp_connect(ip0..3, port) -> fd | -1
    linker.func_wrap(
        "env",
        "tcp_connect",
        |_caller: Caller<WasmState>, i0: i32, i1: i32, i2: i32, i3: i32, port: i32| -> i64 {
            let ip = match ip_from_octets([i0, i1, i2, i3]) {
                Ok(ip) => ip,
                Err(_) => return -1,
            };
            let port = match check_port(port, /*allow_zero=*/ false) {
                Ok(p) => p,
                Err(_) => return -1,
            };
            crate::net::tcp_connect(ip, port) as i64
        },
    )?;

    // tcp_send(fd, ptr, len) -> bytes sent | errno
    linker.func_wrap(
        "env",
        "tcp_send",
        |caller: Caller<WasmState>, fd: i64, ptr: i32, len: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            let bytes = match read_bytes(&mem, &caller, ptr, len, MAX_HOST_IO_BYTES) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let sent = crate::net::tcp_send(fd as u64, &bytes);
            if sent < 0 {
                errno::EIO
            } else {
                sent as i32
            }
        },
    )?;

    // tcp_recv(fd, ptr, capacity) -> bytes read | errno
    linker.func_wrap(
        "env",
        "tcp_recv",
        |mut caller: Caller<WasmState>, fd: i64, ptr: i32, cap: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            if cap < 0 || (cap as usize) > MAX_HOST_IO_BYTES {
                return errno::EOVERFLOW;
            }
            let mut buf = alloc::vec![0u8; cap as usize];
            let n = crate::net::tcp_recv(fd as u64, &mut buf);
            if n < 0 {
                return errno::EIO;
            }
            let n = n as usize;
            match write_bytes(&mem, &mut caller, ptr, cap, &buf[..n]) {
                Ok(written) => written as i32,
                Err(e) => e,
            }
        },
    )?;

    // tcp_close(fd)
    linker.func_wrap(
        "env",
        "tcp_close",
        |_caller: Caller<WasmState>, fd: i64| {
            crate::net::tcp_close(fd as u64);
        },
    )?;

    // udp_bind(port) -> fd | -1
    linker.func_wrap(
        "env",
        "udp_bind",
        |_caller: Caller<WasmState>, port: i32| -> i64 {
            let port = match check_port(port, /*allow_zero=*/ true) {
                Ok(p) => p,
                Err(_) => return -1,
            };
            match crate::net::udp::udp_bind([0u8; 4], port) {
                Ok(fd) => fd as i64,
                Err(_) => -1,
            }
        },
    )?;

    // udp_sendto(fd, ptr, len, ip0..3, port) -> bytes sent | errno
    linker.func_wrap(
        "env",
        "udp_sendto",
        |caller: Caller<WasmState>, fd: i64, ptr: i32, len: i32,
         i0: i32, i1: i32, i2: i32, i3: i32, port: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            let bytes = match read_bytes(&mem, &caller, ptr, len, MAX_HOST_IO_BYTES) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let ip = match ip_from_octets([i0, i1, i2, i3]) {
                Ok(ip) => ip,
                Err(e) => return e,
            };
            let port = match check_port(port, /*allow_zero=*/ false) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let sent = crate::net::udp::udp_sendto(fd as u64, &bytes, ip, port);
            if sent < 0 {
                errno::EIO
            } else {
                sent as i32
            }
        },
    )?;

    // udp_recvfrom(fd, ptr, capacity) -> bytes read | errno
    linker.func_wrap(
        "env",
        "udp_recvfrom",
        |mut caller: Caller<WasmState>, fd: i64, ptr: i32, cap: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            if cap < 0 || (cap as usize) > MAX_HOST_IO_BYTES {
                return errno::EOVERFLOW;
            }
            let mut buf = alloc::vec![0u8; cap as usize];
            let (n, _ip, _port) = crate::net::udp::udp_recvfrom(fd as u64, &mut buf);
            if n < 0 {
                return errno::EIO;
            }
            let n = n as usize;
            match write_bytes(&mem, &mut caller, ptr, cap, &buf[..n]) {
                Ok(written) => written as i32,
                Err(e) => e,
            }
        },
    )?;

    Ok(())
}

// ── IPC ───────────────────────────────────────────────────────────────────

/// Register `ipc_send(to_tid, ptr, len)` and `ipc_recv(ptr, capacity)`.
fn register_ipc(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    // ipc_send(to_tid, ptr, len) -> 0 | errno
    linker.func_wrap(
        "env",
        "ipc_send",
        |caller: Caller<WasmState>, to_tid: i64, ptr: i32, len: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            let bytes = match read_bytes(&mem, &caller, ptr, len, MAX_HOST_IO_BYTES) {
                Ok(b) => b,
                Err(e) => return e,
            };
            crate::process::ipc::send(to_tid as u64, &bytes);
            0
        },
    )?;

    // ipc_recv(ptr, capacity) -> bytes written, 0 if empty, errno on failure
    linker.func_wrap(
        "env",
        "ipc_recv",
        |mut caller: Caller<WasmState>, ptr: i32, cap: i32| -> i32 {
            if cap < 0 || (cap as usize) > MAX_HOST_IO_BYTES {
                return errno::EOVERFLOW;
            }
            let tid = caller.data().tid;
            let msg = match crate::process::ipc::recv(tid) {
                None => return 0,
                Some(m) => m,
            };
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            match write_bytes(&mem, &mut caller, ptr, cap, &msg) {
                Ok(n) => n as i32,
                Err(e) => e,
            }
        },
    )?;
    Ok(())
}

// ── Filesystem ────────────────────────────────────────────────────────────

/// Register `fs_read`, `fs_write`, `fs_exists`, `fs_delete`.
///
/// All paths are resolved inside `/wasm/<tid>/`. See [`sandbox_path`].
fn register_fs(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    // fs_read(path_ptr, path_len, buf_ptr, buf_cap) -> bytes read | errno
    linker.func_wrap(
        "env",
        "fs_read",
        |mut caller: Caller<WasmState>, pp: i32, pl: i32, bp: i32, bc: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            let path_bytes =
                match read_bytes(&mem, &caller, pp, pl, MAX_PATH_BYTES) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
            let tid = caller.data().tid;
            let path = match sandbox_path(tid, &path_bytes) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let data = match crate::fs::ionafs::read(&path) {
                Some(d) => d,
                None => return errno::ENOTFOUND,
            };
            if bc < 0 || (bc as usize) > MAX_HOST_IO_BYTES {
                return errno::EOVERFLOW;
            }
            match write_bytes(&mem, &mut caller, bp, bc, &data) {
                Ok(n) => n as i32,
                Err(e) => e,
            }
        },
    )?;

    // fs_write(path_ptr, path_len, data_ptr, data_len) -> 0 | errno
    linker.func_wrap(
        "env",
        "fs_write",
        |caller: Caller<WasmState>, pp: i32, pl: i32, dp: i32, dl: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            let path_bytes =
                match read_bytes(&mem, &caller, pp, pl, MAX_PATH_BYTES) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
            let data = match read_bytes(&mem, &caller, dp, dl, MAX_HOST_IO_BYTES) {
                Ok(b) => b,
                Err(e) => return e,
            };
            let tid = caller.data().tid;
            let path = match sandbox_path(tid, &path_bytes) {
                Ok(p) => p,
                Err(e) => return e,
            };
            match crate::fs::ionafs::write(&path, &data) {
                Ok(()) => 0,
                Err(_) => errno::EIO,
            }
        },
    )?;

    // fs_exists(path_ptr, path_len) -> 1 | 0 | errno
    linker.func_wrap(
        "env",
        "fs_exists",
        |caller: Caller<WasmState>, pp: i32, pl: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            let path_bytes =
                match read_bytes(&mem, &caller, pp, pl, MAX_PATH_BYTES) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
            let tid = caller.data().tid;
            match sandbox_path(tid, &path_bytes) {
                Ok(path) => {
                    if crate::fs::ionafs::exists(&path) { 1 } else { 0 }
                }
                Err(e) => e,
            }
        },
    )?;

    // fs_delete(path_ptr, path_len) -> 1 | 0 | errno
    linker.func_wrap(
        "env",
        "fs_delete",
        |caller: Caller<WasmState>, pp: i32, pl: i32| -> i32 {
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            let path_bytes =
                match read_bytes(&mem, &caller, pp, pl, MAX_PATH_BYTES) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
            let tid = caller.data().tid;
            match sandbox_path(tid, &path_bytes) {
                Ok(path) => {
                    if crate::fs::ionafs::delete(&path) { 1 } else { 0 }
                }
                Err(e) => e,
            }
        },
    )?;

    Ok(())
}

// ── System ────────────────────────────────────────────────────────────────

/// Register `get_uptime_ms`, `get_chain_rpc`, `spawn_module`.
fn register_system(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    // get_uptime_ms() -> u64
    linker.func_wrap(
        "env",
        "get_uptime_ms",
        |_caller: Caller<WasmState>| -> i64 {
            crate::arch::x86_64::timer::uptime_ms() as i64
        },
    )?;

    // get_chain_rpc(ptr, capacity) -> bytes written | errno
    linker.func_wrap(
        "env",
        "get_chain_rpc",
        |mut caller: Caller<WasmState>, ptr: i32, cap: i32| -> i32 {
            let url = crate::net::CHAIN_RPC_URL.lock().clone();
            if cap < 0 || (cap as usize) > MAX_HOST_IO_BYTES {
                return errno::EOVERFLOW;
            }
            let Some(mem) = memory_of(&caller) else { return errno::EINVAL };
            match write_bytes(&mem, &mut caller, ptr, cap, url.as_bytes()) {
                Ok(n) => n as i32,
                Err(e) => e,
            }
        },
    )?;

    // spawn_module(ptr, len) -> new task id | -1
    linker.func_wrap(
        "env",
        "spawn_module",
        |caller: Caller<WasmState>, ptr: i32, len: i32| -> i64 {
            let Some(mem) = memory_of(&caller) else { return -1 };
            let bytes = match read_bytes(&mem, &caller, ptr, len, MAX_HOST_IO_BYTES) {
                Ok(b) => b,
                Err(_) => return -1,
            };
            match crate::wasm::spawn_module(&bytes) {
                Ok(tid) => tid as i64,
                Err(_) => -1,
            }
        },
    )?;

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── check_range ─────────────────────────────────────────────────────

    #[test]
    fn check_range_accepts_valid_window() {
        assert_eq!(check_range(100, 0, 0).unwrap(), 0..0);
        assert_eq!(check_range(100, 0, 100).unwrap(), 0..100);
        assert_eq!(check_range(100, 50, 50).unwrap(), 50..100);
    }

    #[test]
    fn check_range_rejects_negative_ptr() {
        assert_eq!(check_range(100, -1, 1), Err(errno::EBADPTR));
    }

    #[test]
    fn check_range_rejects_negative_len() {
        assert_eq!(check_range(100, 0, -1), Err(errno::EBADPTR));
    }

    #[test]
    fn check_range_rejects_overflow() {
        // i32::MAX as len plus any positive ptr overflows.
        assert_eq!(
            check_range(usize::MAX, i32::MAX, i32::MAX),
            Err(errno::EBADPTR),
        );
    }

    #[test]
    fn check_range_rejects_out_of_bounds() {
        assert_eq!(check_range(100, 0, 101), Err(errno::EBADPTR));
        assert_eq!(check_range(100, 100, 1), Err(errno::EBADPTR));
    }

    // ── sandbox_path ────────────────────────────────────────────────────

    #[test]
    fn sandbox_path_accepts_plain_relative() {
        assert_eq!(sandbox_path(7, b"kv/data").unwrap(), "/wasm/7/kv/data");
        assert_eq!(sandbox_path(7, b"file").unwrap(), "/wasm/7/file");
    }

    #[test]
    fn sandbox_path_rejects_absolute() {
        assert_eq!(sandbox_path(7, b"/etc/passwd"), Err(errno::EACCES));
    }

    #[test]
    fn sandbox_path_rejects_parent() {
        assert_eq!(sandbox_path(7, b"../secret"), Err(errno::EACCES));
        assert_eq!(sandbox_path(7, b"a/../../etc"), Err(errno::EACCES));
    }

    #[test]
    fn sandbox_path_rejects_dot_and_empty_segments() {
        assert_eq!(sandbox_path(7, b"a/./b"), Err(errno::EACCES));
        assert_eq!(sandbox_path(7, b"a//b"), Err(errno::EACCES));
        assert_eq!(sandbox_path(7, b""), Err(errno::EINVAL));
    }

    #[test]
    fn sandbox_path_rejects_nul() {
        assert_eq!(sandbox_path(7, b"a\0b"), Err(errno::EACCES));
    }

    #[test]
    fn sandbox_path_rejects_non_utf8() {
        assert_eq!(sandbox_path(7, &[0xff, 0xfe]), Err(errno::EPROTO));
    }

    #[test]
    fn sandbox_path_rejects_oversized() {
        let huge = alloc::vec![b'a'; MAX_PATH_BYTES + 1];
        assert_eq!(sandbox_path(7, &huge), Err(errno::EOVERFLOW));
    }

    #[test]
    fn sandbox_path_is_per_module() {
        assert_ne!(
            sandbox_path(1, b"f").unwrap(),
            sandbox_path(2, b"f").unwrap()
        );
    }

    // ── ip_from_octets ──────────────────────────────────────────────────

    #[test]
    fn ip_from_octets_accepts_full_range() {
        assert_eq!(ip_from_octets([0, 0, 0, 0]), Ok([0, 0, 0, 0]));
        assert_eq!(ip_from_octets([255, 255, 255, 255]), Ok([255, 255, 255, 255]));
        assert_eq!(ip_from_octets([127, 0, 0, 1]), Ok([127, 0, 0, 1]));
    }

    #[test]
    fn ip_from_octets_rejects_out_of_range() {
        assert_eq!(ip_from_octets([256, 0, 0, 0]), Err(errno::EINVAL));
        assert_eq!(ip_from_octets([0, -1, 0, 0]), Err(errno::EINVAL));
        assert_eq!(ip_from_octets([0, 0, 0, 9999]), Err(errno::EINVAL));
    }

    // ── check_port ──────────────────────────────────────────────────────

    #[test]
    fn check_port_accepts_valid() {
        assert_eq!(check_port(0, true), Ok(0));
        assert_eq!(check_port(0, false), Err(errno::EINVAL));
        assert_eq!(check_port(80, false), Ok(80));
        assert_eq!(check_port(65535, true), Ok(65535));
    }

    #[test]
    fn check_port_rejects_out_of_range() {
        assert_eq!(check_port(-1, true), Err(errno::EINVAL));
        assert_eq!(check_port(65536, true), Err(errno::EINVAL));
    }
}
