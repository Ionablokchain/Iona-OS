//! WASM host functions — complete set of kernel functions exposed to WASM modules.
//!
//! This module implements all the host functions that WASM modules can call.
//! It includes:
//!
//! - **I/O**: `log_write` for printing to the serial console.
//! - **Storage**: `storage_get` / `storage_set` for per‑module persistent key‑value store.
//! - **Events**: `emit_event` for broadcasting events to IPC listeners.
//! - **Network**: TCP and UDP socket operations.
//! - **IPC**: Inter‑process communication (send/receive messages).
//! - **File system**: `fs_read`, `fs_write`, `fs_exists`, `fs_delete` (IONAFS).
//! - **System**: `get_uptime_ms`, `get_chain_rpc`, `spawn_module`.
//!
//! # Registration
//!
//! All host functions are registered via `register_all(linker)`.

use wasmi::{Caller, Linker};
use crate::wasm::WasmState;

// -----------------------------------------------------------------------------
// Public registration
// -----------------------------------------------------------------------------

/// Register all host functions (I/O, storage, events, network, IPC, FS, system).
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

// -----------------------------------------------------------------------------
// I/O functions
// -----------------------------------------------------------------------------

/// Register `log_write` – prints a string to the serial console and appends to the module's log buffer.
fn register_io(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    linker.func_wrap("env", "log_write", |mut caller: Caller<WasmState>, ptr: i32, len: i32| {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return,
        };
        let msg_bytes = mem.data(&caller)[ptr as usize..(ptr + len) as usize].to_vec();
        if let Ok(msg) = core::str::from_utf8(&msg_bytes) {
            let tid = caller.data().tid;
            crate::serial_println!("[WASM:{}] {}", tid, msg);
            caller.data_mut().log_buf.push(msg.into());
        }
    })?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Storage functions (per‑module KV store)
// -----------------------------------------------------------------------------

/// Register `storage_get` and `storage_set`.
fn register_storage(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    // storage_get(key_ptr, key_len, value_ptr, value_capacity) -> actual length (or -1 if not found)
    linker.func_wrap("env", "storage_get", |mut caller: Caller<WasmState>, kp: i32, kl: i32, vp: i32, vc: i32| -> i32 {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return -1,
        };
        let key = mem.data(&caller)[kp as usize..(kp + kl) as usize].to_vec();
        let val = caller.data().storage.get(&key).cloned();
        match val {
            None => -1,
            Some(v) => {
                let n = v.len().min(vc as usize);
                mem.data_mut(&mut caller)[vp as usize..vp as usize + n].copy_from_slice(&v[..n]);
                n as i32
            }
        }
    })?;

    // storage_set(key_ptr, key_len, value_ptr, value_len)
    linker.func_wrap("env", "storage_set", |mut caller: Caller<WasmState>, kp: i32, kl: i32, vp: i32, vl: i32| {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return,
        };
        let data = mem.data(&caller);
        let key = data[kp as usize..(kp + kl) as usize].to_vec();
        let val = data[vp as usize..(vp + vl) as usize].to_vec();
        let path = alloc::format!("/proc/{}/{}", caller.data().tid,
            core::str::from_utf8(&key).unwrap_or("?"));
        crate::fs::ionafs::write(&path, &val);
        caller.data_mut().storage.insert(key, val);
    })?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Event functions
// -----------------------------------------------------------------------------

/// Register `emit_event` – sends an event to all registered IPC listeners.
fn register_events(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    linker.func_wrap("env", "emit_event", |mut caller: Caller<WasmState>, tp: i32, tl: i32, dp: i32, dl: i32| {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return,
        };
        let data = mem.data(&caller);
        let topic = core::str::from_utf8(&data[tp as usize..(tp + tl) as usize]).unwrap_or("").into();
        let payload = data[dp as usize..(dp + dl) as usize].to_vec();
        let tid = caller.data().tid;
        crate::serial_println!("[WASM:{}] event: {}", tid, topic);
        // Broadcast via IPC to all registered listeners
        caller.data_mut().events.push((topic, payload));
    })?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Network functions (TCP and UDP)
// -----------------------------------------------------------------------------

/// Register TCP and UDP host functions.
fn register_network(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    // --- TCP ---
    // tcp_connect(ip0, ip1, ip2, ip3, port) -> file descriptor (i64)
    linker.func_wrap("env", "tcp_connect", |_caller: Caller<WasmState>, ip0: i32, ip1: i32, ip2: i32, ip3: i32, port: i32| -> i64 {
        crate::net::tcp_connect([ip0 as u8, ip1 as u8, ip2 as u8, ip3 as u8], port as u16) as i64
    })?;

    // tcp_send(fd, ptr, len) -> bytes sent (i32)
    linker.func_wrap("env", "tcp_send", |caller: Caller<WasmState>, fd: i64, ptr: i32, len: i32| -> i32 {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return 0,
        };
        let data = mem.data(&caller)[ptr as usize..(ptr + len) as usize].to_vec();
        crate::net::tcp_send(fd as u64, &data) as i32
    })?;

    // tcp_recv(fd, ptr, capacity) -> bytes read (i32)
    linker.func_wrap("env", "tcp_recv", |mut caller: Caller<WasmState>, fd: i64, ptr: i32, cap: i32| -> i32 {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return 0,
        };
        let mut tmp = alloc::vec![0u8; cap as usize];
        let n = crate::net::tcp_recv(fd as u64, &mut tmp);
        if n > 0 {
            mem.data_mut(&mut caller)[ptr as usize..ptr as usize + n].copy_from_slice(&tmp[..n]);
        }
        n as i32
    })?;

    // tcp_close(fd)
    linker.func_wrap("env", "tcp_close", |_caller: Caller<WasmState>, fd: i64| {
        crate::net::tcp_close(fd as u64);
    })?;

    // --- UDP ---
    // udp_bind(port) -> file descriptor (i64)
    linker.func_wrap("env", "udp_bind", |_caller: Caller<WasmState>, port: i32| -> i64 {
        crate::net::udp::udp_bind([0u8; 4], port as u16).unwrap_or(u64::MAX) as i64
    })?;

    // udp_sendto(fd, ptr, len, ip0, ip1, ip2, ip3, port) -> bytes sent (i32)
    linker.func_wrap("env", "udp_sendto", |caller: Caller<WasmState>, fd: i64, ptr: i32, len: i32, ip0: i32, ip1: i32, ip2: i32, ip3: i32, port: i32| -> i32 {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return 0,
        };
        let data = mem.data(&caller)[ptr as usize..(ptr + len) as usize].to_vec();
        crate::net::udp::udp_sendto(fd as u64, &data, [ip0 as u8, ip1 as u8, ip2 as u8, ip3 as u8], port as u16) as i32
    })?;

    // udp_recvfrom(fd, ptr, capacity) -> bytes read (i32)
    linker.func_wrap("env", "udp_recvfrom", |mut caller: Caller<WasmState>, fd: i64, ptr: i32, cap: i32| -> i32 {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return 0,
        };
        let mut tmp = alloc::vec![0u8; cap as usize];
        let (n, _ip, _port) = crate::net::udp::udp_recvfrom(fd as u64, &mut tmp);
        if n > 0 {
            mem.data_mut(&mut caller)[ptr as usize..ptr as usize + n].copy_from_slice(&tmp[..n]);
        }
        n as i32
    })?;

    Ok(())
}

// -----------------------------------------------------------------------------
// IPC (inter‑process communication)
// -----------------------------------------------------------------------------

/// Register `ipc_send` and `ipc_recv`.
fn register_ipc(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    // ipc_send(to_tid, ptr, len)
    linker.func_wrap("env", "ipc_send", |caller: Caller<WasmState>, to_tid: i64, ptr: i32, len: i32| {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return,
        };
        let data = mem.data(&caller)[ptr as usize..(ptr + len) as usize].to_vec();
        crate::process::ipc::send(to_tid as u64, &data);
    })?;

    // ipc_recv(ptr, capacity) -> bytes read (i32), 0 if none
    linker.func_wrap("env", "ipc_recv", |mut caller: Caller<WasmState>, ptr: i32, cap: i32| -> i32 {
        let tid = caller.data().tid;
        match crate::process::ipc::recv(tid) {
            None => 0,
            Some(msg) => {
                let n = msg.len().min(cap as usize);
                let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
                    Some(m) => m,
                    None => return 0,
                };
                mem.data_mut(&mut caller)[ptr as usize..ptr as usize + n].copy_from_slice(&msg[..n]);
                n as i32
            }
        }
    })?;
    Ok(())
}

// -----------------------------------------------------------------------------
// File system (IONAFS)
// -----------------------------------------------------------------------------

/// Register `fs_read`, `fs_write`, `fs_exists`, `fs_delete`.
fn register_fs(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    // fs_read(path_ptr, path_len, buf_ptr, buf_cap) -> bytes read, or -1 on error
    linker.func_wrap("env", "fs_read", |mut caller: Caller<WasmState>, pp: i32, pl: i32, bp: i32, bc: i32| -> i32 {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return -1,
        };
        let path_bytes = mem.data(&caller)[pp as usize..(pp + pl) as usize].to_vec();
        let path = core::str::from_utf8(&path_bytes).unwrap_or("");
        match crate::fs::ionafs::read(path) {
            None => -1,
            Some(data) => {
                let n = data.len().min(bc as usize);
                mem.data_mut(&mut caller)[bp as usize..bp as usize + n].copy_from_slice(&data[..n]);
                n as i32
            }
        }
    })?;

    // fs_write(path_ptr, path_len, data_ptr, data_len)
    linker.func_wrap("env", "fs_write", |caller: Caller<WasmState>, pp: i32, pl: i32, dp: i32, dl: i32| {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return,
        };
        let path_bytes = mem.data(&caller)[pp as usize..(pp + pl) as usize].to_vec();
        let data = mem.data(&caller)[dp as usize..(dp + dl) as usize].to_vec();
        let path = core::str::from_utf8(&path_bytes).unwrap_or("");
        crate::fs::ionafs::write(path, &data);
    })?;

    // fs_exists(path_ptr, path_len) -> 1 if exists, 0 otherwise
    linker.func_wrap("env", "fs_exists", |caller: Caller<WasmState>, pp: i32, pl: i32| -> i32 {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return 0,
        };
        let path_bytes = mem.data(&caller)[pp as usize..(pp + pl) as usize].to_vec();
        let path = core::str::from_utf8(&path_bytes).unwrap_or("");
        if crate::fs::ionafs::exists(path) { 1 } else { 0 }
    })?;

    // fs_delete(path_ptr, path_len) -> 1 if deleted, 0 otherwise
    linker.func_wrap("env", "fs_delete", |caller: Caller<WasmState>, pp: i32, pl: i32| -> i32 {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return 0,
        };
        let path_bytes = mem.data(&caller)[pp as usize..(pp + pl) as usize].to_vec();
        let path = core::str::from_utf8(&path_bytes).unwrap_or("");
        if crate::fs::ionafs::delete(path) { 1 } else { 0 }
    })?;

    Ok(())
}

// -----------------------------------------------------------------------------
// System functions
// -----------------------------------------------------------------------------

/// Register `get_uptime_ms`, `get_chain_rpc`, `spawn_module`.
fn register_system(linker: &mut Linker<WasmState>) -> Result<(), wasmi::Error> {
    // get_uptime_ms() -> uptime in milliseconds
    linker.func_wrap("env", "get_uptime_ms", |_caller: Caller<WasmState>| -> i64 {
        crate::arch::x86_64::timer::uptime_ms() as i64
    })?;

    // get_chain_rpc(ptr, capacity) -> bytes written (RPC endpoint URL)
    linker.func_wrap("env", "get_chain_rpc", |mut caller: Caller<WasmState>, ptr: i32, cap: i32| -> i32 {
        let url = crate::net::CHAIN_RPC_URL.lock().clone();
        let n = url.len().min(cap as usize);
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return 0,
        };
        mem.data_mut(&mut caller)[ptr as usize..ptr as usize + n].copy_from_slice(&url.as_bytes()[..n]);
        n as i32
    })?;

    // spawn_module(ptr, len) -> new task ID (i64), or -1 on error
    linker.func_wrap("env", "spawn_module", |caller: Caller<WasmState>, ptr: i32, len: i32| -> i64 {
        let mem = match caller.get_export("memory").and_then(|e| e.into_memory()) {
            Some(m) => m,
            None => return -1,
        };
        let bytes = mem.data(&caller)[ptr as usize..(ptr + len) as usize].to_vec();
        crate::wasm::spawn_module(&bytes).unwrap_or(u64::MAX) as i64
    })?;

    Ok(())
}
