//! WASM Runtime — wasmi interpreter (no_std + alloc)
//! Complete host function set for IONA OS kernel


pub mod supervisor;

pub mod host;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::Mutex;
use wasmi::{Engine, Linker, Module, Store};
use crate::task::{Task, TaskId, next_tid};

pub struct WasmState {
    pub tid:     TaskId,
    pub name:    String,
    pub storage: BTreeMap<Vec<u8>, Vec<u8>>,
    pub events:  Vec<(String, Vec<u8>)>,
    pub log_buf: Vec<String>,
}

impl WasmState {
    fn new(tid: TaskId, name: String) -> Self {
        Self { tid, name, storage: BTreeMap::new(), events: Vec::new(), log_buf: Vec::new() }
    }
}

static PENDING: Mutex<Vec<(TaskId, Vec<u8>)>> = Mutex::new(Vec::new());

pub fn spawn_module(bytecode: &[u8]) -> Result<TaskId, &'static str> {
    let bytes = bytecode.to_vec();
    let tid   = next_tid();
    crate::serial_println!("  [WASM] spawn tid={} ({} bytes)", tid, bytes.len());
    let task  = Task::new("wasm-module", wasm_task_fn, tid, 1);
    // Apply WASM seccomp sandbox policy
    crate::security::seccomp::set_wasm_policy(tid);
    crate::sched::SCHEDULER.lock().spawn(task);
    PENDING.lock().push((tid, bytes));
    Ok(tid)
}

fn wasm_task_fn(tid: u64) -> ! {
    let bytecode = loop {
        let mut p = PENDING.lock();
        if let Some(pos) = p.iter().position(|(t,_)| *t == tid) {
            break p.remove(pos).1;
        }
        drop(p);
        core::hint::spin_loop();
    };

    match run_module(tid, &bytecode) {
        Ok(())  => crate::serial_println!("  [WASM] tid={} finished", tid),
        Err(e)  => crate::serial_println!("  [WASM] tid={} error: {:?}", tid, e),
    }
    loop { x86_64::instructions::hlt(); }
}

/// WASM module resource limits
#[derive(Clone, Debug)]
pub struct WasmLimits {
    pub gas_limit:   u64,       // computation budget
    pub memory_pages: u32,      // max 64KB pages (default: 16 = 1MB)
    pub stack_depth:  u32,      // max call stack depth
    pub max_restarts: u32,
}

impl Default for WasmLimits {
    fn default() -> Self {
        Self { gas_limit: 10_000_000, memory_pages: 16, stack_depth: 512, max_restarts: 3 }
    }
}

fn run_module(tid: TaskId, bytecode: &[u8]) -> Result<(), wasmi::Error> {
    let engine = Engine::default();
    let module = Module::new(&engine, bytecode)?;
    let mut store = Store::new(&engine, WasmState::new(tid, "wasm".into()));
    let mut linker = Linker::<WasmState>::new(&engine);

    // Register all host functions
    host::register_all(&mut linker)?;

    // Apply memory limit
    store.limiter(|state: &mut WasmState| {
        Box::new(WasmResourceLimiter {
            max_memory_pages: state.gas_limit.min(16) as u32,
        })
    });
    let instance = linker.instantiate(&mut store, &module)?.start(&mut store)?;

    let run = instance.get_func(&store, "run")
        .or_else(|| instance.get_func(&store, "_start"))
        .or_else(|| instance.get_func(&store, "main"));

    match run {
        Some(f) => { f.call(&mut store, &[], &mut [])?; }
        None    => { crate::serial_println!("  [WASM] no entry point found"); }
    }
    Ok(())
}

/// WASM memory sandbox — validates that WASM module stays within bounds
pub fn wasm_memory_sandbox(ptr: u32, len: u32, module_mem_size: u32) -> bool {
    let end = ptr.saturating_add(len);
    if end > module_mem_size {
        crate::serial_println!("[WASM] sandbox violation: ptr={} len={} limit={}", ptr, len, module_mem_size);
        return false;
    }
    true
}

/// Host functions available to WASM modules
pub mod host_functions {
    /// wasm_print — print to serial from WASM
    pub fn wasm_print(ptr: u32, len: u32, mem: &[u8]) {
        if ptr as usize + len as usize > mem.len() { return; }
        let s = core::str::from_utf8(&mem[ptr as usize..(ptr+len) as usize]).unwrap_or("?");
        crate::serial_println!("[WASM] {}", s);
    }

    /// wasm_storage_get — read from WASM module KV store
    pub fn wasm_storage_get(key: &[u8]) -> Option<alloc::vec::Vec<u8>> {
        // Delegate to IONAFS under /wasm/storage/
        let path = alloc::format!("/wasm/storage/{}", alloc::string::String::from_utf8_lossy(key));
        crate::fs::ionafs::read(&path)
    }

    /// wasm_storage_set — write to WASM module KV store
    pub fn wasm_storage_set(key: &[u8], value: &[u8]) {
        let path = alloc::format!("/wasm/storage/{}", alloc::string::String::from_utf8_lossy(key));
        crate::fs::ionafs::write(&path, value);
    }

    /// wasm_block_height — get current consensus height
    pub fn wasm_block_height() -> u64 {
        crate::consensus::CONSENSUS_ENGINE.lock()
            .as_ref().map(|e| e.height).unwrap_or(0)
    }
}

/// Restart crashed WASM module
pub fn restart_module(name: &str) {
    crate::serial_println!("[WASM] restarting crashed module: {}", name);
    // Re-spawn task from IONAFS
    if let Some(wasm_bytes) = crate::fs::ionafs::read(&alloc::format!("/bin/{}.wasm", name)) {
        let _ = spawn_module(&wasm_bytes);
    }
}
