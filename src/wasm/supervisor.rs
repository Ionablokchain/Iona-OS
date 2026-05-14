//! WASM Module Supervisor — lifecycle complet
//! Monitors modules, enforces limits, handles crashes + restart
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use spin::{Lazy, Mutex};
use crate::task::TaskId;

#[derive(Debug, Clone, PartialEq)]
pub enum ModuleState {
    Running,
    Stopped,
    Crashed { reason: String },
    GasExhausted,
    MemoryLimitExceeded,
    Restarting { attempt: u32 },
}

pub struct ModuleEntry {
    pub tid:         TaskId,
    pub name:        String,
    pub wasm_path:   String,
    pub state:       ModuleState,
    pub gas_used:    u64,
    pub gas_limit:   u64,
    pub mem_pages:   u32,
    pub mem_limit:   u32,
    pub restarts:    u32,
    pub max_restarts: u32,
    pub started_ms:  u64,
}

static MODULES: Lazy<Mutex<BTreeMap<TaskId, ModuleEntry>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

pub fn register(tid: TaskId, name: &str, path: &str, gas_limit: u64, mem_limit: u32, max_restarts: u32) {
    MODULES.lock().insert(tid, ModuleEntry {
        tid, name: name.into(), wasm_path: path.into(),
        state: ModuleState::Running,
        gas_used: 0, gas_limit, mem_pages: 0, mem_limit,
        restarts: 0, max_restarts,
        started_ms: crate::arch::x86_64::timer::uptime_ms(),
    });
    crate::serial_println!("  [WSUP] registered '{}' tid={} gas={} mem={}p",
        name, tid, gas_limit, mem_limit);
}

pub fn charge_gas(tid: TaskId, amount: u64) -> bool {
    let mut mods = MODULES.lock();
    let entry    = match mods.get_mut(&tid) { Some(e) => e, None => return true };
    entry.gas_used = entry.gas_used.saturating_add(amount);
    if entry.gas_used > entry.gas_limit {
        entry.state = ModuleState::GasExhausted;
        crate::serial_println!("  [WSUP] tid={} gas exhausted", tid);
        return false;
    }
    true
}

pub fn report_crash(tid: TaskId, reason: &str) {
    let mut mods  = MODULES.lock();
    let entry     = match mods.get_mut(&tid) { Some(e) => e, None => return };
    entry.state   = ModuleState::Crashed { reason: reason.into() };
    crate::serial_println!("  [WSUP] tid={} crashed: {}", tid, reason);

    if entry.restarts < entry.max_restarts {
        entry.restarts += 1;
        let path = entry.wasm_path.clone();
        let name = entry.name.clone();
        let gl   = entry.gas_limit;
        let ml   = entry.mem_limit;
        let mr   = entry.max_restarts;
        let attempt = entry.restarts;
        entry.state = ModuleState::Restarting { attempt };
        drop(mods);

        crate::serial_println!("  [WSUP] restarting '{}' attempt {}", name, attempt);
        if let Some(bytecode) = crate::fs::ionafs::read(&path) {
            if let Ok(new_tid) = crate::wasm::spawn_module(&bytecode) {
                register(new_tid, &name, &path, gl, ml, mr);
            }
        }
    }
}

pub fn get_state(tid: TaskId) -> Option<ModuleState> {
    MODULES.lock().get(&tid).map(|e| e.state.clone())
}

pub fn list_running() -> Vec<(TaskId, String)> {
    MODULES.lock().iter()
        .filter(|(_, e)| e.state == ModuleState::Running)
        .map(|(tid, e)| (*tid, e.name.clone()))
        .collect()
}

/// Tick — called periodically to check module health
pub fn tick() {
    let tids: Vec<TaskId> = MODULES.lock().keys().cloned().collect();
    for tid in tids {
        let state = {
            let mods = MODULES.lock();
            mods.get(&tid).map(|e| e.state.clone())
        };
        // Check if scheduler task still alive
        let alive = {
            let s = crate::sched::SCHEDULER.lock();
            s.stats().current_tid == Some(tid)
                || s.stats().blocked_count > 0 // may be blocked
        };
        if !alive {
            if let Some(ModuleState::Running) = state {
                report_crash(tid, "task not found in scheduler");
            }
        }
    }
}
