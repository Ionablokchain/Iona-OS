//! Reconcile loop — aplică desired state de la chain
//! Port al iona-os reconcile, fără tokio

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use iona_syscall as sys;
use crate::supervisor::Supervisor;

/// Deployment manifest primit de la chain via HTTP
#[derive(Clone)]
pub struct DeployManifest {
    pub name:      String,
    pub wasm_path: String,   // path în IONAFS unde e stocat bytecode-ul
    pub max_gas:   u64,
    pub max_restarts: u32,
}

pub struct ReconcileEngine {
    /// Ce vrea chain-ul să ruleze (desired state)
    pub desired: Vec<DeployManifest>,
    /// Ce rulează actual
    pub running: BTreeMap<String, u64>, // name → pid
}

impl ReconcileEngine {
    pub fn new() -> Self {
        Self { desired: Vec::new(), running: BTreeMap::new() }
    }

    pub fn set_desired(&mut self, manifests: Vec<DeployManifest>) {
        self.desired = manifests;
    }

    /// Compară desired vs running și aplică diferențele
    pub fn reconcile_once(&mut self, sup: &mut Supervisor) {
        // START: servicii în desired dar nu în running
        for manifest in &self.desired.clone() {
            if !self.running.contains_key(&manifest.name) {
                match sup.deploy(&manifest.name, &manifest.wasm_path,
                                  manifest.max_gas, manifest.max_restarts) {
                    Ok(pid) => { self.running.insert(manifest.name.clone(), pid); }
                    Err(e)  => { sys::klog(&alloc::format!("[REC] deploy failed: {} — {}", manifest.name, e)); }
                }
            }
        }

        // STOP: servicii care nu mai sunt în desired
        let desired_names: Vec<String> = self.desired.iter().map(|m| m.name.clone()).collect();
        let to_stop: Vec<String> = self.running.keys()
            .filter(|n| !desired_names.contains(n))
            .cloned().collect();

        for name in to_stop {
            if let Some(&pid) = self.running.get(&name) {
                sup.kill(pid);
                self.running.remove(&name);
                sys::klog(&alloc::format!("[REC] stopped '{}'", name));
            }
        }
    }
}
