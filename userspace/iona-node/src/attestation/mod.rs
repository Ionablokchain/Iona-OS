//! Attestation — trimite starea nodului la chain
//! Port al iona-os attestation, fără tokio

use alloc::string::String;
use alloc::vec::Vec;
use iona_syscall as sys;
use crate::supervisor::Supervisor;
use crate::p2p::HttpClient;

pub struct AttestationBuilder {
    pub node_pk:    Vec<u8>,
    pub chain_url:  String,
    pub os_version: String,
}

impl AttestationBuilder {
    pub fn new(chain_url: String, os_version: String) -> Self {
        // Generăm o cheie naivă (în producție: ed25519 real)
        let node_pk = alloc::vec![0xABu8; 32];
        Self { node_pk, chain_url, os_version }
    }

    /// Construiește și trimite attestation la chain
    pub fn submit(&self, sup: &Supervisor, height: u64) -> bool {
        let running: Vec<u8> = sup.processes.values()
            .map(|e| {
                let s = alloc::format!("{}:{:?};", e.name, e.state);
                s.into_bytes()
            })
            .flatten()
            .collect();

        let body = alloc::format!(
            "{{\"node_pk\":\"{}\",\"height\":{},\"services\":\"{}\",\"os_version\":\"{}\"}}",
            hex_encode(&self.node_pk),
            height,
            core::str::from_utf8(&running).unwrap_or("?"),
            self.os_version,
        );

        let url = alloc::format!("{}/chain/attestation", self.chain_url);
        match HttpClient::post(&url, body.as_bytes()) {
            Ok(_)  => { sys::klog("[ATT] attestation submitted"); true }
            Err(e) => { sys::klog(&alloc::format!("[ATT] failed: {}", e)); false }
        }
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| alloc::format!("{:02x}", b)).collect()
}
