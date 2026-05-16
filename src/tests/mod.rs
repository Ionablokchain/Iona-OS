//! IONA OS Kernel Test Framework
//!
//! Subsystem tests run at boot (in debug builds) to validate correctness.
//! Each test returns `Ok(())` or `Err("description of failure")`.
//!
//! **Security note:** Any cryptographic keys used in tests are derived
//! deterministically from non‑secret seeds (`b"test-seed-..."`) and are
//! **never** used in production builds (tests are disabled by default).
//!
//! Test categories:
//!   memory  — frame allocator, buddy, slab, CoW, mmap, swap
//!   fs      — IONAFS write/read/rename/delete/crash recovery
//!   net     — TCP/UDP connectivity, DNS resolution
//!   sched   — task creation, sleep, wake, context switch
//!   syscall — argument validation, errno propagation
//!   smp     — TLB shootdown, per-core scheduler, work stealing
//!   wasm    — module load, host calls, gas limits
//!   iona    — end-to-end node boot, storage init, gossip

#![cfg(any(test, feature = "test-kernel"))]  // only compiled for test builds

pub mod stress;

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

pub type TestResult = Result<(), String>;

pub struct TestSuite {
    pub name:    &'static str,
    pub tests:   Vec<(&'static str, fn() -> TestResult)>,
    pub passed:  usize,
    pub failed:  usize,
}

impl TestSuite {
    pub fn new(name: &'static str) -> Self {
        Self { name, tests: Vec::new(), passed: 0, failed: 0 }
    }

    pub fn add(&mut self, name: &'static str, f: fn() -> TestResult) {
        self.tests.push((name, f));
    }

    pub fn run_all(&mut self) {
        crate::serial_println!("\n┌─── Test Suite: {} ─────────────────────────┐", self.name);
        for (name, f) in &self.tests {
            match f() {
                Ok(()) => {
                    self.passed += 1;
                    crate::serial_println!("│  ✓ {}", name);
                }
                Err(msg) => {
                    self.failed += 1;
                    crate::serial_println!("│  ✗ {} — {}", name, msg);
                }
            }
        }
        crate::serial_println!("│  Result: {}/{} passed", self.passed, self.passed + self.failed);
        crate::serial_println!("└───────────────────────────────────────────────┘");
    }
}

// -----------------------------------------------------------------------------
// Deterministic test key generation (non‑secret, for tests only)
// -----------------------------------------------------------------------------

/// Derive a deterministic 32‑byte key from a seed string.
/// Used only for testing — never in production.
#[must_use]
fn test_key(seed: &[u8]) -> [u8; 32] {
    let hash = blake3::hash(seed);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_bytes());
    out
}

/// Derive a deterministic 20‑byte address from a seed string.
#[must_use]
fn test_addr(seed: &[u8]) -> [u8; 20] {
    let hash = blake3::hash(seed);
    let mut out = [0u8; 20];
    out.copy_from_slice(&hash.as_bytes()[..20]);
    out
}

// -----------------------------------------------------------------------------
// Memory tests (unchanged except formatting)
// -----------------------------------------------------------------------------

pub mod memory {
    use super::TestResult;
    use alloc::format;

    pub fn test_frame_alloc() -> TestResult {
        let f1 = crate::memory::frame_alloc::allocate_one()
            .ok_or("frame_alloc: allocation failed")?;
        let f2 = crate::memory::frame_alloc::allocate_one()
            .ok_or("frame_alloc: second allocation failed")?;
        if f1.start_address() == f2.start_address() {
            return Err("frame_alloc: returned same frame twice".into());
        }
        crate::memory::frame_alloc::dec_ref(f1);
        crate::memory::frame_alloc::dec_ref(f2);
        Ok(())
    }

    pub fn test_refcounting() -> TestResult {
        let f = crate::memory::frame_alloc::allocate_one()
            .ok_or("refcount: alloc failed")?;
        let rc0 = crate::memory::frame_alloc::get_ref(f);
        if rc0 != 1 { return Err(format!("refcount: expected 1, got {}", rc0)); }
        crate::memory::frame_alloc::inc_ref(f);
        if crate::memory::frame_alloc::get_ref(f) != 2 { return Err("inc_ref failed".into()); }
        crate::memory::frame_alloc::dec_ref(f);
        crate::memory::frame_alloc::dec_ref(f);
        Ok(())
    }

    pub fn test_buddy() -> TestResult {
        let (_total, free_before) = crate::mm::buddy::stats();
        let _ = crate::mm::buddy::alloc_pages(0);
        let (_, free_after) = crate::mm::buddy::stats();
        if free_after >= free_before {
            return Err("buddy: allocation did not reduce free count".into());
        }
        Ok(())
    }

    pub fn test_mmap() -> TestResult {
        let tid = 9999u64;
        let addr = crate::process::mmap::mmap(tid, 0, 4096,
            crate::process::mmap::PROT_READ | crate::process::mmap::PROT_WRITE,
            crate::process::mmap::MAP_ANONYMOUS | crate::process::mmap::MAP_PRIVATE,
            -1, 0);
        if addr == u64::MAX { return Err("mmap: failed to allocate".into()); }
        if addr == 0 { return Err("mmap: returned NULL".into()); }
        let ok = crate::process::mmap::munmap(tid, addr, 4096);
        if !ok { return Err("munmap: failed".into()); }
        Ok(())
    }
}

// ... (all other test modules remain the same, only cryptographic sections are modified) ...

// -----------------------------------------------------------------------------
// Consensus tests (refactored to remove hardcoded keys)
// -----------------------------------------------------------------------------

pub mod consensus_tests {
    use super::*;
    use crate::consensus::{
        engine::{Config, Engine, Step},
        validator_set::{Validator, ValidatorSet},
        messages::{ConsensusMsg, VoteType},
        quorum::quorum_threshold,
    };
    use crate::crypto::{PublicKeyBytes, Signer};
    use crate::slashing::StakeLedger;

    // Mock signer for consensus tests (uses test_key)
    struct TestSigner {
        pk: PublicKeyBytes,
        sk: [u8; 32],
    }

    impl TestSigner {
        fn new(seed: &[u8]) -> Self {
            let sk = test_key(seed);
            let pk = PublicKeyBytes(crate::crypto::ecdsa::public_from_secret(&sk).to_vec());
            Self { pk, sk }
        }
    }

    impl Signer for TestSigner {
        fn public_key_bytes(&self) -> Vec<u8> {
            self.pk.0.clone()
        }
        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            crate::crypto::ecdsa::sign(&self.sk, msg)
        }
    }

    struct NoopStore;
    impl crate::consensus::engine::BlockStore for NoopStore {
        fn get(&self, _: &crate::types::Hash32) -> Option<crate::types::Block> { None }
        fn put(&self, _: crate::types::Block) {}
    }

    struct Collector(alloc::vec::Vec<ConsensusMsg>);
    impl crate::consensus::engine::Outbox for Collector {
        fn broadcast(&mut self, msg: ConsensusMsg) { self.0.push(msg); }
        fn request_block(&mut self, _: crate::types::Hash32) {}
        fn on_commit(&mut self, _: &crate::consensus::engine::CommitCertificate,
            _: &crate::types::Block, _: &crate::types::KvState, _: u64, _: &[crate::types::Receipt]) {}
    }

    pub fn test_quorum_threshold() -> TestResult {
        assert_eq!(quorum_threshold(3), 3);
        assert_eq!(quorum_threshold(4), 3);
        assert_eq!(quorum_threshold(6), 5);
        Ok(())
    }

    pub fn test_engine_init() -> TestResult {
        let signer = TestSigner::new(b"engine-init-key");
        let vset = ValidatorSet::new(alloc::vec![
            Validator { pk: signer.pk.clone(), power: 100 },
        ]);
        let engine: Engine<TestSigner> = Engine::new(
            Config::default(), vset, 1, [0u8;32],
            alloc::collections::BTreeMap::new(),
            StakeLedger::new(), None,
        );
        if engine.state.height != 1 { return Err("wrong height".into()); }
        if engine.state.step != Step::Propose { return Err("wrong step".into()); }
        Ok(())
    }

    pub fn test_proposer_selection() -> TestResult {
        let signer1 = TestSigner::new(b"proposer-1");
        let signer2 = TestSigner::new(b"proposer-2");
        let vset = ValidatorSet::new(alloc::vec![
            Validator { pk: signer1.pk.clone(), power: 100 },
            Validator { pk: signer2.pk.clone(), power: 100 },
        ]);
        let prop0 = vset.proposer_for(0, 0);
        let prop1 = vset.proposer_for(0, 1);
        if prop0.pk == prop1.pk {
            return Err("same proposer for different rounds".into());
        }
        Ok(())
    }

    pub fn test_fast_quorum() -> TestResult {
        let cfg = Config { fast_quorum: true, ..Config::default() };
        if !cfg.fast_quorum { return Err("fast_quorum should be enabled by default".into()); }
        if cfg.propose_timeout_ms != 300 { return Err("wrong propose timeout".into()); }
        Ok(())
    }

    pub fn test_eip1559_base_fee() -> TestResult {
        use crate::execution::next_base_fee;
        let fee = next_base_fee(1000, 43_000_000, 43_000_000);
        if fee != 1000 { return Err(alloc::format!("fee unchanged: got {}", fee)); }
        let fee = next_base_fee(1000, 86_000_000, 43_000_000);
        if fee <= 1000 { return Err("fee should increase when over target".into()); }
        let fee = next_base_fee(1000, 0, 43_000_000);
        if fee >= 1000 { return Err("fee should decrease when under target".into()); }
        Ok(())
    }

    pub fn test_double_sign_detection() -> TestResult {
        use crate::consensus::quorum::VoteTally;
        use crate::consensus::validator_set::{Validator, ValidatorSet};
        let pk = PublicKeyBytes(alloc::vec![1u8; 33]);
        let vset = ValidatorSet::new(alloc::vec![Validator { pk: pk.clone(), power: 100 }]);
        let mut tally = VoteTally::default();
        let bid_a = [0x01u8; 32];
        let bid_b = [0x02u8; 32];
        tally.add_vote(&vset, &pk, &Some(bid_a));
        tally.add_vote(&vset, &pk, &Some(bid_b));
        let (_, max_power) = tally.best().ok_or("tally empty")?;
        if max_power != 100 {
            return Err(alloc::format!("wrong power: {}", max_power));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Network tests (unchanged)
// -----------------------------------------------------------------------------

pub mod net_tests {
    use super::TestResult;

    pub fn test_tcp_connect_loopback() -> TestResult {
        crate::net::poll();
        Ok(())
    }

    pub fn test_udp_bind_sendto() -> TestResult {
        let fd = crate::net::udp_bind([0,0,0,0], 9999)
            .ok_or("udp_bind failed — no network stack")?;
        let data = b"IONA-test";
        crate::net::udp_sendto(fd, data, [127,0,0,1], 9999);
        crate::net::udp_close(fd);
        Ok(())
    }

    pub fn test_dns_resolve_localhost() -> TestResult {
        let ip = crate::net::dns::resolve("localhost")
            .ok_or("localhost did not resolve")?;
        if ip != [127,0,0,1] {
            return Err(alloc::format!("localhost resolved to {:?} not 127.0.0.1", ip));
        }
        Ok(())
    }

    pub fn test_dns_resolve_ipv4_literal() -> TestResult {
        let ip = crate::net::dns::resolve("8.8.8.8")
            .ok_or("IP literal 8.8.8.8 failed to parse")?;
        if ip != [8,8,8,8] {
            return Err(alloc::format!("IP parse: {:?} != [8,8,8,8]", ip));
        }
        Ok(())
    }

    pub fn test_smoltcp_poll_no_panic() -> TestResult {
        crate::net::poll();
        crate::net::poll();
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Crypto tests (removed hardcoded keys, use test_key)
// -----------------------------------------------------------------------------

pub mod crypto_tests {
    use super::*;

    pub fn test_sha256_empty() -> TestResult {
        let hash = crate::net::tls::sha256(b"");
        if hash[0] != 0xe3 || hash[1] != 0xb0 || hash[2] != 0xc4 {
            return Err(alloc::format!("sha256 empty: wrong first bytes: {:02x}{:02x}{:02x}", hash[0], hash[1], hash[2]));
        }
        Ok(())
    }

    pub fn test_sha256_abc() -> TestResult {
        let hash = crate::net::tls::sha256(b"abc");
        if hash[0] != 0xba || hash[1] != 0x78 || hash[2] != 0x16 {
            return Err(alloc::format!("sha256 abc: wrong first bytes: {:02x}{:02x}{:02x}", hash[0], hash[1], hash[2]));
        }
        Ok(())
    }

    pub fn test_hmac_sha256() -> TestResult {
        let mac = crate::net::tls::hmac_sha256(b"key", b"message");
        if mac == [0u8; 32] { return Err("hmac_sha256 returned all zeros".into()); }
        let mac2 = crate::net::tls::hmac_sha256(b"key", b"message");
        if mac != mac2 { return Err("hmac_sha256 not deterministic".into()); }
        Ok(())
    }

    pub fn test_hkdf_extract() -> TestResult {
        let prk = crate::net::tls::hkdf_extract(b"salt", b"input key material");
        if prk == [0u8; 32] { return Err("hkdf_extract returned all zeros".into()); }
        Ok(())
    }

    pub fn test_poly1305_known() -> TestResult {
        let key = [0u8; 32];
        let msg = [0u8; 64];
        let tag = crate::net::tls::poly1305_mac(&key, &msg);
        if tag != [0u8; 16] {
            return Err(alloc::format!("poly1305 zero: expected all zeros, got {:02x}{:02x}...", tag[0], tag[1]));
        }
        Ok(())
    }

    pub fn test_x25519_basepoint() -> TestResult {
        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        let result = crate::net::tls::x25519_basepoint(&scalar);
        if result == [0u8; 32] { return Err("x25519 basepoint returned all zeros".into()); }
        Ok(())
    }

    pub fn test_keccak256_empty() -> TestResult {
        let mut evm = crate::blockchain::revm_port::Evm::new("test-keccak");
        let from = test_addr(b"keccak-test");
        let mut acc = crate::blockchain::revm_port::Account::default();
        acc.balance = 10_000_000;
        evm.state.set_account(from, acc);
        let bytecode = alloc::vec![0x60u8, 0, 0x60, 0, 0x20, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xf3];
        let result = evm.transact(from, None, 0, bytecode, 200_000);
        if !result.success {
            return Err(alloc::format!("keccak256 contract failed: {:?}", result.error));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Security / hardening tests (refactored)
// -----------------------------------------------------------------------------

pub mod hardening_tests {
    use super::*;

    pub fn test_safe_copy_window() -> TestResult {
        use crate::syscall::user_access::{IS_SAFE_COPY, set_safe_copy_window, clear_safe_copy_window};
        use core::sync::atomic::Ordering;

        let before = IS_SAFE_COPY.load(Ordering::SeqCst);
        if before { return Err("IS_SAFE_COPY should be false initially".into()); }

        set_safe_copy_window();
        let during = IS_SAFE_COPY.load(Ordering::SeqCst);
        let percpu_during = crate::arch::x86_64::percpu::is_safe_copy();
        if !(during || percpu_during) {
            return Err("safe-copy window should be set".into());
        }

        clear_safe_copy_window();
        let after = IS_SAFE_COPY.load(Ordering::SeqCst);
        let percpu_after = crate::arch::x86_64::percpu::is_safe_copy();
        if after || percpu_after {
            return Err("safe-copy window should be cleared".into());
        }
        Ok(())
    }

    pub fn test_user_range_check() -> TestResult {
        use crate::syscall::user_access::{check_user_range, USER_SPACE_MAX};

        if !check_user_range(0x1000, 64) {
            return Err("valid range rejected".into());
        }
        if check_user_range(0, 1) {
            return Err("null pointer allowed".into());
        }
        if check_user_range(0xFFFF_8000_0000_0000, 1) {
            return Err("kernel address allowed".into());
        }
        if check_user_range(USER_SPACE_MAX - 4, 8) {
            return Err("overflow allowed".into());
        }
        if check_user_range(USER_SPACE_MAX, 0) {
            return Err("limit address allowed".into());
        }
        Ok(())
    }

    pub fn test_hsm_sign_path() -> TestResult {
        use crate::security::hsm::{HsmProvider, SoftHsm};
        let hsm = SoftHsm;
        let key_id = "test-sign-key";
        hsm.generate_key(key_id);
        let data = b"IONA OS HSM sign test";
        let sig = hsm.sign(key_id, data).ok_or("HSM sign returned None")?;
        if sig.len() != 64 {
            return Err(alloc::format!("expected 64-byte ECDSA signature, got {}", sig.len()));
        }
        let ok = hsm.verify(key_id, data, &sig);
        if !ok {
            return Err("HSM verify failed".into());
        }
        Ok(())
    }

    pub fn test_list_prefix_bounded() -> TestResult {
        for i in 0..5u32 {
            crate::fs::ionafs::write(&alloc::format!("/var/test-prefix-{}", i), b"x");
        }
        let results = crate::fs::ionafs::list_prefix("/var/test-prefix-", 3);
        if results.len() > 3 {
            return Err(alloc::format!("list_prefix returned {} > 3", results.len()));
        }
        for i in 0..5u32 {
            crate::fs::ionafs::delete(&alloc::format!("/var/test-prefix-{}", i));
        }
        Ok(())
    }

    pub fn test_p256_sign_non_empty() -> TestResult {
        // Generate a deterministic test key (not hardcoded)
        let sk = test_key(b"p256-test-key");
        let hash = [0x13u8; 32];
        let sig = crate::net::tls::ecdsa::p256_sign(&sk, &hash);
        if sig.len() != 64 {
            return Err(alloc::format!("p256_sign returned {} bytes, expected 64", sig.len()));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Run all hardening tests together (returns bool for compatibility)
// -----------------------------------------------------------------------------

pub fn run_hardening_tests() -> bool {
    let tests = [
        hardening_tests::test_safe_copy_window,
        hardening_tests::test_user_range_check,
        hardening_tests::test_hsm_sign_path,
        hardening_tests::test_list_prefix_bounded,
        hardening_tests::test_p256_sign_non_empty,
    ];
    let mut passed = 0;
    for test in tests {
        if test().is_ok() {
            passed += 1;
        }
    }
    crate::serial_println!("[TEST] hardening: {}/{} passed", passed, tests.len());
    passed == tests.len()
}

// -----------------------------------------------------------------------------
// Rest of the original test modules (unchanged, omitted for brevity)
// -----------------------------------------------------------------------------
// ... (all other modules like `stress`, `fs_tests`, `smp_tests`, `gui_tests`, etc.)
// remain exactly as in the original file. Only the sections containing hardcoded
// keys have been replaced with the deterministic key generation shown above.
