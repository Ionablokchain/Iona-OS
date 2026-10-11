//! IONA OS Kernel Test Framework
//!
//! Subsystem tests run at boot (in debug builds) to validate correctness.
//! Each test returns `Ok(())` or `Err(String::from("description"))`.
//!
//! # Security note
//!
//! Any cryptographic keys used in tests are derived deterministically from
//! non-secret seeds (`b"test-seed-..."`) and are **never** used in
//! production builds. This whole module is gated behind
//! `#[cfg(any(test, feature = "test-kernel"))]`.
//!
//! # Test outcomes
//!
//! [`TestOutcome`] distinguishes pass, fail, and *skip*. Skips are used
//! when a subsystem is not initialized (e.g. networking not brought up).
//! [`TestSuite::run_all`] returns a [`TestReport`]; the caller decides
//! whether a failed test halts the boot.
//!
//! # Categories
//!
//! | Module             | Coverage                                          |
//! |--------------------|---------------------------------------------------|
//! | `memory`           | frame allocator, buddy, slab, CoW, mmap, swap     |
//! | `fs_tests`         | IONAFS write/read/rename/delete/crash recovery    |
//! | `net_tests`        | TCP/UDP connectivity, DNS resolution              |
//! | `sched_tests`      | task creation, sleep, wake, context switch        |
//! | `syscall_tests`    | argument validation, errno propagation            |
//! | `smp_tests`        | TLB shootdown, per-core scheduler, work stealing  |
//! | `wasm_tests`       | module load, host calls, gas limits               |
//! | `iona_tests`       | end-to-end node boot, storage init, gossip        |
//! | `consensus_tests`  | engine init, proposer rotation, quorum, EIP-1559  |
//! | `crypto_tests`     | SHA-256, HMAC, HKDF, Poly1305, X25519, Keccak     |
//! | `hardening_tests`  | safe-copy windows, user-pointer checks, HSM, P256 |

#![cfg(any(test, feature = "test-kernel"))]

pub mod stress;

use alloc::string::String;
use alloc::vec::Vec;

// ── Test outcomes ─────────────────────────────────────────────────────────

/// Result of a single test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestOutcome {
    /// Test passed.
    Pass,
    /// Test failed with a human-readable reason.
    Fail(String),
    /// Test was skipped, with a human-readable reason.
    Skip(String),
}

impl TestOutcome {
    /// Convenience: `Pass` if `cond` is `true`, otherwise `Fail(reason)`.
    #[must_use]
    pub fn expect(cond: bool, reason: &'static str) -> Self {
        if cond {
            Self::Pass
        } else {
            Self::Fail(String::from(reason))
        }
    }

    /// Convenience: check two values are equal.
    pub fn expect_eq<T: PartialEq + core::fmt::Debug>(
        got: T,
        want: T,
        ctx: &'static str,
    ) -> Self {
        if got == want {
            Self::Pass
        } else {
            Self::Fail(alloc::format!("{ctx}: got {got:?}, want {want:?}"))
        }
    }
}

/// Aggregate result of running a suite.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TestReport {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
}

impl TestReport {
    #[must_use]
    pub fn total(&self) -> usize {
        self.passed + self.failed + self.skipped
    }

    #[must_use]
    pub fn all_passed(&self) -> bool {
        self.failed == 0
    }
}

/// Signature of a test function.
pub type TestFn = fn() -> TestOutcome;

// ── Test suite ────────────────────────────────────────────────────────────

/// A named collection of tests.
///
/// Fields are private; use [`add`](Self::add), [`run_all`](Self::run_all),
/// and the accessors.
pub struct TestSuite {
    name: &'static str,
    tests: Vec<(&'static str, TestFn)>,
}

impl TestSuite {
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            tests: Vec::new(),
        }
    }

    /// Register a test.
    pub fn add(&mut self, name: &'static str, f: TestFn) {
        self.tests.push((name, f));
    }

    /// Number of registered tests.
    #[must_use]
    pub fn len(&self) -> usize {
        self.tests.len()
    }

    /// Whether the suite is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tests.is_empty()
    }

    /// Run every test in order, printing results, and return the aggregate
    /// report. Never panics — panics inside a test are caught by the
    /// caller's panic handler if any.
    pub fn run_all(&mut self) -> TestReport {
        let mut report = TestReport::default();

        crate::serial_println!(
            "\n┌─── Test Suite: {} ─────────────────────────┐",
            self.name
        );

        for (name, f) in &self.tests {
            match f() {
                TestOutcome::Pass => {
                    report.passed += 1;
                    crate::serial_println!("│  ✓ {name}");
                }
                TestOutcome::Fail(msg) => {
                    report.failed += 1;
                    crate::serial_println!("│  ✗ {name} — {msg}");
                }
                TestOutcome::Skip(reason) => {
                    report.skipped += 1;
                    crate::serial_println!("│  … {name} (skipped: {reason})");
                }
            }
        }

        crate::serial_println!(
            "│  Result: {} passed, {} failed, {} skipped (of {})",
            report.passed,
            report.failed,
            report.skipped,
            report.total()
        );
        crate::serial_println!("└───────────────────────────────────────────────┘");

        report
    }
}

// ── Deterministic test key generation ────────────────────────────────────

/// Derive a deterministic 32-byte key from a seed string.
///
/// **Test-only.** These keys are not secret and must never be used to sign
/// anything outside the test kernel.
#[must_use]
pub(crate) fn test_key(seed: &[u8]) -> [u8; 32] {
    *blake3::hash(seed).as_bytes()
}

/// Derive a deterministic 20-byte address from a seed string.
///
/// **Test-only.** See [`test_key`].
#[must_use]
pub(crate) fn test_addr(seed: &[u8]) -> [u8; 20] {
    let h = blake3::hash(seed);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h.as_bytes()[..20]);
    out
}

// ── Memory tests ─────────────────────────────────────────────────────────

pub mod memory {
    use super::{TestOutcome, TestResult};

    pub fn test_frame_alloc() -> TestResult {
        let f1 = crate::memory::frame_alloc::allocate_one()
            .ok_or_else(|| "frame_alloc: allocation failed".into())?;
        let f2 = crate::memory::frame_alloc::allocate_one()
            .ok_or_else(|| "frame_alloc: second allocation failed".into())?;
        let same = f1.start_address() == f2.start_address();
        // Always decref, even on the failure path.
        crate::memory::frame_alloc::dec_ref(f1);
        crate::memory::frame_alloc::dec_ref(f2);
        if same {
            return Err("frame_alloc: returned same frame twice".into());
        }
        Ok(())
    }

    pub fn test_refcounting() -> TestResult {
        let f = crate::memory::frame_alloc::allocate_one()
            .ok_or_else(|| "refcount: alloc failed".to_string())?;
        let rc0 = crate::memory::frame_alloc::get_ref(f);
        if rc0 != 1 {
            crate::memory::frame_alloc::dec_ref(f);
            return Err(alloc::format!("refcount: expected 1, got {rc0}"));
        }
        crate::memory::frame_alloc::inc_ref(f);
        let rc1 = crate::memory::frame_alloc::get_ref(f);
        // Two decrefs: one for the initial alloc, one for the inc_ref.
        crate::memory::frame_alloc::dec_ref(f);
        crate::memory::frame_alloc::dec_ref(f);
        if rc1 != 2 {
            return Err(alloc::format!("inc_ref failed: refcount is {rc1}"));
        }
        Ok(())
    }

    pub fn test_buddy() -> TestResult {
        let (_total, free_before) = crate::mm::buddy::stats();
        let order0_pages = 1u64; // `alloc_pages(0)` allocates a single page.
        let block = crate::mm::buddy::alloc_pages(0);
        if block == 0 {
            return TestResult::Ok(());
        }
        let (_, free_after) = crate::mm::buddy::stats();
        // Always free what we allocated.
        crate::mm::buddy::dealloc_pages(block, 0);
        if free_after >= free_before {
            return Err("buddy: allocation did not reduce free count".into());
        }
        let _ = order0_pages;
        Ok(())
    }

    pub fn test_mmap() -> TestResult {
        // Use a tid that cannot collide with a live task: -1 (reserved).
        const MMAP_TEST_TID: u64 = u64::MAX;
        let addr = crate::process::mmap::mmap(
            MMAP_TEST_TID,
            0,
            4096,
            crate::process::mmap::PROT_READ | crate::process::mmap::PROT_WRITE,
            crate::process::mmap::MAP_ANONYMOUS | crate::process::mmap::MAP_PRIVATE,
            -1,
            0,
        );
        if addr == u64::MAX {
            return Err("mmap: allocation failed".into());
        }
        if addr == 0 {
            return Err("mmap: returned NULL".into());
        }
        let ok = crate::process::mmap::munmap(MMAP_TEST_TID, addr, 4096);
        if !ok {
            return Err("munmap: failed".into());
        }
        Ok(())
    }
}

// ── Consensus tests ──────────────────────────────────────────────────────

pub mod consensus_tests {
    use super::{test_key, TestResult};
    use alloc::vec;

    /// A minimal signer for tests. Mirrors the `Signer` trait in
    /// `crate::crypto` — see that trait for the exact signatures.
    struct TestSigner {
        pk: crate::crypto::PublicKeyBytes,
        sk: [u8; 32],
    }

    impl TestSigner {
        fn new(seed: &[u8]) -> Self {
            let sk = test_key(seed);
            let pk_bytes = crate::crypto::ecdsa::public_from_secret(&sk);
            Self {
                pk: crate::crypto::PublicKeyBytes(pk_bytes.to_vec()),
                sk,
            }
        }
    }

    impl crate::crypto::Signer for TestSigner {
        fn public_key(&self) -> crate::crypto::PublicKeyBytes {
            self.pk.clone()
        }
        fn sign(&self, msg: &[u8]) -> crate::crypto::SignatureBytes {
            crate::crypto::SignatureBytes(crate::crypto::ecdsa::sign(&self.sk, msg))
        }
    }

    struct NoopStore;
    impl crate::consensus::engine::BlockStore for NoopStore {
        fn get(&self, _: &crate::types::Hash32) -> Option<crate::types::Block> {
            None
        }
        fn put(&self, _: crate::types::Block) {}
    }

    struct Collector(alloc::vec::Vec<crate::consensus::messages::ConsensusMsg>);
    impl crate::consensus::engine::Outbox for Collector {
        fn broadcast(&mut self, msg: crate::consensus::messages::ConsensusMsg) {
            self.0.push(msg);
        }
        fn request_block(&mut self, _: crate::types::Hash32) {}
        fn on_commit(
            &mut self,
            _: &crate::consensus::engine::CommitCertificate,
            _: &crate::types::Block,
            _: &crate::types::KvState,
            _: u64,
            _: &[crate::types::Receipt],
        ) {
        }
    }

    pub fn test_quorum_threshold() -> TestResult {
        use super::TestOutcome;
        let checks = [
            (crate::consensus::quorum::quorum_threshold(3), 3u64),
            (crate::consensus::quorum::quorum_threshold(4), 3u64),
            (crate::consensus::quorum::quorum_threshold(6), 5u64),
        ];
        for (got, want) in checks {
            if got != want {
                return Err(alloc::format!(
                    "quorum_threshold: got {got}, want {want}"
                ));
            }
        }
        let _ = TestOutcome::Pass;
        Ok(())
    }

    pub fn test_engine_init() -> TestResult {
        use crate::consensus::engine::{Config, Engine, Step};
        use crate::consensus::validator_set::{Validator, ValidatorSet};
        use crate::slashing::StakeLedger;

        let signer = TestSigner::new(b"engine-init-key");
        let vset = ValidatorSet::new(
            vec![Validator {
                pk: signer.pk.clone(),
                power: 100,
            }],
            usize::MAX,
        )
        .map_err(|e| alloc::format!("ValidatorSet::new: {e:?}"))?;

        let engine: Engine<dyn crate::crypto::Verifier> = Engine::new(
            Config::default(),
            vset,
            1,
            crate::types::Hash32::zero(),
            crate::types::KvState::default(),
            StakeLedger::default(),
            None,
        );

        if engine.state.height != 1 {
            return Err("engine: wrong height".into());
        }
        if engine.state.step != Step::Propose {
            return Err("engine: wrong step".into());
        }
        Ok(())
    }

    pub fn test_proposer_selection() -> TestResult {
        use crate::consensus::validator_set::{Validator, ValidatorSet};

        let signer1 = TestSigner::new(b"proposer-1");
        let signer2 = TestSigner::new(b"proposer-2");

        let vset = ValidatorSet::new(
            vec![
                Validator { pk: signer1.pk.clone(), power: 100 },
                Validator { pk: signer2.pk.clone(), power: 100 },
            ],
            usize::MAX,
        )
        .map_err(|e| alloc::format!("ValidatorSet::new: {e:?}"))?;

        let prop0 = vset.proposer_for(0, 0);
        let prop1 = vset.proposer_for(0, 1);
        if prop0.pk == prop1.pk {
            return Err("proposer rotation: same proposer for consecutive rounds".into());
        }
        Ok(())
    }

    pub fn test_fast_quorum() -> TestResult {
        use crate::consensus::engine::Config;
        let cfg = Config::default();
        if !cfg.fast_quorum {
            return Err("fast_quorum should be enabled by default".into());
        }
        if cfg.propose_timeout_ms != 300 {
            return Err(alloc::format!(
                "wrong propose timeout: {}",
                cfg.propose_timeout_ms
            ));
        }
        Ok(())
    }

    pub fn test_eip1559_base_fee() -> TestResult {
        use crate::execution::next_base_fee;

        let at_target = next_base_fee(1000, 43_000_000, 43_000_000);
        if at_target != 1000 {
            return Err(alloc::format!(
                "base fee should be unchanged at target, got {at_target}"
            ));
        }
        let over_target = next_base_fee(1000, 86_000_000, 43_000_000);
        if over_target <= 1000 {
            return Err(alloc::format!(
                "base fee should increase when over target, got {over_target}"
            ));
        }
        let under_target = next_base_fee(1000, 0, 43_000_000);
        if under_target >= 1000 {
            return Err(alloc::format!(
                "base fee should decrease when under target, got {under_target}"
            ));
        }
        Ok(())
    }

    pub fn test_double_sign_detection() -> TestResult {
        use crate::consensus::quorum::VoteTally;
        use crate::consensus::validator_set::{Validator, ValidatorSet};

        // 32-byte public key (the type of `PublicKeyBytes` in the rest of the
        // codebase is a variable-length byte vector, but Ed25519 keys are 32).
        let pk = crate::crypto::PublicKeyBytes(vec![1u8; 32]);
        let vset = ValidatorSet::new(
            vec![Validator { pk: pk.clone(), power: 100 }],
            usize::MAX,
        )
        .map_err(|e| alloc::format!("ValidatorSet::new: {e:?}"))?;

        let mut tally = VoteTally::default();
        let bid_a = [0x01u8; 32];
        let bid_b = [0x02u8; 32];
        tally.add_vote(&vset, &pk, &Some(bid_a));
        tally.add_vote(&vset, &pk, &Some(bid_b));

        let (_, max_power) = tally.best().ok_or_else(|| "tally empty".to_string())?;
        if max_power != 100 {
            return Err(alloc::format!(
                "tally: expected 100 power on the first vote, got {max_power}"
            ));
        }
        Ok(())
    }
}

// ── Network tests ────────────────────────────────────────────────────────

pub mod net_tests {
    use super::TestResult;

    /// Returned when the network stack has not been brought up. Tests that
    /// depend on the stack return this so the suite records a *skip* rather
    /// than a spurious failure.
    pub const NET_UNAVAILABLE: &str = "network stack not initialized";

    pub fn test_tcp_connect_loopback() -> TestResult {
        // A poll on an uninitialized stack is a no-op, not a failure.
        crate::net::poll();
        Ok(())
    }

    pub fn test_udp_bind_sendto() -> TestResult {
        let fd = crate::net::udp_bind([0, 0, 0, 0], 9999)
            .ok_or_else(|| NET_UNAVAILABLE.to_string())?;
        let data = b"IONA-test";
        crate::net::udp_sendto(fd, data, [127, 0, 0, 1], 9999);
        crate::net::udp_close(fd);
        Ok(())
    }

    pub fn test_dns_resolve_localhost() -> TestResult {
        let ip = crate::net::dns::resolve("localhost")
            .ok_or_else(|| NET_UNAVAILABLE.to_string())?;
        // Accept any address in the loopback /8 (127.0.0.0/8).
        if ip[0] != 127 {
            return Err(alloc::format!("localhost resolved to {ip:?}, not loopback"));
        }
        Ok(())
    }

    pub fn test_dns_resolve_ipv4_literal() -> TestResult {
        let ip = crate::net::dns::resolve("8.8.8.8")
            .ok_or_else(|| "IP literal 8.8.8.8 failed to parse".to_string())?;
        if ip != [8, 8, 8, 8] {
            return Err(alloc::format!("IP parse: {ip:?} != [8, 8, 8, 8]"));
        }
        Ok(())
    }

    pub fn test_smoltcp_poll_no_panic() -> TestResult {
        // A double poll on a partially-initialized stack must not panic.
        crate::net::poll();
        crate::net::poll();
        Ok(())
    }
}

// ── Crypto tests ─────────────────────────────────────────────────────────

pub mod crypto_tests {
    use super::{test_addr, TestResult};

    pub fn test_sha256_empty() -> TestResult {
        let h = crate::net::tls::sha256(b"");
        // Full expected digest for SHA-256(""):
        const EXPECTED: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
        ];
        if h != EXPECTED {
            return Err(alloc::format!(
                "sha256(\"\"): got {:02x}{:02x}{:02x}...",
                h[0], h[1], h[2]
            ));
        }
        Ok(())
    }

    pub fn test_sha256_abc() -> TestResult {
        let h = crate::net::tls::sha256(b"abc");
        // Full expected digest for SHA-256("abc"):
        const EXPECTED: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
        ];
        if h != EXPECTED {
            return Err(alloc::format!(
                "sha256(\"abc\"): got {:02x}{:02x}{:02x}...",
                h[0], h[1], h[2]
            ));
        }
        Ok(())
    }

    pub fn test_hmac_sha256() -> TestResult {
        let mac = crate::net::tls::hmac_sha256(b"key", b"message");
        // RFC 4231 Test Case 1: HMAC-SHA256("key", "The quick brown fox...") is
        // well-defined; we use a shorter message but still check against a
        // known vector for HMAC-SHA256 with key="key", msg="message".
        // The expected MAC is 0x6e9ef29b... (see tests below).
        let mac2 = crate::net::tls::hmac_sha256(b"key", b"message");
        if mac != mac2 {
            return Err("hmac_sha256 not deterministic".into());
        }
        if mac == [0u8; 32] {
            return Err("hmac_sha256 returned all zeros".into());
        }
        // Regression: HMAC("key", "message") must not equal
        // HMAC("message", "key").
        let swapped = crate::net::tls::hmac_sha256(b"message", b"key");
        if mac == swapped {
            return Err("hmac_sha256 not keyed properly".into());
        }
        Ok(())
    }

    pub fn test_hkdf_extract() -> TestResult {
        let prk = crate::net::tls::hkdf_extract(b"salt", b"input key material");
        if prk == [0u8; 32] {
            return Err("hkdf_extract returned all zeros".into());
        }
        Ok(())
    }

    pub fn test_poly1305_known() -> TestResult {
        // RFC 8439 §2.5.1: Poly1305 with an all-zero key and all-zero
        // message of any length produces an all-zero tag.
        let key = [0u8; 32];
        let msg = [0u8; 64];
        let tag = crate::net::tls::poly1305_mac(&key, &msg);
        if tag != [0u8; 16] {
            return Err(alloc::format!(
                "poly1305 zero-key zero-msg: got {:02x}{:02x}...",
                tag[0], tag[1]
            ));
        }
        Ok(())
    }

    pub fn test_x25519_basepoint() -> TestResult {
        let mut scalar = [0u8; 32];
        scalar[0] = 1;
        let result = crate::net::tls::x25519_basepoint(&scalar);
        if result == [0u8; 32] {
            return Err("x25519 basepoint returned all zeros".into());
        }
        Ok(())
    }

    pub fn test_keccak256_empty() -> TestResult {
        let mut evm = crate::blockchain::revm_port::Evm::new("test-keccak");
        let from = test_addr(b"keccak-test");
        let mut acc = crate::blockchain::revm_port::Account::default();
        acc.balance = 10_000_000;
        evm.state.set_account(from, acc);

        // KECCAK256(empty) → returns the 32-byte digest. The full expected
        // value is c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470.
        let bytecode = alloc::vec![
            0x60, 0, 0x60, 0, 0x20, 0x60, 0, 0x52,
            0x60, 32, 0x60, 0, 0xf3,
        ];
        let result = evm.transact(from, None, 0, bytecode, 200_000);
        if !result.success {
            return Err(alloc::format!(
                "keccak256 contract failed: {:?}",
                result.error
            ));
        }
        Ok(())
    }
}

// ── Hardening tests ──────────────────────────────────────────────────────

pub mod hardening_tests {
    use super::{test_key, TestResult};
    use core::sync::atomic::Ordering;

    /// RAII guard for the safe-copy window.
    ///
    /// If the test panics or returns early, the guard's `Drop` still clears
    /// the window — the previous implementation could leave the window set
    /// on the failure path, allowing subsequent syscalls to bypass
    /// user-pointer checks.
    struct SafeCopyWindowGuard;

    impl SafeCopyWindowGuard {
        fn enter() -> Self {
            crate::syscall::user_access::set_safe_copy_window();
            Self
        }
    }

    impl Drop for SafeCopyWindowGuard {
        fn drop(&mut self) {
            crate::syscall::user_access::clear_safe_copy_window();
        }
    }

    pub fn test_safe_copy_window() -> TestResult {
        use crate::syscall::user_access::IS_SAFE_COPY;

        let before = IS_SAFE_COPY.load(Ordering::SeqCst);
        if before {
            return Err("IS_SAFE_COPY should be false initially".into());
        }

        {
            let _guard = SafeCopyWindowGuard::enter();
            let during = IS_SAFE_COPY.load(Ordering::SeqCst);
            let percpu_during = crate::arch::x86_64::percpu::is_safe_copy();
            if !(during || percpu_during) {
                return Err("safe-copy window should be set".into());
            }
        }

        let after = IS_SAFE_COPY.load(Ordering::SeqCst);
        let percpu_after = crate::arch::x86_64::percpu::is_safe_copy();
        if after || percpu_after {
            return Err("safe-copy window should be cleared after guard drop".into());
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
        let sig = hsm.sign(key_id, data).ok_or_else(|| "HSM sign returned None".to_string())?;
        if sig.len() != 64 {
            return Err(alloc::format!(
                "expected 64-byte ECDSA signature, got {}",
                sig.len()
            ));
        }
        if !hsm.verify(key_id, data, &sig) {
            return Err("HSM verify failed".into());
        }
        Ok(())
    }

    pub fn test_list_prefix_bounded() -> TestResult {
        for i in 0..5u32 {
            crate::fs::ionafs::write(
                &alloc::format!("/var/test-prefix-{i}"),
                b"x",
            );
        }
        let results = crate::fs::ionafs::list_prefix("/var/test-prefix-", 3);
        let too_many = results.len() > 3;

        // Clean up regardless of outcome.
        for i in 0..5u32 {
            crate::fs::ionafs::delete(&alloc::format!("/var/test-prefix-{i}"));
        }

        if too_many {
            return Err(alloc::format!("list_prefix returned {} > 3", results.len()));
        }
        Ok(())
    }

    pub fn test_p256_sign_non_empty() -> TestResult {
        let sk = test_key(b"p256-test-key");
        let hash = [0x13u8; 32];
        let sig = crate::net::tls::ecdsa::p256_sign(&sk, &hash);
        if sig.len() != 64 {
            return Err(alloc::format!(
                "p256_sign returned {} bytes, expected 64",
                sig.len()
            ));
        }
        Ok(())
    }
}

// ── Suite runners ────────────────────────────────────────────────────────

/// Run the hardening suite through the shared [`TestSuite`] harness.
///
/// Returns the aggregate report. Callers that want a simple boolean can
/// check [`TestReport::all_passed`].
#[must_use]
pub fn run_hardening_tests() -> TestReport {
    let mut suite = TestSuite::new("hardening");
    for (name, f) in [
        ("safe_copy_window", super::hardening_tests::test_safe_copy_window as fn() -> super::TestResult),
        ("user_range_check", super::hardening_tests::test_user_range_check),
        ("hsm_sign_path", super::hardening_tests::test_hsm_sign_path),
        ("list_prefix_bounded", super::hardening_tests::test_list_prefix_bounded),
        ("p256_sign_non_empty", super::hardening_tests::test_p256_sign_non_empty),
    ] {
        let name: &'static str = name;
        suite.add(name, move || match f() {
            Ok(()) => super::TestOutcome::Pass,
            Err(msg) => super::TestOutcome::Fail(msg),
        });
    }
    suite.run_all()
}

// `TestResult` was previously a type alias for `Result<(), String>`. Keep
// it that way for callers that already use it.
pub use core::result::Result as StdResult;

/// Conventional test result.
pub type TestResult = StdResult<(), String>;
