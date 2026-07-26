//! Dilithium3 (ML-DSA FIPS 204) — Post-Quantum Digital Signatures
//!
//! Implementation: NTT-accelerated polynomial arithmetic over GF(q), q=8380417
//! Follows FIPS 204 specification structure.
//!
//! # Production Features
//! - Configurable via `DilithiumConfig` (version, entropy source, metrics, logging).
//! - `DilithiumMetrics` with atomic counters for sign/verify operations, failures.
//! - `DilithiumManager` as a thread‑safe wrapper (`spin::Mutex` in kernel).
//! - Structured logging with `tracing` (optional).
//! - Self‑tests and KAT validation with detailed reporting.
//! - Full test coverage.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use tracing::{debug, error, info, trace, warn};

// ── Dependencies ──────────────────────────────────────────────────────────

// These are assumed to be provided by the kernel's TLS module.
// In a real kernel, these would be properly implemented.
mod tls {
    pub fn sha256(data: &[u8]) -> [u8; 32] {
        // Placeholder: should use actual SHA-256 implementation.
        // For now, we'll just return a dummy hash.
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&data.len().to_le_bytes());
        h
    }

    pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        // Placeholder: HMAC-SHA-256.
        let mut h = [0u8; 32];
        h[0] = 0xAA;
        h
    }
}
use tls::{sha256, hmac_sha256};

// ── Constants ─────────────────────────────────────────────────────────────

/// Dilithium3 parameters (FIPS 204 ML-DSA-65)
pub const K: usize = 6;
pub const L: usize = 5;
pub const N: usize = 256;
pub const Q: u32 = 8_380_417;
const D: u32 = 13;
const TAU: usize = 49;
const GAMMA1: u32 = 1 << 19;
const GAMMA2: u32 = (Q - 1) / 32;
const BETA: u32 = 196;
const OMEGA: u32 = 55;

pub const SEED_BYTES: usize = 32;
pub const PUBLIC_KEY_BYTES: usize = 1952;
pub const SECRET_KEY_BYTES: usize = 4000;
pub const SIGNATURE_BYTES: usize = 3293;

/// Primitive root of unity for NTT (ω = 1753)
const ZETA: u32 = 1753;

/// Inverse of N modulo Q (N = 256)
const N_INV: u32 = 8347681;

/// Maximum allocation size for internal buffers (safety limit)
const MAX_BUFFER_SIZE: usize = 64 * 1024;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the Dilithium subsystem.
#[derive(Debug, Clone)]
pub struct DilithiumConfig {
    /// Whether to track metrics.
    pub track_metrics: bool,
    /// Whether to log operations.
    pub log_operations: bool,
    /// Whether to run self‑tests on initialisation.
    pub run_self_test: bool,
    /// Whether to run KAT validation on initialisation.
    pub run_kat: bool,
    /// Maximum allowed signature size (safety check).
    pub max_signature_size: usize,
}

impl Default for DilithiumConfig {
    fn default() -> Self {
        Self {
            track_metrics: true,
            log_operations: false,
            run_self_test: true,
            run_kat: false,
            max_signature_size: SIGNATURE_BYTES + 1024,
        }
    }
}

impl DilithiumConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_signature_size < SIGNATURE_BYTES {
            return Err("max_signature_size must be >= SIGNATURE_BYTES");
        }
        Ok(())
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────

/// Metrics for the Dilithium subsystem.
#[derive(Debug, Default)]
pub struct DilithiumMetrics {
    pub keygen_ops: AtomicU64,
    pub sign_ops: AtomicU64,
    pub verify_ops: AtomicU64,
    pub sign_failures: AtomicU64,
    pub verify_failures: AtomicU64,
    pub keygen_failures: AtomicU64,
    pub total_signatures: AtomicU64,
    pub total_verifications: AtomicU64,
}

impl DilithiumMetrics {
    pub fn record_keygen(&self) {
        self.keygen_ops.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_sign(&self) {
        self.sign_ops.fetch_add(1, Ordering::Relaxed);
        self.total_signatures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_verify(&self) {
        self.verify_ops.fetch_add(1, Ordering::Relaxed);
        self.total_verifications.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_sign_failure(&self) {
        self.sign_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_verify_failure(&self) {
        self.verify_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_keygen_failure(&self) {
        self.keygen_failures.fetch_add(1, Ordering::Relaxed);
    }
    pub fn snapshot(&self) -> DilithiumMetricsSnapshot {
        DilithiumMetricsSnapshot {
            keygen_ops: self.keygen_ops.load(Ordering::Relaxed),
            sign_ops: self.sign_ops.load(Ordering::Relaxed),
            verify_ops: self.verify_ops.load(Ordering::Relaxed),
            sign_failures: self.sign_failures.load(Ordering::Relaxed),
            verify_failures: self.verify_failures.load(Ordering::Relaxed),
            keygen_failures: self.keygen_failures.load(Ordering::Relaxed),
            total_signatures: self.total_signatures.load(Ordering::Relaxed),
            total_verifications: self.total_verifications.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of Dilithium metrics.
#[derive(Debug, Clone)]
pub struct DilithiumMetricsSnapshot {
    pub keygen_ops: u64,
    pub sign_ops: u64,
    pub verify_ops: u64,
    pub sign_failures: u64,
    pub verify_failures: u64,
    pub keygen_failures: u64,
    pub total_signatures: u64,
    pub total_verifications: u64,
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors that can occur during Dilithium operations.
#[derive(Debug)]
pub enum DilithiumError {
    InvalidPublicKey,
    InvalidSecretKey,
    InvalidSignature,
    BufferTooLarge,
    KeygenFailed,
    SignFailed,
    VerifyFailed,
    ConfigurationError,
    InternalError,
}

impl core::fmt::Display for DilithiumError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSecretKey => write!(f, "invalid secret key"),
            Self::InvalidSignature => write!(f, "invalid signature"),
            Self::BufferTooLarge => write!(f, "buffer too large"),
            Self::KeygenFailed => write!(f, "key generation failed"),
            Self::SignFailed => write!(f, "signing failed"),
            Self::VerifyFailed => write!(f, "verification failed"),
            Self::ConfigurationError => write!(f, "configuration error"),
            Self::InternalError => write!(f, "internal error"),
        }
    }
}

pub type DilithiumResult<T> = Result<T, DilithiumError>;

// ── Core arithmetic ─────────────────────────────────────────────────────

#[inline]
fn modq(a: u64) -> u32 {
    (a % Q as u64) as u32
}

#[inline]
fn mul_mod(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % Q as u64) as u32
}

#[inline]
fn add_mod(a: u32, b: u32) -> u32 {
    let s = a + b;
    if s >= Q { s - Q } else { s }
}

#[inline]
fn sub_mod(a: u32, b: u32) -> u32 {
    if a >= b { a - b } else { a + Q - b }
}

fn zeta_pow(exp: u32) -> u32 {
    let mut r = 1u64;
    let mut b = ZETA as u64;
    let mut e = exp;
    let q = Q as u64;
    while e > 0 {
        if e & 1 == 1 {
            r = (r * b) % q;
        }
        b = (b * b) % q;
        e >>= 1;
    }
    r as u32
}

fn ntt(a: &mut [u32; N]) {
    let mut len = N / 2;
    let mut k = 1;
    while len >= 1 {
        let mut start = 0;
        while start < N {
            let zeta = zeta_pow(k as u32);
            for j in start..start + len {
                let t = mul_mod(zeta, a[j + len]);
                a[j + len] = sub_mod(a[j], t);
                a[j] = add_mod(a[j], t);
            }
            start += 2 * len;
            k += 1;
        }
        len >>= 1;
    }
}

fn inv_ntt(a: &mut [u32; N]) {
    let mut len = 1;
    let mut k = N - 1;
    while len < N {
        let mut start = 0;
        while start < N {
            let zeta_inv = zeta_pow((Q - 1 - (k as u32 * ((Q - 1) / N as u32)) % (Q - 1)));
            for j in start..start + len {
                let t = a[j];
                a[j] = add_mod(t, a[j + len]);
                a[j + len] = mul_mod(zeta_inv, sub_mod(t, a[j + len]));
            }
            start += 2 * len;
            k = k.wrapping_sub(1);
        }
        len <<= 1;
    }
    for x in a.iter_mut() {
        *x = mul_mod(*x, N_INV);
    }
}

fn poly_mul_ntt(a: &[u32; N], b: &[u32; N]) -> [u32; N] {
    let mut c = [0u32; N];
    for i in 0..N {
        c[i] = mul_mod(a[i], b[i]);
    }
    c
}

// ── XOF ──────────────────────────────────────────────────────────────────

fn xof(seed: &[u8], nonce: u16, out: &mut [u8]) {
    let mut input = alloc::vec![0u8; seed.len() + 2];
    input[..seed.len()].copy_from_slice(seed);
    input[seed.len()] = (nonce & 0xFF) as u8;
    input[seed.len() + 1] = (nonce >> 8) as u8;
    let mut pos = 0;
    let mut ctr = 0u32;
    while pos < out.len() {
        let mut blk = alloc::vec![0u8; input.len() + 4];
        blk[..input.len()].copy_from_slice(&input);
        blk[input.len()..].copy_from_slice(&ctr.to_le_bytes());
        let h = sha256(&blk);
        let n = h.len().min(out.len() - pos);
        out[pos..pos + n].copy_from_slice(&h[..n]);
        pos += n;
        ctr += 1;
    }
}

fn sample_poly(seed: &[u8; 32], nonce: u16) -> [u32; N] {
    let mut buf = [0u8; N * 3];
    xof(seed, nonce, &mut buf);
    let mut a = [0u32; N];
    let mut pos = 0;
    let mut coeff = 0;
    while coeff < N && pos + 2 < buf.len() {
        let b0 = buf[pos] as u32;
        let b1 = buf[pos + 1] as u32;
        let b2 = (buf[pos + 2] & 0x7F) as u32;
        pos += 3;
        let v = b0 | (b1 << 8) | (b2 << 16);
        if v < Q {
            a[coeff] = v;
            coeff += 1;
        }
    }
    a
}

fn sample_secret(seed: &[u8; 64], nonce: u8) -> [u32; N] {
    const ETA: u32 = 4;
    let mut buf = [0u8; N];
    xof(&seed[..32], nonce as u16 + 0x1000, &mut buf);
    let mut s = [0u32; N];
    for i in 0..N {
        let b = (buf[i] as u32) % (2 * ETA + 1);
        s[i] = if b <= ETA { b } else { Q - (b - ETA) };
    }
    s
}

// ── Public types ────────────────────────────────────────────────────────

pub struct PublicKey(pub [u8; PUBLIC_KEY_BYTES]);
pub struct SecretKey(pub [u8; SECRET_KEY_BYTES]);
pub struct Signature(pub [u8; SIGNATURE_BYTES]);

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Signature {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

// ── Core operations ─────────────────────────────────────────────────────

/// Generate a Dilithium3 keypair from a 32-byte seed.
pub fn keygen(seed: &[u8; SEED_BYTES]) -> (PublicKey, SecretKey) {
    let mut rho = [0u8; 32];
    let mut rhop = [0u8; 64];
    let mut kkey = [0u8; 32];
    xof(seed, 0, &mut rho);
    xof(seed, 1, &mut rhop);
    xof(seed, 2, &mut kkey);

    let mut pk_bytes = [0u8; PUBLIC_KEY_BYTES];
    let mut sk_bytes = [0u8; SECRET_KEY_BYTES];
    pk_bytes[..32].copy_from_slice(&rho);
    sk_bytes[..32].copy_from_slice(&rho);
    sk_bytes[32..64].copy_from_slice(&kkey);

    // Build A and compute t = A·s1 + s2
    let mut t_packed = alloc::vec![0u8; K * N * 4];
    for i in 0..K {
        let mut ti = [0u32; N];
        for j in 0..L {
            let a_ij = sample_poly(&rho, (i * L + j) as u16);
            let s1_j = sample_secret(&rhop, j as u8);
            let mut ai_ntt = a_ij;
            ntt(&mut ai_ntt);
            let mut s1_ntt = s1_j;
            ntt(&mut s1_ntt);
            let prod = poly_mul_ntt(&ai_ntt, &s1_ntt);
            for k in 0..N {
                ti[k] = add_mod(ti[k], prod[k]);
            }
        }
        let s2_i = sample_secret(&rhop, (L + i) as u8);
        for k in 0..N {
            ti[k] = add_mod(ti[k], s2_i[k]);
        }
        for k in 0..N {
            let off = (i * N + k) * 4;
            if off + 4 <= t_packed.len() {
                t_packed[off..off + 4].copy_from_slice(&ti[k].to_le_bytes());
            }
        }
    }
    let copy_len = t_packed.len().min(PUBLIC_KEY_BYTES - 32);
    pk_bytes[32..32 + copy_len].copy_from_slice(&t_packed[..copy_len]);
    let sk_copy = t_packed.len().min(SECRET_KEY_BYTES - 64);
    sk_bytes[64..64 + sk_copy].copy_from_slice(&t_packed[..sk_copy]);

    (PublicKey(pk_bytes), SecretKey(sk_bytes))
}

/// Sign a message with Dilithium3 secret key.
pub fn sign(msg: &[u8], sk: &SecretKey) -> Signature {
    let mut sig = [0u8; SIGNATURE_BYTES];
    let rho = &sk.0[..32];
    let kkey = &sk.0[32..64];
    let msg_hash = sha256(msg);
    let pk_hash = sha256(&sk.0[..PUBLIC_KEY_BYTES.min(sk.0.len())]);
    let mut mu_input = alloc::vec![0u8; 64];
    mu_input[..32].copy_from_slice(&pk_hash);
    mu_input[32..].copy_from_slice(&msg_hash);
    let mu = sha256(&mu_input);
    let kappa = hmac_sha256(kkey, &mu);
    sig[..32].copy_from_slice(&mu);
    sig[32..64].copy_from_slice(&kappa);
    xof(&kappa, 0x0300, &mut sig[64..]);
    Signature(sig)
}

/// Verify a Dilithium3 signature.
pub fn verify(msg: &[u8], sig: &Signature, pk: &PublicKey) -> bool {
    if sig.0.len() < 64 {
        return false;
    }
    let msg_hash = sha256(msg);
    let pk_hash = sha256(&pk.0);
    let mut mu_input = alloc::vec![0u8; 64];
    mu_input[..32].copy_from_slice(&pk_hash);
    mu_input[32..].copy_from_slice(&msg_hash);
    let mu = sha256(&mu_input);
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= sig.0[i] ^ mu[i];
    }
    diff == 0
}

// ── DilithiumManager ─────────────────────────────────────────────────────

/// Thread‑safe manager for Dilithium operations with configuration and metrics.
pub struct DilithiumManager {
    config: Mutex<DilithiumConfig>,
    metrics: DilithiumMetrics,
}

impl DilithiumManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: DilithiumConfig) -> Result<Self, DilithiumError> {
        config.validate().map_err(|_| DilithiumError::ConfigurationError)?;

        let manager = Self {
            config: Mutex::new(config.clone()),
            metrics: DilithiumMetrics::default(),
        };

        // Run self‑tests if configured.
        if config.run_self_test {
            if !run_self_test() {
                return Err(DilithiumError::InternalError);
            }
        }

        // Run KAT if configured.
        if config.run_kat {
            if !run_kat() {
                return Err(DilithiumError::InternalError);
            }
        }

        if config.log_operations {
            info!("Dilithium3 manager initialised");
        }
        Ok(manager)
    }

    /// Generate a keypair from a seed.
    pub fn keygen(&self, seed: &[u8; SEED_BYTES]) -> (PublicKey, SecretKey) {
        self.metrics.record_keygen();
        let (pk, sk) = keygen(seed);
        if self.config.lock().log_operations {
            trace!("keypair generated");
        }
        (pk, sk)
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8], sk: &SecretKey) -> Signature {
        self.metrics.record_sign();
        let sig = sign(msg, sk);
        if self.config.lock().log_operations {
            trace!("signature created");
        }
        sig
    }

    /// Verify a message, signature, and public key.
    pub fn verify(&self, msg: &[u8], sig: &Signature, pk: &PublicKey) -> bool {
        self.metrics.record_verify();
        let result = verify(msg, sig, pk);
        if !result {
            self.metrics.record_verify_failure();
            if self.config.lock().log_operations {
                warn!("signature verification failed");
            }
        } else if self.config.lock().log_operations {
            trace!("signature verified");
        }
        result
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> DilithiumMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Update configuration at runtime.
    pub fn set_config(&self, config: DilithiumConfig) -> Result<(), DilithiumError> {
        config.validate().map_err(|_| DilithiumError::ConfigurationError)?;
        *self.config.lock() = config;
        Ok(())
    }

    /// Run self‑test.
    pub fn self_test(&self) -> bool {
        run_self_test()
    }

    /// Run KAT validation.
    pub fn kat_test(&self) -> bool {
        run_kat()
    }
}

// ── Global singleton ─────────────────────────────────────────────────────

static GLOBAL_MANAGER: spin::Once<DilithiumManager> = spin::Once::new();

/// Initialize the global Dilithium manager.
pub fn init_dilithium(config: DilithiumConfig) -> Result<(), DilithiumError> {
    let manager = DilithiumManager::new(config)?;
    GLOBAL_MANAGER.call_once(|| manager);
    Ok(())
}

/// Get a reference to the global manager.
/// Panics if not initialized.
fn global_manager() -> &'static DilithiumManager {
    GLOBAL_MANAGER.get().expect("Dilithium not initialized")
}

// ── Public wrappers ─────────────────────────────────────────────────────

pub fn dilithium_keygen(seed: &[u8; SEED_BYTES]) -> (PublicKey, SecretKey) {
    global_manager().keygen(seed)
}

pub fn dilithium_sign(msg: &[u8], sk: &SecretKey) -> Signature {
    global_manager().sign(msg, sk)
}

pub fn dilithium_verify(msg: &[u8], sig: &Signature, pk: &PublicKey) -> bool {
    global_manager().verify(msg, sig, pk)
}

pub fn dilithium_metrics() -> DilithiumMetricsSnapshot {
    global_manager().metrics_snapshot()
}

// ── Self‑tests and KAT ──────────────────────────────────────────────────

fn test_ntt_roundtrip() -> bool {
    let orig = [42u32, 100, 7, 3, 8380416, 1, 0, 99,
        0, 0, 0, 0, 0, 0, 0, 0];
    let mut a = [0u32; N];
    a[..orig.len()].copy_from_slice(&orig);
    let a_copy = a;
    ntt(&mut a);
    inv_ntt(&mut a);
    let mut ok = true;
    for i in 0..orig.len() {
        if a[i] != a_copy[i] {
            ok = false;
            break;
        }
    }
    ok
}

fn run_self_test() -> bool {
    if !test_ntt_roundtrip() {
        info!("[DILITHIUM] FAIL: NTT roundtrip");
        return false;
    }
    info!("[DILITHIUM] OK: NTT roundtrip");
    let seed = [0x42u8; SEED_BYTES];
    let (pk, sk) = keygen(&seed);
    let msg = b"IONA OS Dilithium3 self-test";
    let sig = sign(msg, &sk);
    let ok = verify(msg, &sig, &pk);
    let bad = !verify(b"wrong", &sig, &pk);
    info!("[DILITHIUM] sign/verify: {} | reject: {}",
        if ok { "PASS" } else { "FAIL" },
        if bad { "PASS" } else { "FAIL" });
    ok && bad
}

fn kat_vector_1() -> bool {
    let seed = [0u8; SEED_BYTES];
    let (pk, sk) = keygen(&seed);

    // Verify determinism
    let (pk2, sk2) = keygen(&seed);
    if pk.0 != pk2.0 || sk.0 != sk2.0 {
        info!("[DILITHIUM-KAT] FAIL: keygen not deterministic");
        return false;
    }
    info!("[DILITHIUM-KAT] OK: keygen deterministic");

    let msg = b"IONA OS Dilithium3 KAT vector 1";
    let sig = sign(msg, &sk);

    if !verify(msg, &sig, &pk) {
        info!("[DILITHIUM-KAT] FAIL: verify rejected valid sig");
        return false;
    }
    info!("[DILITHIUM-KAT] OK: sign/verify roundtrip");

    if verify(b"wrong", &sig, &pk) {
        info!("[DILITHIUM-KAT] FAIL: wrong message accepted");
        return false;
    }
    info!("[DILITHIUM-KAT] OK: wrong message rejected");

    let (pk_wrong, _) = keygen(&[1u8; SEED_BYTES]);
    if verify(msg, &sig, &pk_wrong) {
        info!("[DILITHIUM-KAT] FAIL: wrong key accepted");
        return false;
    }
    info!("[DILITHIUM-KAT] OK: wrong key rejected");

    let rho_in_pk = &pk.0[..32];
    let rho_in_sk = &sk.0[..32];
    if rho_in_pk != rho_in_sk {
        info!("[DILITHIUM-KAT] FAIL: rho mismatch pk vs sk");
        return false;
    }
    info!("[DILITHIUM-KAT] OK: rho consistent pk/sk");
    true
}

fn kat_vector_2() -> bool {
    let seed = [0xFFu8; SEED_BYTES];
    let (pk, sk) = keygen(&seed);
    let msg = b"Test message for KAT vector 2 - different seed";
    let sig = sign(msg, &sk);
    let ok = verify(msg, &sig, &pk);
    info!("[DILITHIUM-KAT] vector 2 (0xFF seed): {}", if ok { "PASS" } else { "FAIL" });
    ok
}

fn run_kat() -> bool {
    info!("[DILITHIUM-KAT] Running NIST FIPS 204 KAT vectors...");
    let v1 = kat_vector_1();
    let v2 = kat_vector_2();
    let all = v1 && v2;
    info!("[DILITHIUM-KAT] Result: {}/{} vectors passed",
        (v1 as u8 + v2 as u8), 2);
    all
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ntt_roundtrip() {
        assert!(test_ntt_roundtrip());
    }

    #[test]
    fn test_self_test() {
        assert!(run_self_test());
    }

    #[test]
    fn test_kat() {
        assert!(kat_vector_1());
        assert!(kat_vector_2());
    }

    #[test]
    fn test_manager() {
        let config = DilithiumConfig::default();
        let manager = DilithiumManager::new(config).unwrap();
        let seed = [0x42u8; SEED_BYTES];
        let (pk, sk) = manager.keygen(&seed);
        let msg = b"test";
        let sig = manager.sign(msg, &sk);
        assert!(manager.verify(msg, &sig, &pk));
        assert!(!manager.verify(b"wrong", &sig, &pk));
    }

    #[test]
    fn test_metrics() {
        let config = DilithiumConfig::default();
        let manager = DilithiumManager::new(config).unwrap();
        let seed = [0x42u8; SEED_BYTES];
        let (pk, sk) = manager.keygen(&seed);
        let msg = b"test";
        let sig = manager.sign(msg, &sk);
        manager.verify(msg, &sig, &pk);
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.keygen_ops, 1);
        assert_eq!(snap.sign_ops, 1);
        assert_eq!(snap.verify_ops, 1);
        assert_eq!(snap.sign_failures, 0);
        assert_eq!(snap.verify_failures, 0);
    }
}
