
//! HSM (Hardware Security Module) providers
//! Backend-uri:
//!   SoftHsm — kernel-side HSM:
//!     • sign/verify: ECDSA P-256 RFC 6979 (standard-compatible, 64-byte sig)
//!     • encrypt/decrypt: ChaCha20-Poly1305 with random nonce
//!     • No HMAC fallback — sign returns None if key derivation fails
//!   PKCS11/AWS KMS/Azure Key Vault — interface stubs (log + SoftHsm delegate)
//!     • Not wired to real hardware/cloud yet — requires network HSM driver
//!     • Design is correct; implementation is placeholder
//!
//! Interfața unificată: HsmProvider trait
//! Selectarea backend-ului: din /etc/iona-node.json hsm_backend field

use alloc::{string::String, vec::Vec, format, boxed::Box};

/// Operații HSM comune
pub trait HsmProvider: Send + Sync {
    fn name(&self)                                   -> &'static str;
    fn sign(&self, key_id: &str, data: &[u8])       -> Option<Vec<u8>>;
    fn verify(&self, key_id: &str, data: &[u8], sig: &[u8]) -> bool;
    fn encrypt(&self, key_id: &str, plain: &[u8])   -> Option<Vec<u8>>;
    fn decrypt(&self, key_id: &str, cipher: &[u8])  -> Option<Vec<u8>>;
    fn generate_key(&self, id: &str)                 -> bool;
    fn health_check(&self)                           -> bool;
}

// ── Backend 1: Software (kernel keystore) ──────────────────────────────────
pub struct SoftHsm;
impl HsmProvider for SoftHsm {
    fn name(&self) -> &'static str { "soft-hsm" }
    fn sign(&self, key_id: &str, data: &[u8]) -> Option<Vec<u8>> {
        let key = crate::security::keystore::load(key_id)?;
        let ecdsa_key = derive_ecdsa_key(&key)?;
        // Standard ECDSA P-256 sign (RFC 6979 deterministic k).
        // Signature is 64 bytes (r||s) compatible with standard P-256 verifiers.
        let hash = crate::net::tls::sha256(data);
        let sig  = crate::net::tls::ecdsa::p256_sign(&ecdsa_key, &hash);
        if sig.len() == 64 { Some(sig) } else { None }
    }
    fn verify(&self, key_id: &str, data: &[u8], sig: &[u8]) -> bool {
        let Some(key) = crate::security::keystore::load(key_id) else { return false };
        let Some(ecdsa_key) = derive_ecdsa_key(&key) else { return false };
        if sig.len() < 64 { return false; }
        let hash = crate::net::tls::sha256(data);
        crate::net::tls::ecdsa::p256_verify_raw(&ecdsa_key, &hash, sig)
    }
    fn encrypt(&self, key_id: &str, plain: &[u8]) -> Option<Vec<u8>> {
        let key = crate::security::keystore::load(key_id)?;
        let key32: [u8;32] = key[..32].try_into().ok()?;
        // Generate random nonce from hardware entropy
        let nonce = random_nonce_12();
        let ciphertext = crate::net::tls::Aead::new(key32).seal(&nonce, &[], plain);
        // Prepend nonce (12B) to ciphertext so decrypt can recover it
        let mut out = alloc::vec![0u8; 12 + ciphertext.len()];
        out[..12].copy_from_slice(&nonce);
        out[12..].copy_from_slice(&ciphertext);
        Some(out)
    }
    fn decrypt(&self, key_id: &str, cipher: &[u8]) -> Option<Vec<u8>> {
        if cipher.len() < 12 { return None; }
        let key = crate::security::keystore::load(key_id)?;
        let key32: [u8;32] = key[..32].try_into().ok()?;
        // Extract prepended nonce
        let nonce: [u8;12] = cipher[..12].try_into().ok()?;
        crate::net::tls::Aead::new(key32).open(&nonce, &[], &cipher[12..])
    }
    fn generate_key(&self, id: &str) -> bool {
        let ts = crate::arch::x86_64::timer::uptime_ms();
        let mut key = [0u8; 32];
        for (i,b) in key.iter_mut().enumerate() { *b = ((ts >> (i%8)) ^ ts) as u8; }
        crate::security::keystore::store(id, "HSM-generated", crate::security::keystore::KeyType::Raw32, &key)
    }
    fn health_check(&self) -> bool { crate::security::keystore::is_unlocked() }
}

// ── Backend 2: PKCS#11 (hardware token — YubiKey, Nitrokey, etc.) ──────────
pub struct Pkcs11Hsm {
    pub slot: u32,
    pub pin:  String,
}
impl HsmProvider for Pkcs11Hsm {
    fn name(&self) -> &'static str { "pkcs11" }
    fn sign(&self, key_id: &str, data: &[u8]) -> Option<Vec<u8>> {
        // Production: send CKM_ECDSA via USB/PCIe PKCS#11 device
        // Kernel-mode: use SoftHsm fallback until hardware driver ready
        crate::serial_println!("[HSM/PKCS11] sign key={} (slot {})", key_id, self.slot);
        SoftHsm.sign(key_id, data)
    }
    fn verify(&self, key_id: &str, data: &[u8], sig: &[u8]) -> bool {
        SoftHsm.verify(key_id, data, sig)
    }
    fn encrypt(&self, key_id: &str, plain: &[u8])  -> Option<Vec<u8>> { SoftHsm.encrypt(key_id, plain) }
    fn decrypt(&self, key_id: &str, cipher: &[u8]) -> Option<Vec<u8>> { SoftHsm.decrypt(key_id, cipher) }
    fn generate_key(&self, id: &str) -> bool { SoftHsm.generate_key(id) }
    fn health_check(&self) -> bool {
        // Production: CK_GetSlotInfo + CK_GetMechanismInfo
        crate::serial_println!("[HSM/PKCS11] health check slot={}", self.slot);
        true
    }
}

// ── Backend 3: AWS KMS ────────────────────────────────────────────────────
pub struct AwsKmsHsm {
    pub key_arn:  String,
    pub region:   String,
    pub endpoint: String,  // e.g. "kms.eu-west-1.amazonaws.com"
}
impl HsmProvider for AwsKmsHsm {
    fn name(&self) -> &'static str { "aws-kms" }
    fn sign(&self, key_id: &str, data: &[u8]) -> Option<Vec<u8>> {
        // Production: HTTPS POST to AWS KMS Sign API
        // requires TLS + AWS Sig V4 signing
        crate::serial_println!("[HSM/AWS-KMS] sign key={} arn={}", key_id, self.key_arn);
        // Fallback until network HSM client implemented
        SoftHsm.sign(key_id, data)
    }
    fn verify(&self, key_id: &str, data: &[u8], sig: &[u8]) -> bool { SoftHsm.verify(key_id, data, sig) }
    fn encrypt(&self, key_id: &str, plain: &[u8])  -> Option<Vec<u8>> {
        crate::serial_println!("[HSM/AWS-KMS] encrypt key={}", key_id);
        SoftHsm.encrypt(key_id, plain)
    }
    fn decrypt(&self, key_id: &str, cipher: &[u8]) -> Option<Vec<u8>> { SoftHsm.decrypt(key_id, cipher) }
    fn generate_key(&self, id: &str) -> bool { SoftHsm.generate_key(id) }
    fn health_check(&self) -> bool {
        // Production: describe-key API call
        if !crate::net::is_ready() { return false; }
        crate::serial_println!("[HSM/AWS-KMS] health check endpoint={}", self.endpoint);
        true
    }
}

// ── Backend 4: Azure Key Vault ───────────────────────────────────────────────
pub struct AzureKeyVaultHsm {
    pub vault_url: String,
    pub key_name:  String,
    pub tenant_id: String,
}
impl HsmProvider for AzureKeyVaultHsm {
    fn name(&self) -> &'static str { "azure-key-vault" }
    fn sign(&self, key_id: &str, data: &[u8]) -> Option<Vec<u8>> {
        crate::serial_println!("[HSM/AZURE-KV] sign key={} vault={}", key_id, self.vault_url);
        SoftHsm.sign(key_id, data)
    }
    fn verify(&self, key_id: &str, data: &[u8], sig: &[u8]) -> bool { SoftHsm.verify(key_id, data, sig) }
    fn encrypt(&self, key_id: &str, plain: &[u8])  -> Option<Vec<u8>> { SoftHsm.encrypt(key_id, plain) }
    fn decrypt(&self, key_id: &str, cipher: &[u8]) -> Option<Vec<u8>> { SoftHsm.decrypt(key_id, cipher) }
    fn generate_key(&self, id: &str) -> bool { SoftHsm.generate_key(id) }
    fn health_check(&self) -> bool {
        if !crate::net::is_ready() { return false; }
        crate::serial_println!("[HSM/AZURE-KV] health check vault={}", self.vault_url);
        true
    }
}

// ── Active HSM instance (configurabil din /etc/iona-node.json) ─────────────
use spin::{Lazy, Mutex};

pub static ACTIVE_HSM: Lazy<Mutex<Box<dyn HsmProvider>>> =
    Lazy::new(|| Mutex::new(Box::new(SoftHsm)));

/// Configure HSM backend from string identifier
pub fn configure(backend: &str) {
    match backend {
        "pkcs11" => {
            *ACTIVE_HSM.lock() = Box::new(Pkcs11Hsm { slot: 0, pin: alloc::string::String::new() });
            crate::serial_println!("[HSM] backend: PKCS#11");
        }
        "aws-kms" => {
            *ACTIVE_HSM.lock() = Box::new(AwsKmsHsm {
                key_arn:  "arn:aws:kms:eu-west-1:000000000000:key/iona-validator".into(),
                region:   "eu-west-1".into(),
                endpoint: "kms.eu-west-1.amazonaws.com".into(),
            });
            crate::serial_println!("[HSM] backend: AWS KMS");
        }
        "azure-key-vault" => {
            *ACTIVE_HSM.lock() = Box::new(AzureKeyVaultHsm {
                vault_url: "https://iona-vault.vault.azure.net".into(),
                key_name:  "validator-key".into(),
                tenant_id: "".into(),
            });
            crate::serial_println!("[HSM] backend: Azure Key Vault");
        }
        _ => {
            *ACTIVE_HSM.lock() = Box::new(SoftHsm);
            crate::serial_println!("[HSM] backend: SoftHSM (kernel keystore)");
        }
    }
}

/// Sign with active HSM
pub fn sign(key_id: &str, data: &[u8]) -> Option<Vec<u8>> { ACTIVE_HSM.lock().sign(key_id, data) }
/// Verify with active HSM
pub fn verify(key_id: &str, data: &[u8], sig: &[u8]) -> bool { ACTIVE_HSM.lock().verify(key_id, data, sig) }
/// Encrypt with active HSM
pub fn encrypt(key_id: &str, plain: &[u8]) -> Option<Vec<u8>> { ACTIVE_HSM.lock().encrypt(key_id, plain) }
/// Decrypt with active HSM
pub fn decrypt(key_id: &str, cipher: &[u8]) -> Option<Vec<u8>> { ACTIVE_HSM.lock().decrypt(key_id, cipher) }
/// Health check
pub fn health_check() -> bool { ACTIVE_HSM.lock().health_check() }

/// Generate a random 12-byte nonce for AEAD using hardware entropy
fn random_nonce_12() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    let ts = crate::arch::x86_64::timer::uptime_ms();
    // Use safe rng wrapper (checks CPUID before executing rdrand)
    let rng = crate::security::rng::random_u64();
    let mixed = rng ^ ts.rotate_left(17) ^ 0xCA_FE_BA_BE_DE_AD_BE_EFu64;
    nonce[..8].copy_from_slice(&mixed.to_le_bytes());
    nonce[8..].copy_from_slice(&(ts as u32).to_le_bytes());
    nonce
}

/// Derive a 32-byte ECDSA private key scalar from a master key
fn derive_ecdsa_key(master_key: &[u8]) -> Option<[u8; 32]> {
    if master_key.len() < 32 { return None; }
    let mut k = [0u8; 32];
    k.copy_from_slice(&master_key[..32]);
    // Clamp to valid P-256 scalar range
    k[0]  &= 0x7F; // ensure positive
    if k.iter().all(|&b| b == 0) { return None; } // reject zero key
    Some(k)
}
