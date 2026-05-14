//! Secure Keystore — stocare criptată de chei private
//!
//! Arhitectura:
//!   Fiecare cheie are un ID unic (UUID-like string)
//!   Cheile sunt criptate cu o master key derivată din o passphrase
//!   Stocate în IONAFS la /etc/iona-keystore.enc
//!
//! Encryption: XOR cu keystream derivat din SHA-256(master_key || key_id)
//! (Simplificat — producție: AES-256-GCM sau ChaCha20-Poly1305)
//!
//! Key types:
//!   ECDSA P-256  — validator signing key
//!   Ed25519      — pentru viitor (nu e în kernel acum)
//!   Raw32        — 32-byte generic secret
//!
//! Usage:
//!   keystore::init("my_passphrase")     — unlock keystore
//!   keystore::store("validator-key", key_bytes) — save key
//!   keystore::load("validator-key")     — retrieve key
//!   keystore::list()                    — enumerate key IDs

use alloc::{collections::BTreeMap, string::{String, ToString}, vec::Vec, format};
use spin::{Lazy, Mutex};

#[derive(Clone, Debug, PartialEq)]
pub enum KeyType {
    EcdsaP256,  // 32-byte private key scalar
    Ed25519,    // 32-byte seed
    Raw32,      // 32 arbitrary bytes
    Raw64,      // 64 arbitrary bytes
}

#[derive(Clone, Debug)]
pub struct KeyEntry {
    pub id:       String,
    pub key_type: KeyType,
    pub created:  u64,       // uptime_ms when stored
    pub label:    String,
    encrypted:    Vec<u8>,   // XOR-encrypted key material
}

struct Keystore {
    master_key: Option<[u8; 32]>,
    keys:       BTreeMap<String, KeyEntry>,
    unlocked:   bool,
}

static KS: Lazy<Mutex<Keystore>> = Lazy::new(|| Mutex::new(Keystore {
    master_key: None,
    keys:       BTreeMap::new(),
    unlocked:   false,
}));

/// Cold init at boot — load encrypted metadata from IONAFS without decrypting.
/// Keystore remains LOCKED until init() is called with correct passphrase.
/// This allows:
///   - list() to work (returns IDs + labels, not key material)
///   - is_unlocked() to return false
///   - Firstboot wizard to detect existing vs new keystore
pub fn cold_init() {
    let mut ks = KS.lock();
    if let Some(data) = crate::fs::ionafs::read("/etc/iona-keystore.enc") {
        ks.load_from_bytes(&data);
        crate::serial_println!(
            "  [KEYSTORE] loaded {} encrypted entries (locked — passphrase required)",
            ks.keys.len()
        );
    } else {
        crate::serial_println!("  [KEYSTORE] no keystore on disk — will create at firstboot");
    }
    // Note: ks.unlocked remains false — key material is not accessible
}

/// Initialize keystore with passphrase — derives master key via SHA-256
pub fn init(passphrase: &str) -> bool {
    let master = derive_key(passphrase.as_bytes(), b"iona-keystore-salt-v1");
    let mut ks = KS.lock();
    ks.master_key = Some(master);
    ks.unlocked   = true;
    // Load persisted keys from IONAFS
    if let Some(data) = crate::fs::ionafs::read("/etc/iona-keystore.enc") {
        ks.load_from_bytes(&data);
    }
    crate::serial_println!("  [KEYSTORE] unlocked — {} keys loaded", ks.keys.len());
    true
}

/// Store a key (encrypted with master key)
pub fn store(id: &str, label: &str, key_type: KeyType, key_bytes: &[u8]) -> bool {
    let mut ks = KS.lock();
    if !ks.unlocked { return false; }
    let mk = match ks.master_key { Some(k) => k, None => return false };
    let encrypted = xor_encrypt(&mk, id.as_bytes(), key_bytes);
    let entry = KeyEntry {
        id:       id.into(),
        key_type,
        created:  crate::arch::x86_64::timer::uptime_ms(),
        label:    label.into(),
        encrypted,
    };
    ks.keys.insert(id.into(), entry);
    ks.persist();
    crate::serial_println!("  [KEYSTORE] stored key '{}'", id);
    true
}

/// Retrieve decrypted key bytes
pub fn load(id: &str) -> Option<Vec<u8>> {
    let ks = KS.lock();
    if !ks.unlocked { return None; }
    let mk = ks.master_key?;
    let entry = ks.keys.get(id)?;
    let decrypted = xor_decrypt(&mk, id.as_bytes(), &entry.encrypted)?;
    Some(decrypted)
}

/// Delete a key
pub fn delete(id: &str) -> bool {
    let mut ks = KS.lock();
    let removed = ks.keys.remove(id).is_some();
    if removed { ks.persist(); }
    removed
}

/// List all key IDs and labels
pub fn list() -> Vec<(String, String, KeyType)> {
    let ks = KS.lock();
    ks.keys.values().map(|e| (e.id.clone(), e.label.clone(), e.key_type.clone())).collect()
}

pub fn is_unlocked() -> bool { KS.lock().unlocked }

/// Rotate master key (re-encrypt all stored keys)
pub fn rotate_master_key(new_passphrase: &str) -> bool {
    let new_master = derive_key(new_passphrase.as_bytes(), b"iona-keystore-salt-v1");
    let mut ks = KS.lock();
    if !ks.unlocked { return false; }
    let old_master = match ks.master_key { Some(k) => k, None => return false };
    // Re-encrypt all keys
    let ids: Vec<String> = ks.keys.keys().cloned().collect();
    for id in ids {
        if let Some(entry) = ks.keys.get_mut(&id) {
            let plain = xor_encrypt(&old_master, id.as_bytes(), &entry.encrypted);
            entry.encrypted = xor_encrypt(&new_master, id.as_bytes(), &plain);
        }
    }
    ks.master_key = Some(new_master);
    ks.persist();
    crate::serial_println!("  [KEYSTORE] master key rotated");
    true
}

// ── Internal ──────────────────────────────────────────────────────────────────
impl Keystore {
    fn persist(&self) {
        let data = self.serialize();
        crate::fs::ionafs::write("/etc/iona-keystore.enc", &data);
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (id, entry) in &self.keys {
            // Format: [len:2][id][len:2][label][type:1][created:8][len:2][encrypted]
            let id_b   = id.as_bytes();
            let lbl_b  = entry.label.as_bytes();
            let typ_b  = [entry.key_type.clone() as u8];
            let cre_b  = entry.created.to_le_bytes();
            let enc_b  = &entry.encrypted;
            out.extend_from_slice(&(id_b.len() as u16).to_le_bytes());
            out.extend_from_slice(id_b);
            out.extend_from_slice(&(lbl_b.len() as u16).to_le_bytes());
            out.extend_from_slice(lbl_b);
            out.push(typ_b[0]);
            out.extend_from_slice(&cre_b);
            out.extend_from_slice(&(enc_b.len() as u16).to_le_bytes());
            out.extend_from_slice(enc_b);
        }
        out
    }

    fn load_from_bytes(&mut self, data: &[u8]) {
        let mut i = 0;
        while i + 2 <= data.len() {
            let id_len = u16::from_le_bytes([data[i],data[i+1]]) as usize; i+=2;
            if i+id_len > data.len() { break; }
            let id = String::from_utf8_lossy(&data[i..i+id_len]).into_owned(); i+=id_len;
            if i+2 > data.len() { break; }
            let lbl_len = u16::from_le_bytes([data[i],data[i+1]]) as usize; i+=2;
            if i+lbl_len > data.len() { break; }
            let label = String::from_utf8_lossy(&data[i..i+lbl_len]).into_owned(); i+=lbl_len;
            if i+1 > data.len() { break; }
            let kt = match data[i] { 1=>KeyType::Ed25519, 2=>KeyType::Raw32, 3=>KeyType::Raw64, _=>KeyType::EcdsaP256 }; i+=1;
            if i+8 > data.len() { break; }
            let created = u64::from_le_bytes(data[i..i+8].try_into().unwrap_or([0;8])); i+=8;
            if i+2 > data.len() { break; }
            let enc_len = u16::from_le_bytes([data[i],data[i+1]]) as usize; i+=2;
            if i+enc_len > data.len() { break; }
            let encrypted = data[i..i+enc_len].to_vec(); i+=enc_len;
            self.keys.insert(id.clone(), KeyEntry { id, key_type: kt, created, label, encrypted });
        }
    }
}

// ── Crypto primitives ─────────────────────────────────────────────────────────
fn derive_key(passphrase: &[u8], salt: &[u8]) -> [u8; 32] {
    // Simplified KDF: SHA-256(passphrase || salt) repeated 1000 times
    // Production: use PBKDF2-SHA256 or Argon2
    let mut h = [0u8; 32];
    let mut buf: Vec<u8> = passphrase.to_vec();
    buf.extend_from_slice(salt);
    for _ in 0..1000 {
        h = sha256_simple(&buf);
        buf = h.to_vec();
        buf.extend_from_slice(salt);
    }
    h
}

/// Encrypt with ChaCha20-Poly1305 AEAD (using built-in TLS implementation).
/// Nonce: 12 bytes = SHA-256(key||id||"iona-nonce-v1")[..12]
/// DETERMINISTIC but safe: each (key, id) pair has a unique nonce.
/// If the same key is ever rotated, id must change too (use version suffix).
/// NO FALLBACK: if AEAD fails, encryption fails — never silently degrade.
fn xor_encrypt(key: &[u8; 32], id: &[u8], data: &[u8]) -> Vec<u8> {
    let aead = crate::net::tls::Aead::new(*key);
    let mut nonce_seed = alloc::vec![];
    nonce_seed.extend_from_slice(key);
    nonce_seed.extend_from_slice(id);
    nonce_seed.extend_from_slice(b"iona-nonce-v1");
    let nh = sha256_simple(&nonce_seed);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nh[..12]);
    aead.seal(&nonce, &[], data)
}

/// Decrypt — inverse of xor_encrypt
fn xor_decrypt(key: &[u8; 32], id: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() < 16 { return None; } // AEAD tag is 16 bytes min
    let aead = crate::net::tls::Aead::new(*key);
    let mut nonce_seed = alloc::vec![];
    nonce_seed.extend_from_slice(key);
    nonce_seed.extend_from_slice(id);
    nonce_seed.extend_from_slice(b"iona-nonce-v1");
    let nh = sha256_simple(&nonce_seed);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nh[..12]);
    aead.open(&nonce, &[], ciphertext)
}

fn sha256_simple(data: &[u8]) -> [u8; 32] {
    // Use the kernel's existing sha256 implementation
    crate::consensus::engine::sha256_hash(data)
}


impl KeyType {
    fn as_u8(&self) -> u8 {
        match self { KeyType::EcdsaP256=>0, KeyType::Ed25519=>1, KeyType::Raw32=>2, KeyType::Raw64=>3 }
    }
}

pub fn revoke(key_id: &str) -> bool {
    let revoked_id = alloc::format!("{}.revoked", key_id);
    if let Some(k) = load(key_id) { store(&revoked_id, &k); }
    delete(key_id)
}
pub fn is_revoked(key_id: &str) -> bool {
    load(&alloc::format!("{}.revoked", key_id)).is_some()
}
pub fn backup_key(key_id: &str, backup_path: &str) -> bool {
    match load(key_id) { Some(k) => { store(backup_path, &k); true } None => false }
}
pub fn restore_from_recovery(key_id: &str, _recovery_key: &[u8]) -> bool {
    let backup_id = alloc::format!("{}.backup", key_id);
    if let Some(backup) = load(&backup_id) { store(key_id, &backup); true } else { false }
}
