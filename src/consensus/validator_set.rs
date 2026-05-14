//! ValidatorSet — round-robin proposer selection

use alloc::vec::Vec;
use crate::types::{Height, Round};
use crate::crypto::PublicKeyBytes;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Validator {
    pub pk:    PublicKeyBytes,
    pub power: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    pub validators: Vec<Validator>,
}

impl ValidatorSet {
    pub fn new(validators: Vec<Validator>) -> Self { Self { validators } }

    pub fn contains(&self, pk: &PublicKeyBytes) -> bool {
        self.validators.iter().any(|v| &v.pk == pk)
    }

    pub fn total_power(&self) -> u64 {
        self.validators.iter().map(|v| v.power).sum()
    }

    pub fn power_of(&self, pk: &PublicKeyBytes) -> Option<u64> {
        self.validators.iter().find(|v| &v.pk == pk).map(|v| v.power)
    }

    /// Round-robin proposer: (height + round) mod n
    pub fn proposer_for(&self, height: Height, round: Round) -> &Validator {
        let n = self.validators.len().max(1);
        let idx = ((height as u64).wrapping_add(round as u64)) as usize % n;
        &self.validators[idx]
    }
}
