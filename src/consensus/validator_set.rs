//! Validator set — round-robin proposer selection
//!
//! This module defines the validator set used in Tendermint consensus.
//! Each validator has a public key and a voting power (stake).
//! The proposer for a given height and round is selected using a
//! round‑robin algorithm: `(height + round) mod n`.

use alloc::vec::Vec;
use crate::types::{Height, Round};
use crate::crypto::PublicKeyBytes;

// -----------------------------------------------------------------------------
// Validator
// -----------------------------------------------------------------------------

/// A single validator participating in consensus.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Validator {
    /// Public key of the validator (used to verify signatures).
    pub pk: PublicKeyBytes,
    /// Voting power (stake) of this validator. Higher power means more influence.
    pub power: u64,
}

// -----------------------------------------------------------------------------
// Validator set
// -----------------------------------------------------------------------------

/// The set of validators active at a given height.
/// Proposers are selected round‑robin from this set.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    /// List of validators in arbitrary order (proposer selection uses deterministic index).
    pub validators: Vec<Validator>,
}

impl ValidatorSet {
    /// Create a new validator set from a list of validators.
    pub fn new(validators: Vec<Validator>) -> Self {
        Self { validators }
    }

    /// Check whether a validator with the given public key exists in the set.
    pub fn contains(&self, pk: &PublicKeyBytes) -> bool {
        self.validators.iter().any(|v| &v.pk == pk)
    }

    /// Return the total voting power (sum of all validators' powers).
    pub fn total_power(&self) -> u64 {
        self.validators.iter().map(|v| v.power).sum()
    }

    /// Return the voting power of a specific validator, or `None` if not found.
    pub fn power_of(&self, pk: &PublicKeyBytes) -> Option<u64> {
        self.validators.iter().find(|v| &v.pk == pk).map(|v| v.power)
    }

    /// Select the proposer for a given height and round.
    ///
    /// The algorithm is round‑robin:
    /// `index = (height + round) mod number_of_validators`
    ///
    /// This matches the Tendermint specification.
    ///
    /// # Panics
    /// Panics if the validator set is empty (should not happen in a live chain).
    pub fn proposer_for(&self, height: Height, round: Round) -> &Validator {
        let n = self.validators.len();
        assert!(n > 0, "validator set cannot be empty");
        let idx = ((height as u64).wrapping_add(round as u64)) as usize % n;
        &self.validators[idx]
    }

    /// Return the number of validators in the set.
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Returns `true` if there are no validators.
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pk(val: u8) -> PublicKeyBytes {
        let mut pk = [0u8; 32];
        pk[0] = val;
        pk
    }

    #[test]
    fn total_power_sum() {
        let vset = ValidatorSet::new(vec![
            Validator { pk: dummy_pk(1), power: 100 },
            Validator { pk: dummy_pk(2), power: 200 },
            Validator { pk: dummy_pk(3), power: 300 },
        ]);
        assert_eq!(vset.total_power(), 600);
    }

    #[test]
    fn proposer_round_robin() {
        let vset = ValidatorSet::new(vec![
            Validator { pk: dummy_pk(1), power: 10 },
            Validator { pk: dummy_pk(2), power: 20 },
            Validator { pk: dummy_pk(3), power: 30 },
        ]);
        // height=1, round=0 -> idx = (1+0)%3 = 1 -> second validator (pk=2)
        let prop = vset.proposer_for(Height::new(1), Round::new(0));
        assert_eq!(prop.pk, dummy_pk(2));
        // height=1, round=1 -> idx=2 -> third validator (pk=3)
        let prop = vset.proposer_for(Height::new(1), Round::new(1));
        assert_eq!(prop.pk, dummy_pk(3));
        // height=1, round=2 -> idx=0 -> first validator (pk=1)
        let prop = vset.proposer_for(Height::new(1), Round::new(2));
        assert_eq!(prop.pk, dummy_pk(1));
        // height=2, round=0 -> idx=(2+0)%3=2 -> third validator
        let prop = vset.proposer_for(Height::new(2), Round::new(0));
        assert_eq!(prop.pk, dummy_pk(3));
    }

    #[test]
    fn contains_and_power_of() {
        let pk1 = dummy_pk(1);
        let pk2 = dummy_pk(2);
        let vset = ValidatorSet::new(vec![
            Validator { pk: pk1, power: 100 },
        ]);
        assert!(vset.contains(&pk1));
        assert!(!vset.contains(&pk2));
        assert_eq!(vset.power_of(&pk1), Some(100));
        assert_eq!(vset.power_of(&pk2), None);
    }
}
