//! Stake ledger and slashing logic
//!
//! When a validator double-signs, their stake is reduced by slash_fraction.
//! Slashed stake goes to a community pool (or is burned).

use alloc::collections::BTreeMap;
use crate::crypto::PublicKeyBytes;
use crate::evidence::Evidence;
use crate::types::Height;

/// Fraction to slash on double-sign: 5% of stake
pub const SLASH_FRACTION_DOUBLE_SIGN: u64 = 20; // denominator: 1/20 = 5%

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct StakeLedger {
    /// validator pk → staked amount (in base units)
    pub stakes:  BTreeMap<PublicKeyBytes, u64>,
    /// validator pk → total slashed amount
    pub slashed: BTreeMap<PublicKeyBytes, u64>,
    pub community_pool: u64,
}

impl StakeLedger {
    pub fn new() -> Self { Self::default() }

    pub fn set_stake(&mut self, pk: PublicKeyBytes, amount: u64) {
        self.stakes.insert(pk, amount);
    }

    pub fn get_stake(&self, pk: &PublicKeyBytes) -> u64 {
        *self.stakes.get(pk).unwrap_or(&0)
    }

    /// Apply evidence: slash the offending validator
    pub fn apply_evidence(&mut self, ev: &Evidence, _at_height: Height) {
        let offender = ev.offender().clone();
        let stake = self.get_stake(&offender);
        if stake == 0 { return; }

        let slash_amount = stake / SLASH_FRACTION_DOUBLE_SIGN;
        if slash_amount == 0 { return; }

        *self.stakes.entry(offender.clone()).or_insert(0) -= slash_amount;
        *self.slashed.entry(offender.clone()).or_insert(0) += slash_amount;
        self.community_pool += slash_amount;

        crate::serial_println!(
            "[SLASH] validator slashed {} (double-sign): -{} stake",
            { let bytes = &offender.0[..8.min(offender.0.len())]; let mut s = alloc::string::String::new(); for b in bytes { let _ = core::fmt::Write::write_fmt(&mut s, format_args!("{:02x}", b)); } s },
            slash_amount
        );
    }
}
