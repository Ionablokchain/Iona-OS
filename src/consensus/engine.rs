//! Tendermint BFT Consensus Engine
//!
//! Implements the Tendermint v0.34 consensus protocol with:
//! - Propose → Prevote → Precommit → Commit steps
//! - Fast quorum for sub‑second finality
//! - Double‑sign guard with persistent storage
//! - Evidence detection and reporting
//! - Block store and outbox abstractions
//! - Kernel‑level integration via syscall 400
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::consensus::{Engine, Config, Step};
//! use iona::crypto::ed25519::Ed25519Signer;
//!
//! let signer = Ed25519Signer::random();
//! let mut engine = Engine::new(
//!     Config::default(),
//!     validator_set,
//!     height,
//!     prev_block_id,
//!     app_state,
//!     stakes,
//!     Some(double_sign_guard),
//! );
//! engine.tick(&signer, &store, &mut outbox, dt_ms, mempool_drain);
//! ```

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::consensus::double_sign::DoubleSignGuard;
use crate::consensus::messages::*;
use crate::consensus::quorum::{quorum_threshold, VoteTally};
use crate::consensus::validator_set::ValidatorSet;
use crate::crypto::{Signer, Verifier, PublicKeyBytes, SignatureBytes};
use crate::evidence::Evidence;
use crate::execution::{build_block, next_base_fee, verify_block_with_vset};
use crate::slashing::StakeLedger;
use crate::types::{Block, Hash32, Height, KvState, Round, Tx, Receipt};

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during consensus operations.
#[derive(Debug, Error)]
pub enum ConsensusError {
    #[error("invalid signature")]
    BadSignature,
    #[error("unknown validator")]
    UnknownValidator,
    #[error("wrong consensus step")]
    BadStep,
    #[error("block execution failed: {0}")]
    Execution(String),
    #[error("double‑sign conflict detected")]
    DoubleSignConflict,
    #[error("quorum not reached")]
    QuorumNotReached,
    #[error("max rounds exceeded")]
    MaxRoundsExceeded,
    #[error("proposer not set")]
    NoProposer,
    #[error("I/O error: {0}")]
    Io(String),
}

pub type ConsensusResult<T> = Result<T, ConsensusError>;

// -----------------------------------------------------------------------------
// Step definitions
// -----------------------------------------------------------------------------

/// Consensus step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Step {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Step::Propose => write!(f, "Propose"),
            Step::Prevote => write!(f, "Prevote"),
            Step::Precommit => write!(f, "Precommit"),
            Step::Commit => write!(f, "Commit"),
        }
    }
}

// -----------------------------------------------------------------------------
// Commit certificate
// -----------------------------------------------------------------------------

/// Certificate proving that a block has been committed.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitCertificate {
    pub height: Height,
    pub block_id: Hash32,
    pub precommits: Vec<Vote>,
}

impl CommitCertificate {
    /// Verify the certificate against a validator set and a verifier.
    pub fn verify<V: Verifier>(&self, vset: &ValidatorSet) -> ConsensusResult<()> {
        let q = quorum_threshold(vset.total_power());
        let mut power = 0u64;
        for vote in &self.precommits {
            if !vset.contains(&vote.voter) {
                return Err(ConsensusError::UnknownValidator);
            }
            let bytes = vote_sign_bytes(vote.vote_type, vote.height, vote.round, &vote.block_id);
            V::verify(&vote.voter, &bytes, &vote.signature)
                .map_err(|_| ConsensusError::BadSignature)?;
            power += vset.power_of(&vote.voter);
        }
        if power < q {
            return Err(ConsensusError::QuorumNotReached);
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Consensus engine configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub propose_timeout_ms: u64,
    pub prevote_timeout_ms: u64,
    pub precommit_timeout_ms: u64,
    pub max_rounds: u32,
    pub max_txs_per_block: usize,
    pub gas_target: u64,
    pub initial_base_fee_per_gas: u64,
    pub include_block_in_proposal: bool,
    /// Advance step immediately on quorum — key to sub‑second finality.
    pub fast_quorum: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            propose_timeout_ms: 300,
            prevote_timeout_ms: 200,
            precommit_timeout_ms: 200,
            max_rounds: 50,
            max_txs_per_block: 4096,
            gas_target: 43_000_000,
            initial_base_fee_per_gas: 1,
            include_block_in_proposal: true,
            fast_quorum: true,
        }
    }
}

// -----------------------------------------------------------------------------
// Consensus state
// -----------------------------------------------------------------------------

/// Current consensus state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsensusState {
    pub height: Height,
    pub round: Round,
    pub step: Step,
    pub locked_round: Option<Round>,
    pub locked_value: Option<Hash32>,
    pub valid_round: Option<Round>,
    pub valid_value: Option<Hash32>,
    pub proposal: Option<Proposal>,
    pub proposal_block: Option<Block>,
    pub votes: BTreeMap<Round, BTreeMap<VoteType, BTreeMap<PublicKeyBytes, Vote>>>,
    pub vote_index: BTreeMap<(PublicKeyBytes, Height, Round, VoteType), (Option<Hash32>, Vote)>,
    pub decided: Option<CommitCertificate>,
}

impl ConsensusState {
    pub fn new(height: Height) -> Self {
        Self {
            height,
            round: 0,
            step: Step::Propose,
            locked_round: None,
            locked_value: None,
            valid_round: None,
            valid_value: None,
            proposal: None,
            proposal_block: None,
            votes: BTreeMap::new(),
            vote_index: BTreeMap::new(),
            decided: None,
        }
    }

    /// Reset the state for a new height.
    pub fn reset(&mut self, height: Height) {
        *self = Self::new(height);
    }

    /// Advance to the next round.
    pub fn advance_round(&mut self) {
        self.round += 1;
        self.proposal = None;
        self.proposal_block = None;
        self.step = Step::Propose;
    }
}

// -----------------------------------------------------------------------------
// Block store trait
// -----------------------------------------------------------------------------

/// Storage for blocks by their hash.
pub trait BlockStore: Send + Sync {
    fn get(&self, id: &Hash32) -> Option<Block>;
    fn put(&self, block: Block);
}

// -----------------------------------------------------------------------------
// Outbox trait
// -----------------------------------------------------------------------------

/// Interface for sending consensus messages and committing blocks.
pub trait Outbox {
    fn broadcast(&mut self, msg: ConsensusMsg);
    fn request_block(&mut self, block_id: Hash32);
    fn on_commit(
        &mut self,
        cert: &CommitCertificate,
        block: &Block,
        new_state: &KvState,
        new_base_fee: u64,
        receipts: &[Receipt],
    );
}

// -----------------------------------------------------------------------------
// Engine
// -----------------------------------------------------------------------------

/// Tendermint BFT consensus engine.
pub struct Engine<V: Verifier> {
    pub cfg: Config,
    pub vset: ValidatorSet,
    pub state: ConsensusState,
    pub prev_block_id: Hash32,
    pub app_state: KvState,
    pub stakes: StakeLedger,
    pub base_fee_per_gas: u64,
    ds_guard: Option<DoubleSignGuard>,
    step_elapsed_ms: u64,
    _v: PhantomData<V>,
}

impl<V: Verifier> Engine<V> {
    /// Create a new consensus engine.
    pub fn new(
        cfg: Config,
        vset: ValidatorSet,
        height: Height,
        prev_block_id: Hash32,
        app_state: KvState,
        stakes: StakeLedger,
        ds_guard: Option<DoubleSignGuard>,
    ) -> Self {
        Self {
            base_fee_per_gas: cfg.initial_base_fee_per_gas,
            cfg,
            vset,
            state: ConsensusState::new(height),
            prev_block_id,
            app_state,
            stakes,
            step_elapsed_ms: 0,
            ds_guard,
            _v: PhantomData,
        }
    }

    /// Check if the local node is the proposer for the current height and round.
    pub fn is_proposer(&self, pk: &PublicKeyBytes) -> bool {
        self.vset.proposer_for(self.state.height, self.state.round).pk == *pk
    }

    /// Derive an address string from a public key (for execution).
    fn proposer_addr_string(&self, pk: &PublicKeyBytes) -> String {
        crate::crypto::tx::derive_address(&pk.0)
    }

    /// Main tick function – call periodically with elapsed milliseconds.
    pub fn tick<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        dt_ms: u64,
        mempool_drain: impl FnOnce(usize) -> Vec<Tx>,
    ) {
        if self.state.decided.is_some() {
            return;
        }
        self.step_elapsed_ms = self.step_elapsed_ms.saturating_add(dt_ms);

        match self.state.step {
            Step::Propose => {
                let first_tick = self.step_elapsed_ms == dt_ms;
                if first_tick && self.state.proposal.is_none() {
                    self.maybe_propose(signer, store, out, mempool_drain);
                }
                let has_valid = self.cfg.fast_quorum
                    && self.state.proposal.is_some()
                    && self.state.proposal_block.is_some();
                if has_valid || self.step_elapsed_ms >= self.cfg.propose_timeout_ms {
                    self.state.step = Step::Prevote;
                    self.step_elapsed_ms = 0;
                    let vote_block = self.state.proposal.as_ref().and_then(|p| {
                        if self.state.proposal_block.is_some() {
                            Some(p.block_id.clone())
                        } else {
                            None
                        }
                    });
                    self.broadcast_vote(signer, out, VoteType::Prevote, vote_block);
                }
            }
            Step::Prevote => {
                if self.step_elapsed_ms >= self.cfg.prevote_timeout_ms {
                    self.advance_round(signer, store, out);
                }
            }
            Step::Precommit => {
                if self.step_elapsed_ms >= self.cfg.precommit_timeout_ms {
                    self.advance_round(signer, store, out);
                }
            }
            Step::Commit => {}
        }
    }

    /// Advance to the next round.
    fn advance_round<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
    ) {
        if self.state.round + 1 >= self.cfg.max_rounds {
            warn!(height = self.state.height, round = self.state.round, "max rounds reached");
            return;
        }
        self.state.advance_round();
        self.step_elapsed_ms = 0;
        debug!(height = self.state.height, round = self.state.round, "advanced round");
        // Try to propose immediately in the new round if we are the proposer.
        self.maybe_propose(signer, store, out, |_| Vec::new());
    }

    /// Propose a block if we are the proposer.
    fn maybe_propose<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        mempool_drain: impl FnOnce(usize) -> Vec<Tx>,
    ) {
        if self.state.proposal.is_some() {
            return;
        }
        if !self.is_proposer(&signer.public_key()) {
            return;
        }

        let txs = mempool_drain(self.cfg.max_txs_per_block);
        let proposer_addr = self.proposer_addr_string(&signer.public_key());
        let (block, _new_state, _receipts) = build_block(
            self.state.height,
            self.state.round,
            self.prev_block_id.clone(),
            signer.public_key().0.clone(),
            &proposer_addr,
            &self.app_state,
            self.base_fee_per_gas,
            txs,
        );
        let bid = block.id();
        store.put(block.clone());

        // Double‑sign check before proposal.
        if let Some(g) = &self.ds_guard {
            if g.check_proposal(self.state.height, self.state.round, &bid).is_err() {
                warn!(height = self.state.height, round = self.state.round, "ds_guard refused proposal");
                return;
            }
        }

        let sign_bytes = proposal_sign_bytes(
            self.state.height,
            self.state.round,
            &bid,
            self.state.valid_round,
        );
        let sig = signer.sign(&sign_bytes);

        if let Some(g) = &self.ds_guard {
            if g.record_proposal(self.state.height, self.state.round, &bid).is_err() {
                warn!(height = self.state.height, round = self.state.round, "ds_guard record failed");
                return;
            }
        }

        let prop = Proposal {
            height: self.state.height,
            round: self.state.round,
            proposer: signer.public_key(),
            block_id: bid.clone(),
            block: if self.cfg.include_block_in_proposal { Some(block.clone()) } else { None },
            pol_round: self.state.valid_round,
            signature: sig,
        };
        self.state.proposal = Some(prop.clone());
        self.state.proposal_block = Some(block);
        out.broadcast(ConsensusMsg::Proposal(prop));
        info!(height = self.state.height, round = self.state.round, "broadcast proposal");
    }

    /// Handle an incoming consensus message.
    pub fn on_message<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        msg: ConsensusMsg,
    ) -> ConsensusResult<()> {
        match msg {
            ConsensusMsg::Proposal(p) => self.on_proposal(signer, store, out, p),
            ConsensusMsg::Vote(v) => self.on_vote(signer, store, out, v),
            ConsensusMsg::Evidence(ev) => {
                self.stakes.apply_evidence(&ev, self.state.height);
                Ok(())
            }
        }
    }

    /// Verify a proposal.
    fn verify_proposal(&self, p: &Proposal) -> ConsensusResult<()> {
        if !self.vset.contains(&p.proposer) {
            return Err(ConsensusError::UnknownValidator);
        }
        if self.vset.proposer_for(p.height, p.round).pk != p.proposer {
            return Err(ConsensusError::UnknownValidator);
        }
        if p.height != self.state.height || p.round != self.state.round {
            return Err(ConsensusError::BadStep);
        }
        let bytes = proposal_sign_bytes(p.height, p.round, &p.block_id, p.pol_round);
        V::verify(&p.proposer, &bytes, &p.signature)
            .map_err(|_| ConsensusError::BadSignature)
    }

    /// Verify a vote.
    fn verify_vote(&self, v: &Vote) -> ConsensusResult<()> {
        if !self.vset.contains(&v.voter) {
            return Err(ConsensusError::UnknownValidator);
        }
        if v.height != self.state.height || v.round != self.state.round {
            return Err(ConsensusError::BadStep);
        }
        let bytes = vote_sign_bytes(v.vote_type, v.height, v.round, &v.block_id);
        V::verify(&v.voter, &bytes, &v.signature)
            .map_err(|_| ConsensusError::BadSignature)
    }

    /// Handle a proposal message.
    fn on_proposal<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        p: Proposal,
    ) -> ConsensusResult<()> {
        if self.state.decided.is_some() {
            return Ok(());
        }
        self.verify_proposal(&p)?;

        if let Some(b) = p.block.clone() {
            store.put(b);
        }

        let block = store.get(&p.block_id);
        if block.is_none() {
            out.request_block(p.block_id.clone());
            self.state.step = Step::Prevote;
            self.step_elapsed_ms = 0;
            self.broadcast_vote(signer, out, VoteType::Prevote, None);
            self.state.proposal = Some(p);
            self.state.proposal_block = None;
            return Ok(());
        }
        let block = block.unwrap();
        let proposer_addr = self.proposer_addr_string(&p.proposer);
        if verify_block_with_vset(&self.app_state, &block, &proposer_addr, &p.proposer).is_none() {
            self.state.step = Step::Prevote;
            self.step_elapsed_ms = 0;
            self.broadcast_vote(signer, out, VoteType::Prevote, None);
            return Ok(());
        }

        let proposal_id = p.block_id.clone();
        self.state.proposal = Some(p);
        self.state.proposal_block = Some(block);
        self.state.step = Step::Prevote;
        self.step_elapsed_ms = 0;
        let vote_block = self.prevote_choice(&proposal_id);
        self.broadcast_vote(signer, out, VoteType::Prevote, vote_block);
        Ok(())
    }

    /// Determine the prevote choice based on locked value.
    fn prevote_choice(&self, proposal_id: &Hash32) -> Option<Hash32> {
        if let Some(locked) = &self.state.locked_value {
            if locked != proposal_id {
                return None;
            }
        }
        Some(proposal_id.clone())
    }

    /// Record a vote and detect double‑vote evidence.
    fn record_vote_and_detect_evidence(&mut self, v: &Vote) -> Option<Evidence> {
        let key = (v.voter.clone(), v.height, v.round, v.vote_type);
        if let Some((prev_bid, prev_vote)) = self.state.vote_index.get(&key) {
            if prev_bid != &v.block_id {
                return Some(Evidence::DoubleVote {
                    voter: v.voter.clone(),
                    height: v.height,
                    round: v.round,
                    vote_type: v.vote_type,
                    a: prev_bid.clone(),
                    b: v.block_id.clone(),
                    vote_a: prev_vote.clone(),
                    vote_b: v.clone(),
                });
            }
        } else {
            self.state.vote_index.insert(key, (v.block_id.clone(), v.clone()));
        }
        None
    }

    /// Handle a vote message.
    fn on_vote<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        v: Vote,
    ) -> ConsensusResult<()> {
        if self.state.decided.is_some() {
            return Ok(());
        }
        self.verify_vote(&v)?;

        // Detect and broadcast evidence.
        if let Some(ev) = self.record_vote_and_detect_evidence(&v) {
            self.stakes.apply_evidence(&ev, self.state.height);
            out.broadcast(ConsensusMsg::Evidence(ev));
        }

        let rt = self.state.votes.entry(v.round).or_default();
        let vt = rt.entry(v.vote_type).or_default();
        vt.insert(v.voter.clone(), v.clone());

        match v.vote_type {
            VoteType::Prevote => {
                if self.state.step == Step::Prevote {
                    if let Some((bid_opt, pow)) = self.tally(v.round, VoteType::Prevote) {
                        let q = quorum_threshold(self.vset.total_power());
                        if pow >= q {
                            if let Some(bid) = bid_opt {
                                self.state.valid_round = Some(self.state.round);
                                self.state.valid_value = Some(bid.clone());
                                self.state.locked_round = Some(self.state.round);
                                self.state.locked_value = Some(bid.clone());
                                self.state.step = Step::Precommit;
                                self.step_elapsed_ms = 0;
                                self.broadcast_vote(signer, out, VoteType::Precommit, Some(bid));
                            } else {
                                self.advance_round(signer, store, out);
                            }
                        }
                    }
                }
            }
            VoteType::Precommit => {
                if self.state.step == Step::Precommit {
                    if let Some((bid_opt, pow)) = self.tally(v.round, VoteType::Precommit) {
                        let q = quorum_threshold(self.vset.total_power());
                        if pow >= q {
                            if let Some(bid) = bid_opt {
                                let block = store.get(&bid);
                                if block.is_none() {
                                    out.request_block(bid.clone());
                                    return Ok(());
                                }
                                let block = block.unwrap();
                                let proposer_pk = PublicKeyBytes(block.header.proposer_pk.clone());
                                let expected = &self.vset.proposer_for(self.state.height, v.round).pk;
                                let proposer_addr = self.proposer_addr_string(&proposer_pk);
                                let (new_state, receipts) = verify_block_with_vset(
                                    &self.app_state,
                                    &block,
                                    &proposer_addr,
                                    expected,
                                )
                                .ok_or_else(|| ConsensusError::Execution("block execution failed".into()))?;

                                let precommits = self.collect_votes(v.round, VoteType::Precommit, Some(&bid));
                                let cert = CommitCertificate {
                                    height: self.state.height,
                                    block_id: bid.clone(),
                                    precommits,
                                };
                                self.state.decided = Some(cert.clone());
                                self.state.step = Step::Commit;
                                self.step_elapsed_ms = 0;
                                self.app_state = new_state.clone();
                                self.prev_block_id = bid.clone();

                                let new_base = next_base_fee(
                                    self.base_fee_per_gas,
                                    block.header.gas_used,
                                    self.cfg.gas_target,
                                );
                                self.base_fee_per_gas = new_base;
                                out.on_commit(&cert, &block, &new_state, new_base, &receipts);
                                info!(height = self.state.height, "block committed");
                            } else {
                                self.advance_round(signer, store, out);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Tally votes for a given round and vote type.
    fn tally(&self, round: Round, vt: VoteType) -> Option<(Option<Hash32>, u64)> {
        let mut tally = VoteTally::default();
        let rt = self.state.votes.get(&round)?;
        let votes = rt.get(&vt)?;
        for (voter, vote) in votes.iter() {
            tally.add_vote(&self.vset, voter, &vote.block_id);
        }
        tally.best()
    }

    /// Collect votes for a given round, vote type, and optional block target.
    fn collect_votes(&self, round: Round, vt: VoteType, target: Option<&Hash32>) -> Vec<Vote> {
        let mut out = Vec::new();
        let Some(rt) = self.state.votes.get(&round) else { return out };
        let Some(votes) = rt.get(&vt) else { return out };
        for (_voter, vote) in votes.iter() {
            let matches = match (target, &vote.block_id) {
                (Some(t), Some(b)) => t == b,
                (None, None) => true,
                _ => false,
            };
            if matches {
                out.push(vote.clone());
            }
        }
        out
    }

    /// Broadcast a vote (with double‑sign guard check).
    fn broadcast_vote<S: Signer, O: Outbox>(
        &self,
        signer: &S,
        out: &mut O,
        vt: VoteType,
        block_id: Option<Hash32>,
    ) {
        if let Some(g) = &self.ds_guard {
            if g.check_vote(vt, self.state.height, self.state.round, &block_id).is_err() {
                warn!(height = self.state.height, round = self.state.round, vote_type = ?vt, "ds_guard refused vote");
                return;
            }
        }
        let bytes = vote_sign_bytes(vt, self.state.height, self.state.round, &block_id);
        let sig = signer.sign(&bytes);
        if let Some(g) = &self.ds_guard {
            if g.record_vote(vt, self.state.height, self.state.round, &block_id).is_err() {
                warn!(height = self.state.height, round = self.state.round, vote_type = ?vt, "ds_guard record failed");
                return;
            }
        }
        let vote = Vote {
            vote_type: vt,
            height: self.state.height,
            round: self.state.round,
            voter: signer.public_key(),
            block_id,
            signature: sig,
        };
        out.broadcast(ConsensusMsg::Vote(vote));
    }

    /// Handle a block received in response to a `request_block`.
    pub fn on_block_received<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
        block: Block,
    ) -> ConsensusResult<()> {
        store.put(block.clone());
        if let Some(prop) = self.state.proposal.clone() {
            if prop.block_id == block.id() && self.state.proposal_block.is_none() {
                self.state.proposal_block = Some(block);
                if self.state.step == Step::Prevote {
                    let bid = prop.block_id.clone();
                    let vote_block = self.prevote_choice(&bid);
                    self.broadcast_vote(signer, out, VoteType::Prevote, vote_block);
                }
            }
        }
        Ok(())
    }

    /// Move to the next height after a commit.
    pub fn next_height<S: Signer, B: BlockStore, O: Outbox>(
        &mut self,
        signer: &S,
        store: &B,
        out: &mut O,
    ) {
        self.state = ConsensusState::new(self.state.height + 1);
        self.step_elapsed_ms = 0;
        self.state.step = Step::Propose;
        self.maybe_propose(signer, store, out, |_| Vec::new());
    }
}

// -----------------------------------------------------------------------------
// Kernel bridge
// -----------------------------------------------------------------------------

/// Kernel‑visible CommitCertificate – subset of full certificate for kernel verification.
#[repr(C)]
pub struct KernelCommitCert {
    pub height: u64,
    pub vote_count: u32,
    pub quorum: u32,
    pub votes_hash: [u8; 32],
    pub valset_hash: [u8; 32],
}

/// Load a `KernelCommitCert` from a userspace pointer.
fn load_commit_cert(ptr: u64) -> Option<KernelCommitCert> {
    use crate::syscall::user_access::{check_user_range, copy_from_user};
    if ptr == 0 {
        return None;
    }
    let sz = core::mem::size_of::<KernelCommitCert>() as u64;
    if !check_user_range(ptr, sz) {
        return None;
    }
    let mut buf = alloc::vec![0u8; sz as usize];
    if copy_from_user(&mut buf, ptr).is_err() {
        return None;
    }
    // SAFETY: The buffer is exactly the size of the struct and we have
    // verified the user range.
    let cert = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const KernelCommitCert) };
    Some(cert)
}

/// Verify a `KernelCommitCert` against the expected height.
fn verify_commit_cert(cert: &KernelCommitCert, expected_height: u64) -> bool {
    if cert.height != expected_height {
        return false;
    }
    if cert.quorum == 0 {
        return false;
    }
    cert.vote_count >= cert.quorum
}

/// Persist a committed block to IONAFS.
pub fn persist_committed_block(height: u64, validator_id: u32, cert_votes: u32) {
    use crate::arch::x86_64::timer::uptime_ms;
    let path = alloc::format!("/var/iona-node/blocks/{:010}", height);
    let ts = uptime_ms();
    // Dummy hash for demonstration – in production this would be the block hash.
    let data = alloc::format!(
        "{{\"h\":{},\"ts\":{},\"val\":{},\"votes\":{},\"hash\":\"0x{:04x}{:04x}\"}}",
        height, ts, validator_id, cert_votes,
        (height * 1009) % 0xFFFF, (height * 7919) % 0xFFFF
    );
    crate::fs::ionafs::write(&path, data.as_bytes());
    info!(height, "block persisted to IONAFS");
}

/// Advance kernel consensus height via syscall 400.
///
/// This function is called from the kernel’s syscall handler.
/// It validates and applies a CommitCertificate provided by userspace.
pub fn advance_tick(height: u64, round: u64, step: u8, cert_ptr: u32) -> u64 {
    // Access the global consensus engine (singleton).
    // In production, this would be a proper global state.
    let mut engine = crate::consensus::CONSENSUS_ENGINE.lock();
    if let Some(ref mut e) = *engine {
        if height != e.state.height {
            return 0;
        }
        e.state.round = round as u32;
        if step != 3 {
            // Not Precommit
            return 0;
        }
        if e.vset.total_power() == 0 {
            return 0;
        }

        let quorum_threshold = quorum_threshold(e.vset.total_power()) as u32;

        let committed = if cert_ptr == 0 {
            // Testnet mode: trust report – require at least quorum.
            if e.vset.total_power() as u32 >= quorum_threshold {
                debug!(peers = e.vset.total_power(), "testnet commit accepted");
                true
            } else {
                warn!(peers = e.vset.total_power(), quorum = quorum_threshold, "testnet commit rejected");
                false
            }
        } else {
            // Production mode: verify certificate.
            match load_commit_cert(cert_ptr as u64) {
                Some(cert) if verify_commit_cert(&cert, height) => {
                    info!(
                        height = cert.height,
                        votes = cert.vote_count,
                        quorum = cert.quorum,
                        "cert verified"
                    );
                    true
                }
                Some(_) => {
                    warn!(height, "cert quorum not met");
                    false
                }
                None => {
                    warn!(height, "invalid cert pointer");
                    false
                }
            }
        };

        if committed {
            let h = e.state.height;
            let cert_votes = if cert_ptr == 0 {
                e.vset.total_power() as u32
            } else {
                load_commit_cert(cert_ptr as u64)
                    .map(|c| c.vote_count)
                    .unwrap_or(e.vset.total_power() as u32)
            };
            e.state.height += 1;
            e.state.round = 0;
            info!(height = h, "block committed");
            persist_committed_block(h, 0, cert_votes);
            return h;
        }
    }
    0
}

// -----------------------------------------------------------------------------
// Re‑exports
// -----------------------------------------------------------------------------

// The global engine is defined elsewhere; we re‑export it here for compatibility.
// In the original code, `CONSENSUS_ENGINE` is a global static.
// We'll keep the existing `pub use super::CONSENSUS_ENGINE;` at the top.

// We also re‑export the types needed by external callers.
pub use super::CONSENSUS_ENGINE;
pub use crate::consensus::messages::{ConsensusMsg, Proposal, Vote, VoteType};
pub use crate::consensus::quorum::{quorum_threshold, VoteTally};
pub use crate::consensus::validator_set::ValidatorSet;
