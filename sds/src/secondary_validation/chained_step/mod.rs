//! `ChainedStepValidator`: a secondary validator whose behaviour is a list of generic steps read
//! from the rule config, so new token checksum schemes ship as rule changes instead of library
//! releases.
//!
//! # Contract
//!
//! [`compile_chain`] turns the validator `config` object into a [`CompiledChain`]:
//! - a `version` newer than [`CHAINED_STEP_VALIDATOR_VERSION`], or a missing / invalid `version`,
//!   is a refusal ([`ChainCompileError::FutureVersion`], [`ChainCompileError::MissingVersion`],
//!   [`ChainCompileError::InvalidVersion`]): the caller disables the rule;
//! - anything else that cannot be compiled is [`ChainCompileError::Fallback`]: the caller replaces
//!   the validator with its constant `default_response`.
//!
//! [`CompiledChain::evaluate`] then runs per match and returns:
//! - [`ChainOutcome::Valid`] when every step succeeds;
//! - [`ChainOutcome::Invalid`] when a step's check is negative (the token is not genuine);
//! - [`ChainOutcome::Error`] when a step cannot be evaluated (the caller applies
//!   `default_response`).
//!
//! Each op documents which of its runtime failures are negative and which are errors, and keeps
//! that classification in a single `class()` match so it can be audited. That classification is
//! part of the op's versioned contract.
//!
//! # Versioning
//!
//! Every feature a chain can reference (op, input key, enum value) records the version that
//! introduced it. [`validate_chain_strict`] rejects chains that declare a `version` lower than the
//! features they use, because an older runtime would not understand them.

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod compile;
mod ops;
mod since;
mod value;

#[cfg(test)]
mod test;

pub(crate) use compile::{ChainCompileError, compile_chain};
pub use compile::{ChainValidationError, validate_chain_strict};

use ops::CompiledOp;
use value::{Frame, ThreadState, Value};

/// The highest chain `version` this runtime understands. Bumped whenever a release adds anything
/// a chain can reference (see the `since` tables).
pub const CHAINED_STEP_VALIDATOR_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainOutcome {
    Valid,
    /// A check was negative: the match is not a genuine token.
    Invalid,
    /// A step could not be evaluated; the caller applies the validator's `default_response`.
    Error,
}

/// Whether a runtime failure means "not a genuine token" or "could not evaluate".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FailureClass {
    Negative,
    Error,
}

impl From<FailureClass> for ChainOutcome {
    fn from(class: FailureClass) -> Self {
        match class {
            FailureClass::Negative => ChainOutcome::Invalid,
            FailureClass::Error => ChainOutcome::Error,
        }
    }
}

#[derive(Debug)]
pub struct CompiledChain {
    steps: Vec<CompiledOp>,
    slot_count: usize,
    /// Every literal referenced by the chain, concatenated, so literal operands are plain spans.
    literals: Vec<u8>,
    declared_version: u32,
    required_version: Option<since::FeatureRequirement>,
}

impl CompiledChain {
    pub fn evaluate(&self, input: &str) -> ChainOutcome {
        value::with_thread_state(|state| self.evaluate_with_state(input.as_bytes(), state))
            .unwrap_or(ChainOutcome::Error)
    }

    fn evaluate_with_state(&self, input: &[u8], state: &mut ThreadState) -> ChainOutcome {
        let Some(global_match) = value::Span::of_match(input) else {
            return ChainOutcome::Error;
        };
        let ThreadState {
            scratch,
            regex_caches,
            ..
        } = state;
        let mut frame = Frame::new(
            input,
            &self.literals,
            scratch,
            regex_caches,
            self.slot_count,
            Value::Bytes(global_match),
        );
        for step in &self.steps {
            if let Err(class) = step.run(&mut frame) {
                return class.into();
            }
        }
        ChainOutcome::Valid
    }
}

/// Drops the calling thread's chain scratch buffer and regex caches on their next use, and makes
/// every other thread do the same. Part of `clear_all_caches`.
pub fn clear_chain_caches() {
    value::bump_cache_epoch();
}
