use crate::scanner::RootCompiledRule;
use crate::RuleMatch;
use rayon::{ThreadPool, ThreadPoolBuilder};
use std::sync::LazyLock;
use std::vec::Vec;

/// A locally configured thread pool is used for Rayon to prevent conflicts with other libraries
/// that might override the (default) global thread pool with different (potentially undesirable) settings
pub static RAYON_THREAD_POOL: LazyLock<ThreadPool> =
    LazyLock::new(|| ThreadPoolBuilder::new().build().unwrap());

pub trait MatchValidator: Send + Sync {
    // Trait use to validate the matches and update the match status
    // It requires the matches found by the scans and the scanner rules to retrieve the match validation type
    fn validate(&self, matches: &mut Vec<RuleMatch>, scanner_rules: &[RootCompiledRule]);
}
