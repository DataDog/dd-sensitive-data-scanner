// This blocks accidental use of `println`. If one is actually needed, you can
// override with `#[allow(clippy::print_stdout)]`.
#![deny(clippy::print_stdout)]

mod encoding;
mod event;
mod match_action;
#[cfg(feature = "match_validation")]
mod match_validation;
mod normalization;
mod observability;
mod parser;
mod path;
mod proximity_keywords;
mod rule_match;
mod scanner;
mod scoped_ruleset;
mod secondary_validation;
mod stats;
mod validation;

#[cfg(any(test, feature = "testing", feature = "bench"))]
mod simple_event;

// This is the public API of the SDS core library
pub use encoding::{EncodeIndices, Encoding, Utf8Encoding};
pub use event::{Event, EventVisitor, VisitStringResult};
pub use match_action::{MatchAction, PartialRedactDirection};
#[cfg(feature = "match_validation")]
pub use match_validation::{
    config::AwsConfig, config::AwsType, config::HttpValidatorConfigBuilder,
    config::MatchValidationType, http_validator::HttpValidatorHelper, match_status::MatchStatus,
};
pub use observability::labels::Labels;
pub use path::{Path, PathSegment};
pub use rule_match::{ReplacementType, RuleMatch};
pub use scanner::cache_pool::{CachePool, CachePoolBuilder, CachePoolGuard};
#[cfg(feature = "match_validation")]
pub use scanner::error::MatchValidationError;
pub use scanner::{
    config::RuleConfig,
    error::CreateScannerError,
    regex_rule::config::SecondaryValidator,
    regex_rule::config::{ProximityKeywordsConfig, RegexRuleConfig},
    scope::Scope,
    CompiledRule, CompiledRuleDyn, MatchEmitter, Scanner, ScannerBuilder, StringMatch,
};
pub use scoped_ruleset::ExclusionCheck;
pub use validation::{
    get_regex_complexity_estimate_very_slow, validate_regex, RegexValidationError,
};

#[cfg(any(feature = "testing", feature = "bench"))]
pub use crate::{
    scoped_ruleset::{ContentVisitor, RuleIndexVisitor, ScopedRuleSet},
    secondary_validation::{LuhnChecksum, Validator},
    simple_event::SimpleEvent,
};
