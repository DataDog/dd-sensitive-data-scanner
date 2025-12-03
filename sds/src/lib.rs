// This blocks accidental use of `println`. If one is actually needed, you can
// override with `#[allow(clippy::print_stdout)]`.
#![deny(clippy::print_stdout)]
#![allow(clippy::new_without_default)]

mod encoding;
mod event;
mod match_action;

mod ast_utils;
#[cfg(any(test, feature = "testing", feature = "bench"))]
mod event_json;
mod match_validation;
mod normalization;
mod observability;
mod parser;
mod path;
mod proximity_keywords;
mod rule_match;
mod scanner;
pub(crate) mod scoped_ruleset;
mod secondary_validation;
mod simple_event;
mod stats;
mod tokio;
mod validation;

pub use simple_event::SimpleEvent;

// This is the public API of the SDS core library
pub use encoding::{EncodeIndices, Encoding, Utf8Encoding};
pub use event::{Event, EventVisitor, VisitStringResult};
pub use match_action::{MatchAction, PartialRedactDirection};

pub use match_validation::{
    config::AwsConfig, config::AwsType, config::CustomHttpConfig, config::HttpMethod,
    config::HttpStatusCodeRange, config::HttpValidatorOption, config::InternalMatchValidationType,
    config::MatchValidationType, config::RequestHeader, match_status::MatchStatus,
};
pub use observability::labels::Labels;
pub use path::{Path, PathSegment};
pub use rule_match::{ReplacementType, RuleMatch};
pub use scanner::shared_pool::{SharedPool, SharedPoolGuard};

pub use scanner::suppression::Suppressions;
pub use scanner::{
    CompiledRule, MatchEmitter, RootCompiledRule, RootRuleConfig, RuleResult, RuleStatus,
    ScanOptionBuilder, Scanner, ScannerBuilder, SharedData, StringMatch, StringMatchesCtx,
    config::RuleConfig,
    error::{CreateScannerError, ScannerError},
    regex_rule::config::{
        ClaimRequirement, JwtClaimsValidatorConfig, ProximityKeywordsConfig, RegexRuleConfig,
        SecondaryValidator,
    },
    regex_rule::{RegexCacheKey, RegexCacheValue, RegexCaches, SharedRegex},
    scope::Scope,
};
pub use scoped_ruleset::ExclusionCheck;
pub use tokio::TOKIO_RUNTIME;
pub use validation::{
    RegexValidationError, get_regex_complexity_estimate_very_slow, validate_regex,
};

#[cfg(any(feature = "testing", feature = "bench"))]
pub use crate::{
    scoped_ruleset::{ContentVisitor, RuleIndexVisitor, ScopedRuleSet},
    secondary_validation::{LuhnChecksum, Validator},
};
