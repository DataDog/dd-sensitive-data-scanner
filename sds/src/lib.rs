mod encoding;
mod event;
mod match_action;
mod normalization;
mod observability;
mod parser;
mod path;
mod proximity_keywords;
mod rule;
mod rule_match;
mod scanner;
mod scoped_ruleset;
mod secondary_validation;
mod str_utils;
mod validation;

#[cfg(any(test, feature = "bench"))]
mod simple_event;

// This is the public API of the SDS core library
pub use encoding::{EncodeIndices, Encoding, Utf8Encoding};
pub use event::{Event, EventVisitor, VisitStringResult};
pub use match_action::{MatchAction, PartialRedactDirection};
pub use observability::labels;
pub use path::{Path, PathSegment};
pub use rule::{ProximityKeywordsConfig, RuleConfig, RuleConfigBuilder, Scope, SecondaryValidator};
pub use rule_match::{ReplacementType, RuleMatch};
pub use scanner::{error::CreateScannerError, Scanner};
pub use validation::{validate_regex, RegexValidationError};

#[cfg(feature = "bench")]
pub use crate::{
    scoped_ruleset::{ContentVisitor, ExclusionCheck, RuleIndexVisitor, ScopedRuleSet},
    secondary_validation::{LuhnChecksum, Validator},
    simple_event::SimpleEvent,
};
