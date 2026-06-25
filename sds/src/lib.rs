// This blocks accidental use of `println`. If one is actually needed, you can
// override with `#[allow(clippy::print_stdout)]`.
#![deny(clippy::print_stdout)]
#![allow(clippy::new_without_default)]

#[cfg(feature = "sds-bindings-utils")]
mod bindings_utils;
#[cfg(feature = "dd-sds")]
mod encoding;
#[cfg(feature = "dd-sds")]
mod event;
#[cfg(feature = "dd-sds")]
mod match_action;

#[cfg(feature = "dd-sds")]
mod faker;

#[cfg(feature = "dd-sds")]
mod ast_utils;
#[cfg(feature = "dd-sds")]
mod event_json;
#[cfg(feature = "dd-sds")]
mod match_validation;
#[cfg(feature = "dd-sds")]
mod normalization;
#[cfg(feature = "dd-sds")]
mod observability;
#[cfg(feature = "dd-sds")]
mod parser;
#[cfg(feature = "dd-sds")]
mod path;
#[cfg(feature = "dd-sds")]
mod proximity_keywords;
#[cfg(feature = "dd-sds")]
mod rule_match;
#[cfg(feature = "dd-sds")]
mod scanner;
#[cfg(feature = "dd-sds")]
pub(crate) mod scoped_ruleset;
#[cfg(feature = "dd-sds")]
mod secondary_validation;
#[cfg(feature = "dd-sds")]
mod simple_event;
#[cfg(feature = "dd-sds")]
mod stats;
#[cfg(feature = "dd-sds")]
mod tokio;
#[cfg(feature = "dd-sds")]
mod validation;

#[cfg(feature = "dd_sds_go")]
mod native;
#[cfg(feature = "dd_sds_go")]
pub use native::{
    GoError, RuleDoublePtr, RuleList, RulePtr, convert_panic_to_go_error, handle_go_error,
    handle_panic_ptr_return, read_json,
};

#[cfg(feature = "sds-bindings-utils")]
pub use bindings_utils::{
    BinaryEvent, encode_async_response, encode_response, encode_response_in_place,
};

#[cfg(feature = "dd-sds")]
pub use simple_event::SimpleEvent;

// This is the public API of the SDS core library
#[cfg(feature = "dd-sds")]
pub use encoding::{EncodeIndices, Encoding, Utf8Encoding};
#[cfg(feature = "dd-sds")]
pub use event::{Event, EventVisitor, VisitStringResult};
#[cfg(feature = "dd-sds")]
pub use faker::{StatelessPseudonymizer, StatelessPseudonymizerError, terminal_pool};
#[cfg(feature = "dd-sds")]
pub use match_action::{MatchAction, PartialRedactDirection, PseudonymizationType};

#[cfg(feature = "dd-sds")]
pub use match_validation::{
    config::AwsConfig,
    config::AwsType,
    config::CustomHttpConfig,
    config::HttpMethod,
    config::HttpStatusCodeRange,
    config::HttpValidatorOption,
    config::InternalMatchValidationType,
    config::MatchValidationType,
    config::RequestHeader,
    config_v2::{
        BodyMatcher, CustomHttpConfigV2, HttpCallConfig, HttpRequestConfig, HttpResponseConfig,
        MatchPairingConfig, PairedValidatorConfig, ResponseCondition, ResponseConditionResult,
        ResponseConditionType, StatusCodeMatcher, TemplateVariable, TemplatedMatchString,
        is_valid_body_matcher_path,
    },
    match_status::{HttpErrorInfo, MatchStatus, UnknownResponseTypeInfo, ValidationError},
};
#[cfg(feature = "dd-sds")]
pub use observability::labels::Labels;
#[cfg(feature = "dd-sds")]
pub use path::{Path, PathSegment};
#[cfg(feature = "dd-sds")]
pub use rule_match::{ReplacementType, RuleMatch};
#[cfg(feature = "dd-sds")]
pub use scanner::shared_pool::{SharedPool, SharedPoolGuard};

#[cfg(feature = "dd-sds")]
pub use scanner::suppression::Suppressions;
#[cfg(feature = "dd-sds")]
pub use scanner::{
    CompiledRule, MatchEmitter, MatchGroupingStrategy, Precedence, RootCompiledRule,
    RootRuleConfig, RuleResult, RuleStatus, ScanOptionBuilder, Scanner, ScannerBuilder, SharedData,
    StringMatch, StringMatchesCtx,
    config::RuleConfig,
    error::{CreateScannerError, ScannerError},
    regex_rule::config::{
        ClaimRequirement, JwtClaimsValidatorConfig, ProximityKeywordsConfig, RegexRuleConfig,
        SecondaryValidator,
    },
    regex_rule::{RegexCacheKey, RegexCacheValue, RegexCaches, SharedRegex, get_memoized_regex},
    scope::Scope,
};
#[cfg(feature = "dd-sds")]
pub use scoped_ruleset::ExclusionCheck;
#[cfg(feature = "dd-sds")]
pub use tokio::TOKIO_RUNTIME;
#[cfg(feature = "dd-sds")]
pub use validation::{
    RegexValidationError, get_regex_complexity_estimate_very_slow, validate_regex,
};

#[cfg(feature = "dd-sds")]
pub use scanner::debug_scan::debug_scan;

#[cfg(all(feature = "dd-sds", any(feature = "testing", feature = "bench")))]
pub use crate::{
    scoped_ruleset::{ContentVisitor, RuleIndexVisitor, ScopedRuleSet},
    secondary_validation::{LuhnChecksum, Validator},
};
