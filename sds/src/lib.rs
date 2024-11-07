// This blocks accidental use of `println`. If one is actually needed, you can
// override with `#[allow(clippy::print_stdout)]`.
#![deny(clippy::print_stdout)]

use std::sync::Arc;

use wasm_bindgen::prelude::*;

mod encoding;
mod event;
mod match_action;
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
// use serde_json;

#[cfg(any(test, feature = "testing", feature = "bench"))]
mod simple_event;

// This is the public API of the SDS core library
pub use encoding::{EncodeIndices, Encoding, Utf8Encoding};
pub use event::{Event, EventVisitor, VisitStringResult};
pub use match_action::{MatchAction, PartialRedactDirection};
pub use observability::labels::Labels;
pub use path::{Path, PathSegment};
pub use rule_match::{ReplacementType, RuleMatch};
pub use scanner::cache_pool::{CachePool, CachePoolBuilder, CachePoolGuard};
pub use scanner::{
    config::RuleConfig,
    error::CreateScannerError,
    regex_rule::config::SecondaryValidator,
    regex_rule::config::{ProximityKeywordsConfig, RegexRuleConfig},
    scope::Scope,
    CompiledRule, CompiledRuleDyn, MatchEmitter, Scanner, ScannerBuilder, StringMatch,
};

#[wasm_bindgen]
pub struct ScannerWrapper {
    #[allow(dead_code)]
    scanner: Scanner,
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct WasmRuleMatch {
    pub start: usize,
    pub end: usize,
    pub rule_index: usize,
    namespace: JsValue,
}

#[wasm_bindgen]
impl WasmRuleMatch {
    // Add getter methods
    #[wasm_bindgen(getter)]
    pub fn namespace(&self) -> JsValue {
        self.namespace.clone()
    }
}
#[wasm_bindgen]
pub struct WasmScanResult {
    input: JsValue,
    matches: Vec<WasmRuleMatch>,
}

#[wasm_bindgen]
impl WasmScanResult {
    // Add getter methods
    #[wasm_bindgen(getter)]
    pub fn input(&self) -> JsValue {
        self.input.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn matches(&self) -> Vec<WasmRuleMatch> {
        self.matches.clone()
    }
}

#[wasm_bindgen]
impl ScannerWrapper {
    #[wasm_bindgen(constructor)]
    pub fn new(rules: &str) -> Result<ScannerWrapper, String> {
        // parse rules
        let rules: Vec<RegexRuleConfig> = serde_json::from_str(rules).map_err(|e| e.to_string())?;
        let rules_vec = rules
            .iter()
            .map(|r| Arc::new(r.clone()) as Arc<dyn RuleConfig>)
            .collect::<Vec<_>>();
        let scanner = ScannerBuilder::new(&rules_vec)
            .build()
            .map_err(|e| e.to_string())?;

        Ok(ScannerWrapper { scanner })
    }
    pub fn scan(&self, input: &str) -> WasmScanResult {
        let mut input = input.to_string();
        let res = self.scanner.scan(&mut input, vec![]);
        WasmScanResult {
            input: JsValue::from_str(&input),
            matches: res
                .iter()
                .map(|m| WasmRuleMatch {
                    start: m.start_index,
                    end: m.end_index_exclusive,
                    rule_index: m.rule_index,
                    namespace: JsValue::from_str(m.path.sanitize().as_str()),
                })
                .collect(),
        }
    }
}

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
