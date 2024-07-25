use crate::proximity_keywords::compile_keywords_proximity_config;
use crate::scanner::config::{ProximityKeywordsConfig, RuleConfig, SecondaryValidator};
use crate::scanner::metrics::RuleMetrics;
use crate::scanner::regex_rule::compiled::RegexCompiledRule;
use crate::scanner::scope::Scope;
use crate::secondary_validation::Validator;
use crate::validation::validate_and_create_regex;
use crate::{CachePoolBuilder, CompiledRuleTrait, CreateScannerError, Labels, MatchAction};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DefaultOnNull;
use std::sync::Arc;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegexRuleConfig {
    pub pattern: String,
    pub match_action: MatchAction,
    #[serde(default)]
    pub scope: Scope,
    pub proximity_keywords: Option<ProximityKeywordsConfig>,
    pub validator: Option<SecondaryValidator>,
    #[serde_as(deserialize_as = "DefaultOnNull")]
    #[serde(default)]
    pub labels: Labels,
}

impl RegexRuleConfig {
    pub fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_owned(),
            match_action: MatchAction::None,
            scope: Scope::default(),
            proximity_keywords: None,
            validator: None,
            labels: Labels::default(),
        }
    }

    pub fn pattern(&self, pattern: String) -> Self {
        self.mutate_clone(|x| x.pattern = pattern)
    }

    pub fn match_action(&self, match_action: MatchAction) -> Self {
        self.mutate_clone(|x| x.match_action = match_action)
    }
    pub fn scope(&self, scope: Scope) -> Self {
        self.mutate_clone(|x| x.scope = scope)
    }
    pub fn proximity_keywords(&self, proximity_keywords: ProximityKeywordsConfig) -> Self {
        self.mutate_clone(|x| x.proximity_keywords = Some(proximity_keywords))
    }

    pub fn validator(&self, validator: SecondaryValidator) -> Self {
        self.mutate_clone(|x| x.validator = Some(validator))
    }

    pub fn labels(&self, labels: Labels) -> Self {
        self.mutate_clone(|x| x.labels = labels)
    }

    pub fn build(&self) -> Arc<dyn RuleConfig> {
        Arc::new(RegexRuleConfig {
            pattern: self.pattern.clone(),
            match_action: self.match_action.clone(),
            scope: self.scope.clone(),
            proximity_keywords: self.proximity_keywords.clone(),
            validator: self.validator.clone(),
            labels: self.labels.clone(),
        })
    }

    fn mutate_clone(&self, modify: impl FnOnce(&mut Self)) -> Self {
        let mut clone = self.clone();
        modify(&mut clone);
        clone
    }
}

impl RuleConfig for RegexRuleConfig {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        scanner_labels: Labels,
        cache_pool_builder: &mut CachePoolBuilder,
    ) -> Result<Box<dyn CompiledRuleTrait>, CreateScannerError> {
        let regex = validate_and_create_regex(&self.pattern)?;
        self.match_action.validate()?;

        let rule_labels = scanner_labels.clone_with_labels(self.labels.clone());

        let (included_keywords, excluded_keywords) = self
            .proximity_keywords
            .as_ref()
            .map(|config| compile_keywords_proximity_config(config, &rule_labels))
            .unwrap_or(Ok((None, None)))?;

        let cache_index = cache_pool_builder.push(regex.clone());
        Ok(Box::new(RegexCompiledRule {
            rule_index,
            regex,
            match_action: self.match_action.clone(),
            scope: self.scope.clone(),
            included_keywords,
            excluded_keywords,
            validator: self
                .validator
                .clone()
                .map(|x| Arc::new(x) as Arc<dyn Validator>),
            rule_cache_index: cache_index,
            metrics: RuleMetrics::new(&rule_labels),
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn should_override_pattern() {
        let rule_config = RegexRuleConfig::new("123").pattern("456".to_string());
        assert_eq!(rule_config.pattern, "456");
    }

    #[test]
    fn should_have_default() {
        let rule_config = RegexRuleConfig::new("123");
        assert_eq!(
            rule_config,
            RegexRuleConfig {
                pattern: "123".to_string(),
                match_action: MatchAction::None,
                scope: Scope::all(),
                proximity_keywords: None,
                validator: None,
                labels: Labels::empty(),
            }
        );
    }
}
