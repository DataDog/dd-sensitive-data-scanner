use crate::match_validation::config::MatchValidationType;
use crate::proximity_keywords::compile_keywords_proximity_config;
use crate::scanner::config::RuleConfig;
use crate::scanner::metrics::RuleMetrics;
use crate::scanner::regex_rule::compiled::RegexCompiledRule;
use crate::scanner::regex_rule::regex_store::get_memoized_regex;
use crate::scanner::scope::Scope;
use crate::secondary_validation::Validator;
use crate::validation::validate_and_create_regex;
use crate::{CompiledRuleDyn, CreateScannerError, Labels, MatchAction};
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

    pub match_validation_type: Option<MatchValidationType>,
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

            match_validation_type: None,
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

    pub fn match_validation_type(&self, match_validation_type: MatchValidationType) -> Self {
        self.mutate_clone(|x| x.match_validation_type = Some(match_validation_type))
    }

    pub fn build(&self) -> Arc<dyn RuleConfig> {
        Arc::new(RegexRuleConfig {
            pattern: self.pattern.clone(),
            match_action: self.match_action.clone(),
            scope: self.scope.clone(),
            proximity_keywords: self.proximity_keywords.clone(),
            validator: self.validator.clone(),
            labels: self.labels.clone(),

            match_validation_type: self.match_validation_type.clone(),
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
    ) -> Result<Box<dyn CompiledRuleDyn>, CreateScannerError> {
        let regex = get_memoized_regex(&self.pattern, validate_and_create_regex)?;
        self.match_action.validate()?;

        let rule_labels = scanner_labels.clone_with_labels(self.labels.clone());

        let (included_keywords, excluded_keywords) = self
            .proximity_keywords
            .as_ref()
            .map(|config| compile_keywords_proximity_config(config, &rule_labels))
            .unwrap_or(Ok((None, None)))?;

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
            metrics: RuleMetrics::new(&rule_labels),
            match_validation_type: self.get_match_validation_type().cloned(),
            internal_match_validation_type: self
                .get_match_validation_type()
                .map(|x| x.get_internal_match_validation_type()),
        }))
    }

    fn get_match_validation_type(&self) -> Option<&MatchValidationType> {
        match &self.match_validation_type {
            Some(match_validation_type) => Some(match_validation_type),
            None => None,
        }
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProximityKeywordsConfig {
    pub look_ahead_character_count: usize,

    #[serde_as(deserialize_as = "DefaultOnNull")]
    #[serde(default)]
    pub included_keywords: Vec<String>,

    #[serde_as(deserialize_as = "DefaultOnNull")]
    #[serde(default)]
    pub excluded_keywords: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum SecondaryValidator {
    BrazilianCpfChecksum,
    BrazilianCnpjChecksum,
    ChineseIdChecksum,
    GithubTokenChecksum,
    IbanChecker,
    JwtExpirationChecker,
    LuhnChecksum,
    NhsCheckDigit,
    NirChecksum,
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

                match_validation_type: None,
            }
        );
    }

    #[test]
    fn proximity_keywords_should_have_default() {
        let json_config = r#"{"look_ahead_character_count": 0}"#;
        let test: ProximityKeywordsConfig = serde_json::from_str(json_config).unwrap();
        assert_eq!(
            test,
            ProximityKeywordsConfig {
                look_ahead_character_count: 0,
                included_keywords: vec![],
                excluded_keywords: vec![]
            }
        );

        let json_config = r#"{"look_ahead_character_count": 0, "excluded_keywords": null, "included_keywords": null}"#;
        let test: ProximityKeywordsConfig = serde_json::from_str(json_config).unwrap();
        assert_eq!(
            test,
            ProximityKeywordsConfig {
                look_ahead_character_count: 0,
                included_keywords: vec![],
                excluded_keywords: vec![]
            }
        );
    }
}
