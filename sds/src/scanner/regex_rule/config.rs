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
    #[deprecated(note = "Use `third_party_active_checker` instead")]
    pub match_validation_type: Option<MatchValidationType>,
    pub third_party_active_checker: Option<MatchValidationType>,
}

impl RegexRuleConfig {
    pub fn new(pattern: &str) -> Self {
        #[allow(deprecated)]
        Self {
            pattern: pattern.to_owned(),
            match_action: MatchAction::None,
            scope: Scope::default(),
            proximity_keywords: None,
            validator: None,
            labels: Labels::default(),
            match_validation_type: None,
            third_party_active_checker: None,
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

    #[deprecated(note = "Use `third_party_active_checker` instead")]
    pub fn match_validation_type(&self, match_validation_type: MatchValidationType) -> Self {
        #[allow(deprecated)]
        self.mutate_clone(|x| {
            x.match_validation_type = Some(match_validation_type.clone());
            x.third_party_active_checker = Some(match_validation_type);
        })
    }

    pub fn third_party_active_checker(&self, checker: MatchValidationType) -> Self {
        self.mutate_clone(|x| x.third_party_active_checker = Some(checker))
    }

    pub fn build(&self) -> Arc<dyn RuleConfig> {
        #[allow(deprecated)]
        Arc::new(RegexRuleConfig {
            pattern: self.pattern.clone(),
            match_action: self.match_action.clone(),
            scope: self.scope.clone(),
            proximity_keywords: self.proximity_keywords.clone(),
            validator: self.validator.clone(),
            labels: self.labels.clone(),
            match_validation_type: self.match_validation_type.clone(),
            third_party_active_checker: self.third_party_active_checker.clone(),
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
        #[allow(deprecated)]
        self.third_party_active_checker
            .as_ref()
            .or(self.match_validation_type.as_ref())
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
    AbaRtnChecksum,
    BrazilianCpfChecksum,
    BrazilianCnpjChecksum,
    ChineseIdChecksum,
    GithubTokenChecksum,
    IbanChecker,
    JwtExpirationChecker,
    LuhnChecksum,
    NhsCheckDigit,
    NirChecksum,
    PolishNationalIdChecksum,
}

#[cfg(test)]
mod test {
    use crate::{AwsType, HttpValidatorConfigBuilder};

    use super::*;

    #[test]
    fn should_override_pattern() {
        let rule_config = RegexRuleConfig::new("123").pattern("456".to_string());
        assert_eq!(rule_config.pattern, "456");
    }

    #[test]
    #[allow(deprecated)]
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
                third_party_active_checker: None,
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

    #[test]
    #[allow(deprecated)]
    fn test_third_party_active_checker() {
        // Test setting only the new field
        let http_config = HttpValidatorConfigBuilder::new("http://test.com".to_string())
            .build()
            .unwrap();
        let validation_type = MatchValidationType::CustomHttp(http_config.clone());
        let rule_config =
            RegexRuleConfig::new("123").third_party_active_checker(validation_type.clone());

        assert_eq!(
            rule_config.third_party_active_checker,
            Some(validation_type.clone())
        );
        assert_eq!(rule_config.match_validation_type, None);
        assert_eq!(
            rule_config.get_match_validation_type(),
            Some(&validation_type)
        );

        // Test setting via deprecated field updates both
        let aws_type = AwsType::AwsId;
        let validation_type2 = MatchValidationType::Aws(aws_type);
        let rule_config =
            RegexRuleConfig::new("123").match_validation_type(validation_type2.clone());

        assert_eq!(
            rule_config.third_party_active_checker,
            Some(validation_type2.clone())
        );
        assert_eq!(
            rule_config.match_validation_type,
            Some(validation_type2.clone())
        );
        assert_eq!(
            rule_config.get_match_validation_type(),
            Some(&validation_type2)
        );

        // Test that get_match_validation_type prioritizes third_party_active_checker
        let rule_config = RegexRuleConfig::new("123")
            .match_validation_type(MatchValidationType::Aws(AwsType::AwsId))
            .third_party_active_checker(MatchValidationType::CustomHttp(http_config.clone()));

        assert_eq!(
            rule_config.get_match_validation_type(),
            Some(&MatchValidationType::CustomHttp(http_config.clone()))
        );
    }
}
