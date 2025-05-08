use crate::proximity_keywords::compile_keywords_proximity_config;
use crate::scanner::config::RuleConfig;
use crate::scanner::metrics::RuleMetrics;
use crate::scanner::regex_rule::compiled::RegexCompiledRule;
use crate::scanner::regex_rule::regex_store::get_memoized_regex;
use crate::secondary_validation::Validator;
use crate::validation::validate_and_create_regex;
use crate::{CompiledRule, CreateScannerError, Labels};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use serde_with::DefaultOnNull;
use std::sync::Arc;

pub const DEFAULT_KEYWORD_LOOKAHEAD: usize = 30;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RegexRuleConfig {
    pub pattern: String,
    pub proximity_keywords: Option<ProximityKeywordsConfig>,
    pub validator: Option<SecondaryValidator>,
    #[serde_as(deserialize_as = "DefaultOnNull")]
    #[serde(default)]
    pub labels: Labels,
}

impl RegexRuleConfig {
    pub fn new(pattern: &str) -> Self {
        #[allow(deprecated)]
        Self {
            pattern: pattern.to_owned(),
            proximity_keywords: None,
            validator: None,
            labels: Labels::default(),
        }
    }

    pub fn with_pattern(&self, pattern: &str) -> Self {
        self.mutate_clone(|x| x.pattern = pattern.to_string())
    }

    pub fn with_proximity_keywords(&self, proximity_keywords: ProximityKeywordsConfig) -> Self {
        self.mutate_clone(|x| x.proximity_keywords = Some(proximity_keywords))
    }

    pub fn with_labels(&self, labels: Labels) -> Self {
        self.mutate_clone(|x| x.labels = labels)
    }

    pub fn build(&self) -> Arc<dyn RuleConfig> {
        Arc::new(self.clone())
    }

    fn mutate_clone(&self, modify: impl FnOnce(&mut Self)) -> Self {
        let mut clone = self.clone();
        modify(&mut clone);
        clone
    }

    pub fn with_included_keywords(
        &self,
        keywords: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        let mut this = self.clone();
        let mut config = self.get_or_create_proximity_keywords_config();
        config.included_keywords = keywords
            .into_iter()
            .map(|x| x.as_ref().to_string())
            .collect::<Vec<_>>();
        this.proximity_keywords = Some(config);
        this
    }

    pub fn with_validator(&self, validator: Option<SecondaryValidator>) -> Self {
        let mut this = self.clone();
        this.validator = validator;
        this
    }

    fn get_or_create_proximity_keywords_config(&self) -> ProximityKeywordsConfig {
        self.proximity_keywords
            .clone()
            .unwrap_or_else(|| ProximityKeywordsConfig {
                look_ahead_character_count: DEFAULT_KEYWORD_LOOKAHEAD,
                included_keywords: vec![],
                excluded_keywords: vec![],
            })
    }
}

impl RuleConfig for RegexRuleConfig {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        scanner_labels: Labels,
    ) -> Result<Box<dyn CompiledRule>, CreateScannerError> {
        let regex = get_memoized_regex(&self.pattern, validate_and_create_regex)?;

        let rule_labels = scanner_labels.clone_with_labels(self.labels.clone());

        let (included_keywords, excluded_keywords) = self
            .proximity_keywords
            .as_ref()
            .map(|config| compile_keywords_proximity_config(config, &rule_labels))
            .unwrap_or(Ok((None, None)))?;

        Ok(Box::new(RegexCompiledRule {
            rule_index,
            regex,
            included_keywords,
            excluded_keywords,
            validator: self
                .validator
                .clone()
                .map(|x| Arc::new(x) as Arc<dyn Validator>),
            metrics: RuleMetrics::new(&rule_labels),
        }))
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
    LuxembourgIndividualNINChecksum,
    FranceSsnChecksum,
}

#[cfg(test)]
mod test {
    use crate::{AwsType, CustomHttpConfig, MatchValidationType, RootRuleConfig};

    use super::*;

    #[test]
    fn should_override_pattern() {
        let rule_config = RegexRuleConfig::new("123").with_pattern("456");
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
                proximity_keywords: None,
                validator: None,
                labels: Labels::empty(),
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
        let http_config = CustomHttpConfig::default().with_endpoint("http://test.com".to_string());
        let validation_type = MatchValidationType::CustomHttp(http_config.clone());
        let rule_config = RootRuleConfig::new(RegexRuleConfig::new("123"))
            .third_party_active_checker(validation_type.clone());

        assert_eq!(
            rule_config.third_party_active_checker,
            Some(validation_type.clone())
        );
        assert_eq!(rule_config.match_validation_type, None);
        assert_eq!(
            rule_config.get_third_party_active_checker(),
            Some(&validation_type)
        );

        // Test setting via deprecated field updates both
        let aws_type = AwsType::AwsId;
        let validation_type2 = MatchValidationType::Aws(aws_type);
        let rule_config = RootRuleConfig::new(RegexRuleConfig::new("123"))
            .third_party_active_checker(validation_type2.clone());

        assert_eq!(
            rule_config.third_party_active_checker,
            Some(validation_type2.clone())
        );
        assert_eq!(
            rule_config.get_third_party_active_checker(),
            Some(&validation_type2)
        );

        // Test that get_match_validation_type prioritizes third_party_active_checker
        let rule_config = RootRuleConfig::new(RegexRuleConfig::new("123"))
            .third_party_active_checker(MatchValidationType::CustomHttp(http_config.clone()));

        assert_eq!(
            rule_config.get_third_party_active_checker(),
            Some(&MatchValidationType::CustomHttp(http_config.clone()))
        );
    }
}
