use crate::proximity_keywords::compile_keywords_proximity_config;
use crate::scanner::config::RuleConfig;
use crate::scanner::metrics::RuleMetrics;
use crate::scanner::regex_rule::compiled::RegexCompiledRule;
use crate::scanner::regex_rule::regex_store::get_memoized_regex;
use crate::validation::{RegexPatternCaptureGroupsValidationError, validate_and_create_regex};
use crate::{CompiledRule, CreateScannerError, Labels};
use regex_automata::util::captures::GroupInfo;
use serde::{Deserialize, Serialize};
use serde_with::DefaultOnNull;
use serde_with::serde_as;
use std::sync::Arc;
use strum::{AsRefStr, EnumIter};

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
    pub pattern_capture_groups: Option<Vec<String>>,
}

impl RegexRuleConfig {
    pub fn new(pattern: &str) -> Self {
        #[allow(deprecated)]
        Self {
            pattern: pattern.to_owned(),
            proximity_keywords: None,
            validator: None,
            labels: Labels::default(),
            pattern_capture_groups: None,
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

    pub fn with_pattern_capture_groups(&self, pattern_capture_groups: Vec<String>) -> Self {
        self.mutate_clone(|x| x.pattern_capture_groups = Some(pattern_capture_groups))
    }

    pub fn with_pattern_capture_group(&self, pattern_capture_group: &str) -> Self {
        self.mutate_clone(|x| match x.pattern_capture_groups {
            Some(ref mut pattern_capture_groups) => {
                pattern_capture_groups.push(pattern_capture_group.to_string());
            }
            None => {
                x.pattern_capture_groups = Some(vec![pattern_capture_group.to_string()]);
            }
        })
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

fn is_pattern_capture_groups_valid(
    pattern_capture_groups: &Option<Vec<String>>,
    group_info: &GroupInfo,
) -> Result<(), RegexPatternCaptureGroupsValidationError> {
    if pattern_capture_groups.is_none() {
        return Ok(());
    }
    let pattern_capture_groups = pattern_capture_groups.as_ref().unwrap();
    if pattern_capture_groups.len() != 1 {
        // We currently only allow one capture group
        return Err(RegexPatternCaptureGroupsValidationError::TooManyCaptureGroups);
    }
    let pattern_capture_group = pattern_capture_groups.first().unwrap();
    if group_info
        .all_names()
        .filter(|(_, _, name)| name.is_some())
        .map(|(_, _, name)| name.unwrap())
        .any(|name| name == pattern_capture_group)
    {
        Ok(())
    } else {
        Err(RegexPatternCaptureGroupsValidationError::CaptureGroupNotPresent)
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

        is_pattern_capture_groups_valid(&self.pattern_capture_groups, regex.group_info())?;

        Ok(Box::new(RegexCompiledRule {
            rule_index,
            regex,
            included_keywords,
            excluded_keywords,
            validator: self.validator.clone().map(|x| x.compile()),
            metrics: RuleMetrics::new(&rule_labels),
            pattern_capture_groups: self.pattern_capture_groups.clone(),
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumIter, AsRefStr)]
#[serde(tag = "type")]
pub enum SecondaryValidator {
    AbaRtnChecksum,
    BrazilianCnpjChecksum,
    BrazilianCpfChecksum,
    BtcChecksum,
    BulgarianEGNChecksum,
    ChineseIdChecksum,
    CoordinationNumberChecksum,
    CzechPersonalIdentificationNumberChecksum,
    CzechTaxIdentificationNumberChecksum,
    DutchBsnChecksum,
    DutchPassportChecksum,
    EntropyCheck,
    EthereumChecksum,
    FinnishHetuChecksum,
    FranceNifChecksum,
    FranceSsnChecksum,
    GermanIdsChecksum,
    GermanSvnrChecksum,
    GithubTokenChecksum,
    GreekTinChecksum,
    HungarianTinChecksum,
    IbanChecker,
    IrishPpsChecksum,
    ItalianNationalIdChecksum,
    JwtClaimsValidator { config: JwtClaimsValidatorConfig },
    JwtExpirationChecker,
    LatviaNationalIdChecksum,
    LithuanianPersonalIdentificationNumberChecksum,
    LuhnChecksum,
    LuxembourgIndividualNINChecksum,
    Mod11_10checksum,
    Mod11_2checksum,
    Mod1271_36Checksum,
    Mod27_26checksum,
    Mod37_2checksum,
    Mod37_36checksum,
    Mod661_26checksum,
    Mod97_10checksum,
    MoneroAddress,
    NhsCheckDigit,
    NirChecksum,
    PolishNationalIdChecksum,
    PolishNipChecksum,
    PortugueseTaxIdChecksum,
    RodneCisloNumberChecksum,
    RomanianPersonalNumericCode,
    SlovenianPINChecksum,
    SpanishDniChecksum,
    SpanishNussChecksum,
    SwedenPINChecksum,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", content = "config")]
pub enum ClaimRequirement {
    /// Just check that the claim exists
    Present,
    /// Check that the claim exists and is not expired
    NotExpired,
    /// Check that the claim exists and has an exact value
    ExactValue(String),
    /// Check that the claim exists and matches a regex pattern
    RegexMatch(String),
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct JwtClaimsValidatorConfig {
    #[serde(default)]
    pub required_headers: std::collections::BTreeMap<String, ClaimRequirement>,
    #[serde(default)]
    pub required_claims: std::collections::BTreeMap<String, ClaimRequirement>,
}

#[cfg(test)]
mod test {
    use crate::{AwsType, CustomHttpConfig, MatchValidationType, RootRuleConfig};
    use std::collections::BTreeMap;
    use strum::IntoEnumIterator;

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
                pattern_capture_groups: None,
            }
        );
    }

    #[test]
    fn should_use_capture_group() {
        let rule_config = RegexRuleConfig::new("hey (?<capture_group>world)")
            .with_pattern_capture_groups(vec!["capture_group".to_string()]);
        assert_eq!(
            rule_config,
            RegexRuleConfig {
                pattern: "hey (?<capture_group>world)".to_string(),
                proximity_keywords: None,
                validator: None,
                labels: Labels::empty(),
                pattern_capture_groups: Some(vec!["capture_group".to_string()]),
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

    #[test]
    fn test_secondary_validator_enum_iter() {
        // Test that we can iterate over all SecondaryValidator variants
        let validators: Vec<SecondaryValidator> = SecondaryValidator::iter().collect();
        // Verify some variants
        assert!(validators.contains(&SecondaryValidator::GithubTokenChecksum));
        assert!(validators.contains(&SecondaryValidator::JwtExpirationChecker));
    }

    #[test]
    fn test_secondary_validator_are_sorted() {
        let validator_names: Vec<String> = SecondaryValidator::iter()
            .map(|a| a.as_ref().to_string())
            .collect();
        let mut sorted_validator_names = validator_names.clone();
        sorted_validator_names.sort();
        assert_eq!(
            sorted_validator_names, validator_names,
            "Secondary validators should be sorted by alphabetical order, but it's not the case, expected order:"
        );
    }

    // The order has to be stable to pass linter checks. Otherwise, each instantiation will change the file
    #[test]
    fn test_jwt_claims_validator_config_serialization_order() {
        // Create a config with claims in non-alphabetical order
        let mut required_claims = BTreeMap::new();
        required_claims.insert("zzz".to_string(), ClaimRequirement::Present);
        required_claims.insert("exp".to_string(), ClaimRequirement::NotExpired);
        required_claims.insert(
            "aaa".to_string(),
            ClaimRequirement::ExactValue("test".to_string()),
        );
        required_claims.insert(
            "mmm".to_string(),
            ClaimRequirement::RegexMatch(r"^test.*".to_string()),
        );

        let config = JwtClaimsValidatorConfig {
            required_claims,
            required_headers: std::collections::BTreeMap::new(),
        };

        // Serialize multiple times to ensure stable order
        let serialized1 = serde_json::to_string(&config).unwrap();
        let serialized2 = serde_json::to_string(&config).unwrap();

        // Both serializations should be identical
        assert_eq!(serialized1, serialized2, "Serialization should be stable");

        // Keys should be in alphabetical order
        assert!(serialized1.find("aaa").unwrap() < serialized1.find("exp").unwrap());
        assert!(serialized1.find("exp").unwrap() < serialized1.find("mmm").unwrap());
        assert!(serialized1.find("mmm").unwrap() < serialized1.find("zzz").unwrap());
    }

    #[test]
    fn test_capture_groups_validation() {
        let test_cases: Vec<(
            &str,
            Vec<String>,
            Result<(), RegexPatternCaptureGroupsValidationError>,
        )> = vec![
            (
                "hello (?<capture_group>world)",
                vec!["capture_group".to_string()],
                Ok(()),
            ),
            (
                "hello (?<capture_group>world) and (?<another_group>world)",
                vec!["capture_group".to_string()],
                Ok(()),
            ),
            (
                "hello (?<capture_grou>world)",
                vec!["capture_group".to_string()],
                Err(RegexPatternCaptureGroupsValidationError::CaptureGroupNotPresent),
            ),
            (
                "hello (?<capture_group>world)",
                vec!["capture_group".to_string(), "capture_group2".to_string()],
                Err(RegexPatternCaptureGroupsValidationError::TooManyCaptureGroups),
            ),
        ];
        for (pattern, capture_groups, expected_result) in test_cases {
            let rule_config =
                RegexRuleConfig::new(pattern).with_pattern_capture_groups(capture_groups);
            assert_eq!(
                is_pattern_capture_groups_valid(
                    &rule_config.pattern_capture_groups,
                    &get_memoized_regex(pattern, validate_and_create_regex)
                        .unwrap()
                        .group_info()
                ),
                expected_result
            );
        }
    }
}
