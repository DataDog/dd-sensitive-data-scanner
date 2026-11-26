use crate::proximity_keywords::compile_keywords_proximity_config;
use crate::scanner::config::RuleConfig;
use crate::scanner::disabled_rule::DisabledCompiledRule;
use crate::scanner::metrics::RuleMetrics;
use crate::scanner::regex_rule::compiled::RegexCompiledRule;
use crate::scanner::regex_rule::regex_store::get_memoized_regex;
use crate::validation::{
    RegexPatternCaptureGroupsValidationError, validate_and_create_regex,
    validate_named_capture_group_minimum_length,
};
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
    pub validator: Option<ValidatorConfig>,
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

    pub fn with_excluded_keywords(
        &self,
        keywords: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Self {
        let mut this = self.clone();
        let mut config = self.get_or_create_proximity_keywords_config();
        config.excluded_keywords = keywords
            .into_iter()
            .map(|x| x.as_ref().to_string())
            .collect::<Vec<_>>();
        this.proximity_keywords = Some(config);
        this
    }

    pub fn with_validator(&self, validator: Option<SecondaryValidator>) -> Self {
        self.with_validator_config(validator.map(ValidatorConfig::from))
    }

    pub fn with_validator_config(&self, validator: Option<ValidatorConfig>) -> Self {
        self.mutate_clone(|x| x.validator = validator)
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
    pattern: &str,
    pattern_capture_groups: &Option<Vec<String>>,
    group_info: &GroupInfo,
) -> Result<(), RegexPatternCaptureGroupsValidationError> {
    if pattern_capture_groups.is_none() {
        return Ok(());
    }
    let pattern_capture_groups = pattern_capture_groups.as_ref().unwrap();
    if pattern_capture_groups.len() != 1 {
        // We currently only allow one capture group
        return Err(
            RegexPatternCaptureGroupsValidationError::TooManyCaptureGroups(
                pattern_capture_groups.len(),
            ),
        );
    }
    let pattern_capture_group = pattern_capture_groups.first().unwrap();
    if !group_info
        .all_names()
        .filter(|(_, _, name)| name.is_some())
        .map(|(_, _, name)| name.unwrap())
        .any(|name| name == pattern_capture_group)
    {
        return Err(
            RegexPatternCaptureGroupsValidationError::CaptureGroupNotPresent(
                pattern_capture_group.clone(),
            ),
        );
    }
    // At this point, the capture group is in the regex, and there is exactly one.
    // Currently, it must be called `sds_match`.
    if pattern_capture_group != "sds_match" {
        return Err(RegexPatternCaptureGroupsValidationError::TargetedCaptureGroupMustBeSdsMatch);
    }
    validate_named_capture_group_minimum_length(pattern, pattern_capture_group)?;
    Ok(())
}

impl RuleConfig for RegexRuleConfig {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        scanner_labels: Labels,
    ) -> Result<Box<dyn CompiledRule>, CreateScannerError> {
        let rule_labels = scanner_labels.clone_with_labels(self.labels.clone());

        // The validator is compiled before the regex: a rule written for a newer runtime may also
        // use regex syntax this runtime rejects, and it must be disabled rather than fail the scanner.
        let validator = match self.validator.as_ref().map(ValidatorConfig::compile) {
            None => None,
            Some(Some(validator)) => Some(validator),
            Some(None) => return Ok(Box::new(DisabledCompiledRule)),
        };

        let regex = get_memoized_regex(&self.pattern, validate_and_create_regex)?;

        let (included_keywords, excluded_keywords) = self
            .proximity_keywords
            .as_ref()
            .map(|config| compile_keywords_proximity_config(config, &rule_labels))
            .unwrap_or(Ok((None, None)))?;

        is_pattern_capture_groups_valid(
            &self.pattern,
            &self.pattern_capture_groups,
            regex.group_info(),
        )?;

        Ok(Box::new(RegexCompiledRule {
            rule_index,
            regex,
            included_keywords,
            excluded_keywords,
            validator,
            metrics: RuleMetrics::new(&rule_labels),
            pattern_capture_groups: self.pattern_capture_groups.clone(),
        }))
    }

    fn as_regex_rule(&self) -> Option<&RegexRuleConfig> {
        Some(self)
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

/// A secondary validator together with the result to use when this runtime cannot evaluate it.
///
/// `default_response` is a sibling of `type` on the wire (`{"type": ..., "default_response": ...}`)
/// so that it stays readable even when `type` is unknown to this runtime.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ValidatorConfig {
    #[serde(flatten)]
    pub validator: ValidatorKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_response: Option<DefaultResponse>,
}

impl ValidatorConfig {
    pub fn new(validator: SecondaryValidator, default_response: Option<DefaultResponse>) -> Self {
        Self {
            validator: ValidatorKind::Known(validator),
            default_response,
        }
    }
}

impl From<SecondaryValidator> for ValidatorConfig {
    fn from(validator: SecondaryValidator) -> Self {
        Self::new(validator, None)
    }
}

/// Keeps validators this runtime can't load out of `SecondaryValidator`, so that a rule written for
/// a newer library version degrades to its `default_response` instead of failing to deserialize
/// (which fails the whole rule and, through the Go bindings, the whole scanner).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum ValidatorKind {
    Known(SecondaryValidator),
    /// The `type` is unknown to this runtime, or its `config` uses values this runtime doesn't
    /// know. Kept verbatim so that re-serializing the rule is lossless.
    Unsupported {
        #[serde(rename = "type")]
        type_name: serde_json::Value,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        config: Option<serde_json::Value>,
    },
}

/// Result a validator resolves to when it cannot be evaluated by this runtime.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DefaultResponse {
    /// Keep the match, as if there was no validator.
    Pass,
    /// Drop the match.
    Fail,
}

impl DefaultResponse {
    pub fn is_valid_match(&self) -> bool {
        matches!(self, DefaultResponse::Pass)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumIter, AsRefStr)]
#[serde(tag = "type")]
#[non_exhaustive]
pub enum SecondaryValidator {
    AbaRtnChecksum,
    AtlassianTokenChecksum,
    AustralianMedicareChecksum,
    AustralianTfnChecksum,
    AustrianSSNChecksum,
    BelgiumNationalRegisterChecksum,
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
    EstoniaPersonalCodeChecksum,
    EthereumChecksum,
    FinnishHetuChecksum,
    FranceNifChecksum,
    FranceSsnChecksum,
    GermanIdsChecksum,
    GermanSvnrChecksum,
    GithubTokenChecksum,
    GreeceAmkaChecksum,
    GreekTinChecksum,
    HungarianTinChecksum,
    IbanChecker,
    IrishPpsChecksum,
    ItalianNationalIdChecksum,
    JapanCorporateNumberChecksum,
    JapanDrivingLicenseChecksum,
    JapanMyNumberChecksum,
    JwtClaimsValidator {
        config: JwtClaimsValidatorConfig,
    },
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
    NonHexChecker,
    #[cfg(feature = "token-efficiency-checker")]
    NonHexPlusTokenEfficiencyChecker,
    PolishNationalIdChecksum,
    PolishNipChecksum,
    PortugueseTaxIdChecksum,
    RodneCisloNumberChecksum,
    RomanianPersonalNumericCode,
    SingaporeNricChecksum,
    SloveniaTinChecksum,
    SlovenianPINChecksum,
    SpanishDniChecksum,
    SpanishNussChecksum,
    SwedenPINChecksum,
    ThaiNationalIdChecksum,
    #[cfg(feature = "token-efficiency-checker")]
    TokenEfficiencyCheck,
    UkNinoFormatCheck,
    UkTrnChecksum,
    UsDeaChecksum,
    UsNpiChecksum,
    VerhoeffChecksum,
    VinChecksum,
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
    use crate::{AwsType, CustomHttpConfig, MatchAction, MatchValidationType, RootRuleConfig};
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
    fn match_action_should_default_to_none_on_deserialization() {
        let config: RootRuleConfig<RegexRuleConfig> =
            serde_json::from_str(r#"{"pattern":"hello"}"#).unwrap();
        assert_eq!(config.match_action, MatchAction::None);
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
                "hello (?<sds_match>world)",
                vec!["sds_match".to_string()],
                Ok(()),
            ),
            (
                "hello (?<capture_group>world)",
                vec!["capture_group".to_string()],
                Err(RegexPatternCaptureGroupsValidationError::TargetedCaptureGroupMustBeSdsMatch),
            ),
            (
                "hello (?<sds_match>world) and (?<another_group>world)",
                vec!["sds_match".to_string()],
                Ok(()),
            ),
            (
                "hello (?<capture_grou>world)",
                vec!["capture_group".to_string()],
                Err(
                    RegexPatternCaptureGroupsValidationError::CaptureGroupNotPresent(
                        "capture_group".to_string(),
                    ),
                ),
            ),
            (
                "hello (?<sds_match>d*)",
                vec!["sds_match".to_string()],
                Err(RegexPatternCaptureGroupsValidationError::CaptureGroupMatchesEmptyString),
            ),
            (
                "hello (?<sds_match>world)",
                vec!["sds_match".to_string(), "sds_match2".to_string()],
                Err(RegexPatternCaptureGroupsValidationError::TooManyCaptureGroups(2)),
            ),
        ];
        for (pattern, capture_groups, expected_result) in test_cases {
            let rule_config =
                RegexRuleConfig::new(pattern).with_pattern_capture_groups(capture_groups);
            assert_eq!(
                is_pattern_capture_groups_valid(
                    &rule_config.pattern,
                    &rule_config.pattern_capture_groups,
                    &get_memoized_regex(pattern, validate_and_create_regex)
                        .unwrap()
                        .group_info()
                ),
                expected_result
            );
        }
    }

    fn parse_validator_config(validator: serde_json::Value) -> ValidatorConfig {
        serde_json::from_value(validator).unwrap()
    }

    #[test]
    fn test_unsupported_validator_round_trips_losslessly() {
        let json = serde_json::json!({
            "type": "FutureValidator",
            "default_response": "pass",
            "config": {"key": "value"},
        });
        let config = parse_validator_config(json.clone());
        assert_eq!(serde_json::to_value(&config).unwrap(), json);
    }

    #[test]
    fn test_default_response_is_read_beside_a_configured_validator() {
        let config = parse_validator_config(serde_json::json!({
            "type": "JwtClaimsValidator",
            "default_response": "pass",
            "config": {"required_claims": {}},
        }));
        assert!(matches!(
            config.validator,
            ValidatorKind::Known(SecondaryValidator::JwtClaimsValidator { .. })
        ));
        assert_eq!(config.default_response, Some(DefaultResponse::Pass));
    }

    #[test]
    fn test_default_response_rejects_other_values() {
        for value in [
            serde_json::json!("skip"),
            serde_json::json!("Pass"),
            serde_json::json!(1),
            serde_json::json!(["pass"]),
        ] {
            let result = serde_json::from_value::<ValidatorConfig>(serde_json::json!({
                "type": "LuhnChecksum",
                "default_response": value,
            }));
            assert!(result.is_err(), "{value}");
        }
    }

    #[test]
    fn test_default_response_round_trips() {
        let config = ValidatorConfig::new(
            SecondaryValidator::LuhnChecksum,
            Some(DefaultResponse::Pass),
        );
        let json = serde_json::to_value(&config).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"type": "LuhnChecksum", "default_response": "pass"})
        );
        assert_eq!(parse_validator_config(json), config);
    }

    #[test]
    fn test_absent_default_response_is_not_serialized() {
        let config = ValidatorConfig::from(SecondaryValidator::LuhnChecksum);
        assert_eq!(
            serde_json::to_value(&config).unwrap(),
            serde_json::json!({"type": "LuhnChecksum"})
        );
    }
}
