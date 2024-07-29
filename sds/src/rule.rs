use serde::{Deserialize, Serialize};

use crate::match_action::MatchAction;
use crate::path::Path;
use crate::scanner::cache_pool::CachePoolBuilder;
use crate::scanner::error::CreateScannerError;
use crate::scanner::CompiledRuleTrait;
use crate::Labels;
use serde_with::{serde_as, DefaultOnNull};

pub trait RuleConfigTrait {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
        cache_pool_builder: &mut CachePoolBuilder,
    ) -> Result<Box<dyn CompiledRuleTrait>, CreateScannerError>;
}

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
    // This method will help users to discover the builder
    pub fn builder(pattern: impl Into<String>) -> RuleConfigBuilder {
        RuleConfigBuilder {
            pattern: pattern.into(),
            match_action: Default::default(),
            scope: Scope::all(),
            proximity_keywords: None,
            validator: None,
            labels: Labels::empty(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", content = "paths")]
pub enum Scope {
    // Only `include` fields are scanned,
    Include {
        include: Vec<Path<'static>>,
        exclude: Vec<Path<'static>>,
    },
    // Everything is scanned except the list of fields (children are also excluded)
    Exclude(Vec<Path<'static>>),
}

impl Scope {
    /// All fields of the event are scanned
    pub fn all() -> Self {
        Self::Exclude(vec![])
    }

    /// Paths will be scanned if they are children of any `include` path and NOT children of any `exclude` path
    pub fn include_and_exclude(include: Vec<Path<'static>>, exclude: Vec<Path<'static>>) -> Self {
        Self::Include { include, exclude }
    }

    /// Paths will be scanned if they are children of any `include` path
    pub fn include(include: Vec<Path<'static>>) -> Self {
        Self::Include {
            include,
            exclude: vec![],
        }
    }

    /// Paths will be scanned if they are NOT children of any `exclude` path
    pub fn exclude(exclude: Vec<Path<'static>>) -> Self {
        Self::Exclude(exclude)
    }
}

impl Default for Scope {
    fn default() -> Self {
        Self::all()
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
    LuhnChecksum,
    ChineseIdChecksum,
    GithubTokenChecksum,
    NhsCheckDigit,
    IbanChecker,
    NirChecksum,
}

pub struct RuleConfigBuilder {
    // Probably lots of optional fields.
    pattern: String,
    match_action: MatchAction,
    scope: Scope,
    proximity_keywords: Option<ProximityKeywordsConfig>,
    validator: Option<SecondaryValidator>,
    labels: Labels,
}

impl RuleConfigBuilder {
    pub fn pattern(mut self, pattern: String) -> RuleConfigBuilder {
        self.pattern = pattern;
        self
    }

    pub fn match_action(mut self, match_action: MatchAction) -> RuleConfigBuilder {
        self.match_action = match_action;
        self
    }
    pub fn scope(mut self, scope: Scope) -> RuleConfigBuilder {
        self.scope = scope;
        self
    }
    pub fn proximity_keywords(
        mut self,
        proximity_keywords: ProximityKeywordsConfig,
    ) -> RuleConfigBuilder {
        self.proximity_keywords = Option::from(proximity_keywords);
        self
    }

    pub fn validator(mut self, validator: SecondaryValidator) -> RuleConfigBuilder {
        self.validator = Option::from(validator);
        self
    }

    pub fn labels(mut self, labels: Labels) -> RuleConfigBuilder {
        self.labels = labels;
        self
    }

    pub fn from(rule: &RegexRuleConfig) -> RuleConfigBuilder {
        RuleConfigBuilder {
            pattern: rule.pattern.clone(),
            match_action: rule.match_action.clone(),
            scope: rule.scope.clone(),
            proximity_keywords: rule.proximity_keywords.clone(),
            validator: rule.validator.clone(),
            labels: rule.labels.clone(),
        }
    }

    pub fn build(self) -> RegexRuleConfig {
        RegexRuleConfig {
            pattern: self.pattern,
            match_action: self.match_action,
            scope: self.scope,
            proximity_keywords: self.proximity_keywords,
            validator: self.validator,
            labels: self.labels,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{Labels, MatchAction, ProximityKeywordsConfig, RegexRuleConfig, Scope};

    #[test]
    fn should_override_pattern() {
        let rule_config = RegexRuleConfig::builder("123".to_string())
            .pattern("456".to_string())
            .build();
        assert_eq!(rule_config.pattern, "456");
    }

    #[test]
    fn should_have_default() {
        let rule_config = RegexRuleConfig::builder("123".to_string()).build();
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
