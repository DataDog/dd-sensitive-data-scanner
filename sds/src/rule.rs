use serde::{Deserialize, Serialize};

use crate::match_action::MatchAction;
use crate::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RuleConfig {
    pub pattern: String,
    pub match_action: MatchAction,
    #[serde(default)]
    pub scope: Scope,
    pub proximity_keywords: Option<ProximityKeywordsConfig>,
    pub validator: Option<SecondaryValidator>,
}

impl RuleConfig {
    // This method will help users to discover the builder
    pub fn builder(pattern: impl Into<String>) -> RuleConfigBuilder {
        RuleConfigBuilder {
            pattern: pattern.into(),
            match_action: Default::default(),
            scope: Scope::all(),
            proximity_keywords: None,
            validator: None,
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProximityKeywordsConfig {
    pub look_ahead_character_count: usize,
    pub included_keywords: Vec<String>,
    pub excluded_keywords: Vec<String>,
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum SecondaryValidator {
    LuhnChecksum,
    ChineseIdChecksum,
}

pub struct RuleConfigBuilder {
    // Probably lots of optional fields.
    pattern: String,
    match_action: MatchAction,
    scope: Scope,
    proximity_keywords: Option<ProximityKeywordsConfig>,
    validator: Option<SecondaryValidator>,
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

    pub fn from(rule: &RuleConfig) -> RuleConfigBuilder {
        RuleConfigBuilder {
            pattern: rule.pattern.clone(),
            match_action: rule.match_action.clone(),
            scope: rule.scope.clone(),
            proximity_keywords: rule.proximity_keywords.clone(),
            validator: rule.validator.clone(),
        }
    }

    pub fn build(self) -> RuleConfig {
        RuleConfig {
            pattern: self.pattern,
            match_action: self.match_action,
            scope: self.scope,
            proximity_keywords: self.proximity_keywords,
            validator: self.validator,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{MatchAction, RuleConfig, Scope};

    #[test]
    fn should_override_pattern() {
        let rule_config = RuleConfig::builder("123".to_string())
            .pattern("456".to_string())
            .build();
        assert_eq!(rule_config.pattern, "456");
    }

    #[test]
    fn should_have_default() {
        let rule_config = RuleConfig::builder("123".to_string()).build();
        assert_eq!(
            rule_config,
            RuleConfig {
                pattern: "123".to_string(),
                match_action: MatchAction::None,
                scope: Scope::all(),
                proximity_keywords: None,
                validator: None,
            }
        );
    }
}
