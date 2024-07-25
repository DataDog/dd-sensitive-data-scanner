use serde::{Deserialize, Serialize};

use crate::scanner::cache_pool::CachePoolBuilder;
use crate::scanner::error::CreateScannerError;
use crate::scanner::CompiledRuleTrait;
use crate::Labels;
use serde_with::{serde_as, DefaultOnNull};

pub trait RuleConfig {
    fn convert_to_compiled_rule(
        &self,
        rule_index: usize,
        label: Labels,
        cache_pool_builder: &mut CachePoolBuilder,
    ) -> Result<Box<dyn CompiledRuleTrait>, CreateScannerError>;
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
}



#[cfg(test)]
mod test {
    use super::*;
    
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
