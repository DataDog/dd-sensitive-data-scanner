use ahash::AHashSet;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SuppressionConfig {
    #[serde(default)]
    pub starts_with: Vec<String>,
    #[serde(default)]
    pub ends_with: Vec<String>,
    #[serde(default)]
    pub exact_match: Vec<String>,
}

pub struct CompiledSuppressionConfig {
    pub starts_with: Vec<String>,
    pub ends_with: Vec<String>,
    pub exact_match: AHashSet<String>,
}

impl CompiledSuppressionConfig {
    pub fn should_match_be_suppressed(&self, match_content: &str) -> bool {
        let exact_match = self.exact_match.contains(match_content);
        let starts_with = self
            .starts_with
            .iter()
            .any(|start| match_content.starts_with(start));
        let ends_with = self
            .ends_with
            .iter()
            .any(|end| match_content.ends_with(end));

        exact_match || starts_with || ends_with
    }
}

impl From<SuppressionConfig> for CompiledSuppressionConfig {
    fn from(config: SuppressionConfig) -> Self {
        Self {
            starts_with: config.starts_with,
            ends_with: config.ends_with,
            exact_match: config.exact_match.into_iter().collect(),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_suppression_correctly_suppresses_correctly() {
        let config = SuppressionConfig {
            starts_with: vec!["mary".to_string()],
            ends_with: vec!["@datadoghq.com".to_string()],
            exact_match: vec!["nathan@yahoo.com".to_string()],
        };
        let compiled_config = CompiledSuppressionConfig::from(config);
        assert!(compiled_config.should_match_be_suppressed("mary@datadoghq.com"));
        assert!(compiled_config.should_match_be_suppressed("nathan@yahoo.com"));
        assert!(compiled_config.should_match_be_suppressed("john@datadoghq.com"));
        assert!(!compiled_config.should_match_be_suppressed("john@yahoo.com"));
        assert!(!compiled_config.should_match_be_suppressed("john mary john"));
        assert!(compiled_config.should_match_be_suppressed("mary john john"));
    }
}
