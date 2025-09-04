use ahash::AHashSet;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Suppressions {
    #[serde(default)]
    pub starts_with: Vec<String>,
    #[serde(default)]
    pub ends_with: Vec<String>,
    #[serde(default)]
    pub exact_match: Vec<String>,
}

pub struct CompiledSuppressions {
    pub starts_with: Vec<String>,
    pub ends_with: Vec<String>,
    pub exact_match: AHashSet<String>,
}

impl CompiledSuppressions {
    pub fn should_match_be_suppressed(&self, match_content: &str) -> bool {
        if self.exact_match.contains(match_content) {
            return true;
        }
        if self
            .starts_with
            .iter()
            .any(|start| match_content.starts_with(start))
        {
            return true;
        }
        if self
            .ends_with
            .iter()
            .any(|end| match_content.ends_with(end))
        {
            return true;
        }
        false
    }
}

impl From<Suppressions> for CompiledSuppressions {
    fn from(config: Suppressions) -> Self {
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
        let config = Suppressions {
            starts_with: vec!["mary".to_string()],
            ends_with: vec!["@datadoghq.com".to_string()],
            exact_match: vec!["nathan@yahoo.com".to_string()],
        };
        let compiled_config = CompiledSuppressions::from(config);
        assert!(compiled_config.should_match_be_suppressed("mary@datadoghq.com"));
        assert!(compiled_config.should_match_be_suppressed("nathan@yahoo.com"));
        assert!(compiled_config.should_match_be_suppressed("john@datadoghq.com"));
        assert!(!compiled_config.should_match_be_suppressed("john@yahoo.com"));
        assert!(!compiled_config.should_match_be_suppressed("john mary john"));
        assert!(compiled_config.should_match_be_suppressed("mary john john"));
    }
}
