use ahash::AHashSet;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

const MAX_SUPPRESSIONS_COUNT: usize = 30;
const MAX_SUPPRESSION_LENGTH: usize = 1000;

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

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SuppressionValidationError {
    #[error("No more than {} suppressions are allowed", MAX_SUPPRESSIONS_COUNT)]
    TooManySuppressions,

    #[error("Empty suppressions are not allowed")]
    EmptySuppression,

    #[error(
        "Suppressions cannot be longer than {} characters",
        MAX_SUPPRESSION_LENGTH
    )]
    SuppressionTooLong,

    #[error("Duplicate suppressions are not allowed")]
    DuplicateSuppression,
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

fn validate_suppressions_list(suppressions: &[String]) -> Result<(), SuppressionValidationError> {
    if suppressions.len() > MAX_SUPPRESSIONS_COUNT {
        return Err(SuppressionValidationError::TooManySuppressions);
    }
    if AHashSet::from_iter(suppressions).len() != suppressions.len() {
        return Err(SuppressionValidationError::DuplicateSuppression);
    }
    for suppression in suppressions {
        if suppression.len() > MAX_SUPPRESSION_LENGTH {
            return Err(SuppressionValidationError::SuppressionTooLong);
        }
        if suppression.is_empty() {
            return Err(SuppressionValidationError::EmptySuppression);
        }
    }
    Ok(())
}

impl TryFrom<Suppressions> for CompiledSuppressions {
    type Error = SuppressionValidationError;

    fn try_from(config: Suppressions) -> Result<Self, SuppressionValidationError> {
        validate_suppressions_list(&config.starts_with)?;
        validate_suppressions_list(&config.ends_with)?;
        validate_suppressions_list(&config.exact_match)?;
        Ok(Self {
            starts_with: config.starts_with,
            ends_with: config.ends_with,
            exact_match: config.exact_match.into_iter().collect(),
        })
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
        let compiled_config = CompiledSuppressions::try_from(config).unwrap();
        assert!(compiled_config.should_match_be_suppressed("mary@datadoghq.com"));
        assert!(compiled_config.should_match_be_suppressed("nathan@yahoo.com"));
        assert!(compiled_config.should_match_be_suppressed("john@datadoghq.com"));
        assert!(!compiled_config.should_match_be_suppressed("john@yahoo.com"));
        assert!(!compiled_config.should_match_be_suppressed("john mary john"));
        assert!(compiled_config.should_match_be_suppressed("mary john john"));
    }
}
