#![allow(deprecated)]
// The module level deprecation allow is needed to suppress warnings from `MatchAction::Utf16Hash`
// that I couldn't find a specific line to suppress. It can be removed when the variant is removed.

use std::{borrow::Cow, cmp::min};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{faker, rule_match::ReplacementType};

pub use crate::faker::PseudonymizationType;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(tag = "type")]
pub enum MatchAction {
    /// Do not modify the input.
    #[default]
    None,
    /// Replace matches with a new string.
    Redact { replacement: String },
    /// Hash the result
    Hash,
    /// Hash the result based on UTF-16 bytes encoded match result
    #[deprecated(
        note = "Support hash from UTF-16 encoded bytes for backward compatibility. Users should use instead hash match action."
    )]
    #[cfg(any(test, feature = "utf16_hash_match_action"))]
    Utf16Hash,
    /// Replace the first or last n characters with asterisks.
    PartialRedact {
        direction: PartialRedactDirection,
        character_count: usize,
    },
    /// Replace the match with a pseudonymized value
    Pseudonymize(PseudonymizationType),
}

impl MatchAction {
    pub fn redact(replacement: &str) -> Self {
        Self::Redact {
            replacement: replacement.to_string(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PartialRedactDirection {
    FirstCharacters,
    LastCharacters,
}

const PARTIAL_REDACT_CHARACTER: char = '*';

#[derive(Debug, PartialEq, Eq, Error)]
pub enum MatchActionValidationError {
    #[error("Partial redaction chars must be non-zero")]
    PartialRedactionNumCharsZero,
    #[error("Pseudonymization regex must be valid")]
    PseudonymizationRegexInvalid,
    #[error("Pseudonymization string builder must not be empty")]
    PseudonymizationStringBuilderEmpty,
    #[error("Pseudonymization allowed data must not be empty")]
    PseudonymizationAllowedDataEmpty,
    #[error("Pseudonymization placeholder must have allowed data: {placeholder}")]
    PseudonymizationPlaceholderMissing { placeholder: String },
    #[error("Pseudonymization allowed data list must not be empty: {key}")]
    PseudonymizationAllowedDataEmptyList { key: String },
}

impl From<faker::FakerValidationError> for MatchActionValidationError {
    fn from(error: faker::FakerValidationError) -> Self {
        match error {
            faker::FakerValidationError::RegexInvalid => Self::PseudonymizationRegexInvalid,
            faker::FakerValidationError::StringBuilderEmpty => {
                Self::PseudonymizationStringBuilderEmpty
            }
            faker::FakerValidationError::AllowedDataEmpty => Self::PseudonymizationAllowedDataEmpty,
            faker::FakerValidationError::PlaceholderMissing { placeholder } => {
                Self::PseudonymizationPlaceholderMissing { placeholder }
            }
            faker::FakerValidationError::AllowedDataEmptyList { key } => {
                Self::PseudonymizationAllowedDataEmptyList { key }
            }
        }
    }
}

impl MatchAction {
    pub fn validate(&self) -> Result<(), MatchActionValidationError> {
        match self {
            MatchAction::PartialRedact {
                direction: _,
                character_count,
            } => {
                if *character_count == 0 {
                    Err(MatchActionValidationError::PartialRedactionNumCharsZero)
                } else {
                    Ok(())
                }
            }
            MatchAction::None | MatchAction::Redact { replacement: _ } | MatchAction::Hash => {
                Ok(())
            }
            MatchAction::Pseudonymize(pseudonymization_type) => {
                faker::validate(pseudonymization_type).map_err(Into::into)
            }
            #[cfg(any(test, feature = "utf16_hash_match_action"))]
            #[allow(deprecated)]
            MatchAction::Utf16Hash => Ok(()),
        }
    }

    /// If the match action will modify the content
    pub fn is_mutating(&self) -> bool {
        match self {
            MatchAction::None => false,
            MatchAction::Redact { .. } => true,
            MatchAction::Hash => true,
            #[cfg(any(test, feature = "utf16_hash_match_action"))]
            #[allow(deprecated)]
            MatchAction::Utf16Hash => true,
            MatchAction::PartialRedact { .. } => true,
            MatchAction::Pseudonymize(_) => true,
        }
    }

    pub fn replacement_type(&self) -> ReplacementType {
        match self {
            MatchAction::None => ReplacementType::None,
            MatchAction::Redact { .. } => ReplacementType::Placeholder,
            MatchAction::Hash => ReplacementType::Hash,
            #[cfg(any(test, feature = "utf16_hash_match_action"))]
            #[allow(deprecated)]
            MatchAction::Utf16Hash => ReplacementType::Hash,
            MatchAction::PartialRedact { direction, .. } => match direction {
                PartialRedactDirection::FirstCharacters => ReplacementType::PartialStart,
                PartialRedactDirection::LastCharacters => ReplacementType::PartialEnd,
            },
            MatchAction::Pseudonymize(_) => ReplacementType::Placeholder,
        }
    }

    pub fn get_replacement(&self, matched_content: &str) -> Option<Replacement<'_>> {
        match self {
            MatchAction::None => None,
            MatchAction::Redact { replacement } => Some(Replacement {
                start: 0,
                end: matched_content.len(),
                replacement: Cow::Borrowed(replacement),
            }),
            MatchAction::Hash => Some(Replacement {
                start: 0,
                end: matched_content.len(),
                replacement: Cow::Owned(Self::hash(matched_content)),
            }),
            #[cfg(any(test, feature = "utf16_hash_match_action"))]
            #[allow(deprecated)]
            MatchAction::Utf16Hash => Some(Replacement {
                start: 0,
                end: matched_content.len(),
                replacement: Cow::Owned(Self::utf16_hash(matched_content)),
            }),
            MatchAction::PartialRedact {
                direction,
                character_count: num_characters,
            } => match direction {
                PartialRedactDirection::FirstCharacters => Some(Self::partial_redaction_first(
                    num_characters,
                    matched_content,
                )),
                PartialRedactDirection::LastCharacters => Some(Self::partial_redaction_last(
                    num_characters,
                    matched_content,
                )),
            },
            MatchAction::Pseudonymize(pseudonymization_type) => {
                let match_hash = Self::hash(matched_content);
                Some(Replacement {
                    start: 0,
                    end: matched_content.len(),
                    replacement: Cow::Owned(faker::build(pseudonymization_type, &match_hash)),
                })
            }
        }
    }

    fn hash(match_result: &str) -> String {
        let hash = farmhash2::fingerprint64(match_result.as_bytes());
        format!("{hash:x}")
    }

    #[cfg(any(test, feature = "utf16_hash_match_action"))]
    fn utf16_hash(match_result: &str) -> String {
        let utf16_bytes = match_result
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let hash = farmhash2::fingerprint64(&utf16_bytes);
        format!("{hash:x}")
    }

    fn partial_redaction_first(
        num_characters: &usize,
        matched_content: &str,
    ) -> Replacement<'static> {
        let match_len = matched_content.chars().count();

        let last_replacement_byte = if match_len > *num_characters {
            matched_content
                .char_indices()
                .nth(*num_characters)
                .unwrap()
                .0
        } else {
            matched_content.len()
        };

        let replacement_length = min(*num_characters, match_len);

        Replacement {
            start: 0,
            end: last_replacement_byte,
            replacement: String::from(PARTIAL_REDACT_CHARACTER)
                .repeat(replacement_length)
                .into(),
        }
    }

    fn partial_redaction_last(num_characters: &usize, match_result: &str) -> Replacement<'static> {
        let match_len = match_result.chars().count();

        let start_replacement_byte = if match_len > *num_characters {
            match_result
                .char_indices()
                .nth_back(*num_characters - 1)
                .unwrap()
                .0
        } else {
            0
        };

        let replacement_length = min(*num_characters, match_len);

        Replacement {
            start: start_replacement_byte,
            end: match_result.len(),
            replacement: String::from(PARTIAL_REDACT_CHARACTER)
                .repeat(replacement_length)
                .into(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct Replacement<'a> {
    pub start: usize,
    pub end: usize,
    pub replacement: Cow<'a, str>,
}

#[cfg(test)]
mod test {
    use ahash::AHashMap;

    use crate::match_action::PartialRedactDirection::{FirstCharacters, LastCharacters};
    use crate::match_action::{MatchAction, PseudonymizationType, Replacement};

    #[test]
    fn match_with_no_action() {
        let match_action = MatchAction::None;

        assert_eq!(match_action.get_replacement("rene coty"), None);
        assert_eq!(match_action.get_replacement("rene"), None);
    }

    #[test]
    fn match_with_redaction() {
        let match_action = MatchAction::Redact {
            replacement: "[REPLACEMENT]".to_string(),
        };

        assert_eq!(
            match_action.get_replacement("rene coty"),
            Some(Replacement {
                start: 0,
                end: 9,
                replacement: "[REPLACEMENT]".into()
            })
        );

        assert_eq!(
            match_action.get_replacement("coty"),
            Some(Replacement {
                start: 0,
                end: 4,
                replacement: "[REPLACEMENT]".into()
            })
        );
    }

    #[test]
    fn match_with_hash() {
        let match_action = MatchAction::Hash;

        assert_eq!(
            match_action.get_replacement("coty"),
            Some(Replacement {
                start: 0,
                end: 4,
                replacement: "fdf7528ad7f83901".into()
            })
        );

        assert_eq!(
            match_action.get_replacement("rene"),
            Some(Replacement {
                start: 0,
                end: 4,
                replacement: "51a2842f626aaaec".into()
            })
        );

        assert_eq!(
            match_action.get_replacement("😊"),
            Some(Replacement {
                start: 0,
                end: 4,
                replacement: "6ce17744696c2107".into()
            })
        );
    }

    #[test]
    #[cfg(feature = "utf16_hash_match_action")]
    fn match_with_utf16_hash() {
        #[allow(deprecated)]
        let match_action = MatchAction::Utf16Hash;

        assert_eq!(
            match_action.get_replacement("coty"),
            Some(Replacement {
                start: 0,
                end: 4,
                replacement: "d6bf038129a9eb52".into()
            })
        );

        assert_eq!(
            match_action.get_replacement("rene"),
            Some(Replacement {
                start: 0,
                end: 4,
                replacement: "8627c79c79ff4b8b".into()
            })
        );

        assert_eq!(
            match_action.get_replacement("😊"),
            Some(Replacement {
                start: 0,
                end: 4,
                replacement: "268a21f211fdbc0a".into()
            })
        );
    }

    #[test]
    fn match_with_partial_redaction_first_characters_should_always_redact_num_characters_max() {
        let match_action = MatchAction::PartialRedact {
            character_count: 5,
            direction: FirstCharacters,
        };

        assert_eq!(
            match_action.get_replacement("ene coty"),
            Some(Replacement {
                start: 0,
                end: 5,
                replacement: "*****".into()
            })
        );

        assert_eq!(
            match_action.get_replacement("rene"),
            Some(Replacement {
                start: 0,
                end: 4,
                replacement: "****".into()
            })
        );

        assert_eq!(
            match_action.get_replacement("rene "),
            Some(Replacement {
                start: 0,
                end: 5,
                replacement: "*****".into()
            })
        );
    }

    #[test]
    fn match_with_partial_redaction_last_characters_should_always_redact_num_characters_max() {
        let match_action = MatchAction::PartialRedact {
            character_count: 5,
            direction: LastCharacters,
        };

        assert_eq!(
            match_action.get_replacement("rene cot"),
            Some(Replacement {
                start: 3,
                end: 8,
                replacement: "*****".into()
            })
        );

        assert_eq!(
            match_action.get_replacement("rene"),
            Some(Replacement {
                start: 0,
                end: 4,
                replacement: "****".into()
            })
        );

        assert_eq!(
            match_action.get_replacement("rene "),
            Some(Replacement {
                start: 0,
                end: 5,
                replacement: "*****".into()
            })
        );
    }

    #[test]
    fn match_with_partial_redaction_should_redact_match_length_maximum() {
        let match_action = MatchAction::PartialRedact {
            character_count: 350,
            direction: FirstCharacters,
        };

        assert_eq!(
            match_action.get_replacement("rene coty"),
            Some(Replacement {
                start: 0,
                end: 9,
                replacement: "*********".into()
            })
        );

        assert_eq!(
            match_action.get_replacement("👍 rene coty"),
            Some(Replacement {
                start: 0,
                end: 14,
                replacement: "***********".into()
            })
        )
    }

    #[test]
    fn partially_redacts_first_emoji() {
        let match_action = MatchAction::PartialRedact {
            character_count: 1,
            direction: FirstCharacters,
        };

        assert_eq!(
            match_action.get_replacement("😊🤞"),
            Some(Replacement {
                start: 0,
                end: 4,
                replacement: "*".into()
            })
        );
    }

    #[test]
    fn partially_redacts_last_emoji() {
        let match_action = MatchAction::PartialRedact {
            character_count: 2,
            direction: LastCharacters,
        };

        assert_eq!(
            match_action.get_replacement("😊🤞👋"),
            Some(Replacement {
                start: 4,
                end: 12,
                replacement: "**".into()
            })
        );
    }

    #[test]
    fn test_farmhash_bugfix() {
        // Testing the bugfix from https://github.com/seiflotfy/rust-farmhash/pull/16
        assert_eq!(
            MatchAction::Hash.get_replacement(&"x".repeat(128)),
            Some(Replacement {
                start: 0,
                end: 128,
                replacement: "5170af09fd870c17".into()
            })
        );
    }

    #[test]
    fn match_with_pseudonymization_is_deterministic() {
        let mut allowed_data = AHashMap::new();
        allowed_data.insert(
            "first_name".to_string(),
            vec!["Alice".to_string(), "Bob".to_string()],
        );

        let match_action = MatchAction::Pseudonymize(PseudonymizationType::Faker {
            string_builder: "{first_name}".to_string(),
            allowed_data,
        });

        let first_replacement = match_action.get_replacement("coty").unwrap();
        let second_replacement = match_action.get_replacement("coty").unwrap();

        assert_eq!(first_replacement, second_replacement);
        assert!(!first_replacement.replacement.is_empty());
    }
}
