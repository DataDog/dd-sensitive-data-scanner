mod regex;
mod template;

use ahash::AHashMap;
use rand::{SeedableRng, rngs::StdRng};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum PseudonymizationType {
    Regex {
        regex: String,
    },
    Faker {
        string_builder: String,
        allowed_data: AHashMap<String, Vec<String>>,
    },
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum FakerValidationError {
    #[error("Pseudonymization regex must be valid: {regex}")]
    RegexInvalid { regex: String },
    #[error("Pseudonymization string builder must not be empty")]
    StringBuilderEmpty,
    #[error("Pseudonymization allowed data must not be empty")]
    AllowedDataEmpty,
    #[error("Pseudonymization placeholder must have allowed data: {placeholder}")]
    PlaceholderMissing { placeholder: String },
    #[error("Pseudonymization allowed data list must not be empty: {key}")]
    AllowedDataEmptyList { key: String },
}

pub fn build(pseudonymization_type: &PseudonymizationType, match_hash: &str) -> String {
    let mut rng = seeded_rng(match_hash);
    match pseudonymization_type {
        PseudonymizationType::Regex { regex } => regex::build(regex, &mut rng),
        PseudonymizationType::Faker {
            string_builder,
            allowed_data,
        } => template::build(string_builder, allowed_data, &mut rng),
    }
}

pub fn validate(pseudonymization_type: &PseudonymizationType) -> Result<(), FakerValidationError> {
    match pseudonymization_type {
        PseudonymizationType::Regex { regex } => {
            ::regex::Regex::new(regex)
                .map_err(|_| FakerValidationError::RegexInvalid {
                    regex: regex.clone(),
                })?;
            regex::validate(regex)
        }
        PseudonymizationType::Faker {
            string_builder,
            allowed_data,
        } => template::validate(string_builder, allowed_data),
    }
}

fn seeded_rng(match_hash: &str) -> StdRng {
    let seed = u64::from_str_radix(match_hash, 16).unwrap_or(0);
    StdRng::seed_from_u64(seed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed_data(entries: Vec<(&str, Vec<&str>)>) -> AHashMap<String, Vec<String>> {
        entries
            .into_iter()
            .map(|(key, values)| {
                (
                    key.to_string(),
                    values.into_iter().map(str::to_string).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn build_is_deterministic_for_same_hash() {
        let pseudonymization_type = PseudonymizationType::Faker {
            string_builder: "{first_name} {last_name}".to_string(),
            allowed_data: allowed_data(vec![
                ("first_name", vec!["Alice", "Bob", "Carol"]),
                ("last_name", vec!["Smith", "Jones", "Miller"]),
            ]),
        };

        assert_eq!(
            build(&pseudonymization_type, "fdf7528ad7f83901"),
            build(&pseudonymization_type, "fdf7528ad7f83901")
        );
    }

    #[test]
    fn build_differs_for_different_hash() {
        let pseudonymization_type = PseudonymizationType::Faker {
            string_builder: "{value}".to_string(),
            allowed_data: allowed_data(vec![(
                "value",
                vec![
                    "value-0", "value-1", "value-2", "value-3", "value-4", "value-5", "value-6",
                    "value-7", "value-8", "value-9",
                ],
            )]),
        };

        let first_output = build(&pseudonymization_type, "1");
        let found_different_output = (2..50)
            .map(|seed| build(&pseudonymization_type, &format!("{seed:x}")))
            .any(|output| output != first_output);

        assert!(found_different_output);
    }

    #[test]
    fn regex_output_matches_pattern() {
        let pseudonymization_type = PseudonymizationType::Regex {
            regex: "[A-Z]{3}[0-9]{2}".to_string(),
        };

        let output = build(&pseudonymization_type, "fdf7528ad7f83901");

        assert!(
            ::regex::Regex::new(r"^[A-Z]{3}[0-9]{2}$")
                .unwrap()
                .is_match(&output)
        );
    }

    #[test]
    fn template_replaces_all_placeholders() {
        let pseudonymization_type = PseudonymizationType::Faker {
            string_builder: "{first_name} {last_name}".to_string(),
            allowed_data: allowed_data(vec![
                ("first_name", vec!["Alice"]),
                ("last_name", vec!["Smith"]),
            ]),
        };

        let output = build(&pseudonymization_type, "fdf7528ad7f83901");

        assert_eq!(output, "Alice Smith");
    }

    #[test]
    fn template_respects_allowed_data() {
        let pseudonymization_type = PseudonymizationType::Faker {
            string_builder: "{first_name} {last_name}".to_string(),
            allowed_data: allowed_data(vec![
                ("first_name", vec!["Alice", "Bob"]),
                ("last_name", vec!["Smith", "Jones"]),
            ]),
        };

        let output = build(&pseudonymization_type, "fdf7528ad7f83901");
        let mut parts = output.split(' ');
        let first_name = parts.next().unwrap();
        let last_name = parts.next().unwrap();

        assert!(["Alice", "Bob"].contains(&first_name));
        assert!(["Smith", "Jones"].contains(&last_name));
        assert_eq!(parts.next(), None);
    }

    #[test]
    fn validate_rejects_missing_placeholder() {
        let pseudonymization_type = PseudonymizationType::Faker {
            string_builder: "{first_name} {last_name}".to_string(),
            allowed_data: allowed_data(vec![("first_name", vec!["Alice"])]),
        };

        assert_eq!(
            validate(&pseudonymization_type),
            Err(FakerValidationError::PlaceholderMissing {
                placeholder: "last_name".to_string()
            })
        );
    }

    #[test]
    fn validate_rejects_empty_list() {
        let pseudonymization_type = PseudonymizationType::Faker {
            string_builder: "{first_name}".to_string(),
            allowed_data: allowed_data(vec![("first_name", vec![])]),
        };

        assert_eq!(
            validate(&pseudonymization_type),
            Err(FakerValidationError::AllowedDataEmptyList {
                key: "first_name".to_string()
            })
        );
    }
}
