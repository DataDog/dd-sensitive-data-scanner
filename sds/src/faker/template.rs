use ahash::AHashMap;
use rand::{Rng, rngs::StdRng};

use super::FakerValidationError;

pub fn build(
    string_builder: &str,
    allowed_data: &AHashMap<String, Vec<String>>,
    rng: &mut StdRng,
) -> String {
    let mut output = String::new();
    let mut remaining = string_builder;

    while let Some(start) = remaining.find('{') {
        output.push_str(&remaining[..start]);
        let after_start = &remaining[start + 1..];

        let Some(end) = after_start.find('}') else {
            output.push_str(&remaining[start..]);
            return output;
        };

        let placeholder = &after_start[..end];
        let values = allowed_data
            .get(placeholder)
            .expect("pseudonymization placeholder should have been validated");
        let index = rng.gen_range(0..values.len());
        output.push_str(&values[index]);
        remaining = &after_start[end + 1..];
    }

    output.push_str(remaining);
    output
}

pub fn validate(
    string_builder: &str,
    allowed_data: &AHashMap<String, Vec<String>>,
) -> Result<(), FakerValidationError> {
    if string_builder.is_empty() {
        return Err(FakerValidationError::StringBuilderEmpty);
    }

    if allowed_data.is_empty() {
        return Err(FakerValidationError::AllowedDataEmpty);
    }

    for (key, values) in allowed_data {
        if values.is_empty() {
            return Err(FakerValidationError::AllowedDataEmptyList {
                key: key.to_string(),
            });
        }
    }

    for placeholder in placeholders(string_builder) {
        if !allowed_data.contains_key(placeholder) {
            return Err(FakerValidationError::PlaceholderMissing {
                placeholder: placeholder.to_string(),
            });
        }
    }

    Ok(())
}

fn placeholders(string_builder: &str) -> Vec<&str> {
    let mut placeholders = Vec::new();
    let mut remaining = string_builder;

    while let Some(start) = remaining.find('{') {
        let after_start = &remaining[start + 1..];
        let Some(end) = after_start.find('}') else {
            break;
        };

        placeholders.push(&after_start[..end]);
        remaining = &after_start[end + 1..];
    }

    placeholders
}
