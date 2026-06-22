use rand::{Rng, rngs::StdRng};

use crate::normalization::rust_regex_adapter::convert_to_rust_regex;

use super::FakerValidationError;

const MAX_REPEAT: u32 = 100;

pub fn build(regex: &str, rng: &mut StdRng) -> String {
    let regex = normalize_regex(regex).expect("pseudonymization regex should have been validated");
    let generator = rand_regex::Regex::compile(&regex, MAX_REPEAT)
        .expect("pseudonymization regex should have been validated");
    rng.sample(generator)
}

pub fn validate(regex: &str) -> Result<(), FakerValidationError> {
    let regex = normalize_regex(regex)?;
    rand_regex::Regex::compile(&regex, MAX_REPEAT)
        .map(|_| ())
        .map_err(|_| FakerValidationError::RegexInvalid)
}

fn normalize_regex(regex: &str) -> Result<String, FakerValidationError> {
    convert_to_rust_regex(regex).map_err(|_| FakerValidationError::RegexInvalid)
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn normalizes_perl_digit_class_to_ascii_digits() {
        assert_eq!(
            normalize_regex(r"0\d( ?\d{2}){4}"),
            Ok(r"0[0-9]( ?[0-9]{2}){4}".to_string())
        );
    }

    #[test]
    fn build_uses_ascii_digits_for_perl_digit_class() {
        let mut rng = StdRng::seed_from_u64(42);

        let output = build(r"0\d( ?\d{2}){4}", &mut rng);

        assert!(output.chars().all(|c| c == ' ' || c.is_ascii_digit()));
    }
}
