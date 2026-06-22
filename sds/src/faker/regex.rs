use rand::{Rng, rngs::StdRng};

use super::FakerValidationError;

const MAX_REPEAT: u32 = 100;

pub fn build(regex: &str, rng: &mut StdRng) -> String {
    let generator = rand_regex::Regex::compile(regex, MAX_REPEAT)
        .expect("pseudonymization regex should have been validated");
    rng.sample(generator)
}

pub fn validate(regex: &str) -> Result<(), FakerValidationError> {
    rand_regex::Regex::compile(regex, MAX_REPEAT)
        .map(|_| ())
        .map_err(|_| FakerValidationError::RegexInvalid)
}
