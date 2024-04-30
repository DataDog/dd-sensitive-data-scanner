use crate::normalization::rust_regex_adapter::convert_to_rust_regex;
use crate::parser::error::ParseError;
use regex_automata::meta::{self};
use thiserror::Error;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum RegexValidationError {
    #[error("Invalid regex syntax")]
    InvalidSyntax,

    #[error("The regex pattern was nested too deeply")]
    ExceededDepthLimit,

    #[error("The regex has exceeded the complexity limit (i.e. it might be too slow)")]
    TooComplex,

    #[error("Regex patterns are not allowed to match an empty string")]
    MatchesEmptyString,
}

impl From<ParseError> for RegexValidationError {
    fn from(err: ParseError) -> Self {
        match err {
            ParseError::InvalidSyntax => Self::InvalidSyntax,
            ParseError::ExceededDepthLimit => Self::ExceededDepthLimit,
        }
    }
}

const REGEX_COMPLEXITY_LIMIT: usize = 1_000_000;

/// Checks that a regex pattern is valid for using in an SDS scanner
pub fn validate_regex(input: &str) -> Result<(), RegexValidationError> {
    // This is the same as `validate_and_create_regex`, but removes the actual Regex type
    // to create a more stable API for external users of the crate.
    validate_and_create_regex(input).map(|_| ())
}

pub fn validate_and_create_regex(input: &str) -> Result<meta::Regex, RegexValidationError> {
    // This validates that the syntax is valid and normalizes behavior.
    let converted_pattern = convert_to_rust_regex(input)?;

    let regex = meta::Builder::new()
        .configure(
            meta::Config::new()
                .nfa_size_limit(Some(REGEX_COMPLEXITY_LIMIT))
                // This is purely a performance setting. This is the default, but it might be worth testing this in benchmarks for a better number
                .hybrid_cache_capacity(2 * (1 << 20)),
        )
        .syntax(
            regex_automata::util::syntax::Config::default()
                .dot_matches_new_line(false)
                .unicode(true),
        )
        .build(&converted_pattern)
        .map_err(|regex_err| {
            if regex_err.size_limit().is_some() {
                RegexValidationError::TooComplex
            } else {
                // Internally the `regex` crate does this conversion, so we do it too
                RegexValidationError::InvalidSyntax
            }
        })?;

    if regex.is_match("") {
        return Err(RegexValidationError::MatchesEmptyString);
    }

    Ok(regex)
}

#[cfg(test)]
mod test {
    use crate::validation::{validate_and_create_regex, validate_regex, RegexValidationError};

    #[test]
    fn pattern_matching_empty_string_is_invalid() {
        // simple case that matches (only) empty string
        assert_eq!(
            validate_regex(""),
            Err(RegexValidationError::MatchesEmptyString)
        );
        assert_eq!(
            // This is an alternation with an empty string for the right side (which matches anything)
            validate_regex("a|"),
            Err(RegexValidationError::MatchesEmptyString)
        );

        // A subset of the regex _can_ match the empty string, as long as the entire pattern does not
        assert!(validate_regex("(a|)b").is_ok(),);
    }

    #[test]
    fn too_complex_pattern_is_rejected() {
        assert_eq!(
            validate_regex(".{10000}"),
            Err(RegexValidationError::TooComplex)
        );
    }

    #[test]
    fn highly_nested_pattern_is_rejected() {
        assert_eq!(
            validate_regex(&("(".repeat(1000) + "x" + &")".repeat(1000))),
            Err(RegexValidationError::ExceededDepthLimit)
        );
    }

    #[test]
    fn dot_new_line() {
        let regex = validate_and_create_regex(".").unwrap();
        assert_eq!(regex.is_match("\n"), false);
    }
}
