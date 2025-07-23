use crate::normalization::rust_regex_adapter::{
    convert_to_rust_regex, convert_to_rust_regex_ast, QUANTIFIER_LIMIT,
};
use crate::parser::error::ParseError;
use moka::sync::Cache;
use once_cell::sync::Lazy;
use regex_automata::meta::{self};
use regex_syntax::ast::Ast;
use regex_syntax::hir::translate::Translator;
use thiserror::Error;

static REGEX_CACHE: Lazy<Cache<String, Result<(), RegexValidationError>>> =
    Lazy::new(|| Cache::new(1000));

#[derive(Debug, PartialEq, Eq, Error, Clone)]
pub enum RegexValidationError {
    #[error("Invalid regex syntax")]
    InvalidSyntax,

    #[error("The regex pattern is nested too deeply")]
    ExceededDepthLimit,

    #[error("The regex has exceeded the complexity limit (try simplifying the regex)")]
    TooComplex,

    #[error("Regex patterns are not allowed to match an empty string")]
    MatchesEmptyString,

    #[error("Regex quantifier is too high. Max is {}", QUANTIFIER_LIMIT)]
    ExceededQuantifierLimit,
}

impl From<ParseError> for RegexValidationError {
    fn from(err: ParseError) -> Self {
        match err {
            ParseError::InvalidSyntax => Self::InvalidSyntax,
            ParseError::ExceededDepthLimit => Self::ExceededDepthLimit,
            ParseError::ExceededQuantifierLimit => Self::ExceededQuantifierLimit,
        }
    }
}

const REGEX_COMPLEXITY_LIMIT: usize = 1_000_000;

/// Checks that a regex pattern is valid for using in an SDS scanner
pub fn validate_regex(input: &str) -> Result<(), RegexValidationError> {
    // This is the same as `validate_and_create_regex`, but removes the actual Regex type
    // to create a more stable API for external users of the crate.
    if let Some(cache_hit) = REGEX_CACHE.get(input) {
        return cache_hit;
    }

    let result = validate_and_create_regex(input).map(|_| ());

    REGEX_CACHE.insert(input.to_owned(), result.clone());
    result
}

pub fn get_regex_complexity_estimate_very_slow(input: &str) -> Result<usize, RegexValidationError> {
    // The regex crate doesn't directly give you access to the "complexity", but it does
    // reject if it's too large, so we can binary search to find the limit.

    let converted_pattern = convert_to_rust_regex(input)?;

    let mut low = 1;
    // Allow it to go a bit higher than the normal limit, since this can be used for debugging
    // how complex a regex is.
    let mut high = 10 * REGEX_COMPLEXITY_LIMIT;
    while low < high {
        let mid = low + (high - low) / 2;
        if is_regex_within_complexity_limit(&converted_pattern, mid)? {
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    Ok(low)
}

pub fn validate_and_create_regex(input: &str) -> Result<meta::Regex, RegexValidationError> {
    // This validates that the syntax is valid and normalizes behavior.
    let ast = convert_to_rust_regex_ast(input)?;
    let pattern = ast.to_string();

    // Ensure that zero-length matches are not possible
    check_minimum_match_length(&ast, &pattern)?;

    let regex = build_regex(&pattern.to_string(), REGEX_COMPLEXITY_LIMIT)?;
    Ok(regex)
}

fn check_minimum_match_length(ast: &Ast, ast_str: &str) -> Result<(), RegexValidationError> {
    let hir = Translator::new()
        .translate(ast_str, ast)
        .map_err(|_| RegexValidationError::InvalidSyntax)?;
    match hir.properties().minimum_len() {
        None => {
            // This pattern cannot ever match
            Err(RegexValidationError::InvalidSyntax)
        }
        Some(min_length) => {
            if min_length == 0 {
                Err(RegexValidationError::MatchesEmptyString)
            } else {
                Ok(())
            }
        }
    }
}

fn is_regex_within_complexity_limit(
    converted_pattern: &str,
    complexity_limit: usize,
) -> Result<bool, RegexValidationError> {
    match build_regex(converted_pattern, complexity_limit) {
        Ok(_) => Ok(true),
        Err(err) => match err {
            RegexValidationError::TooComplex => Ok(false),
            _ => Err(err),
        },
    }
}

fn build_regex(
    converted_pattern: &str,
    complexity_limit: usize,
) -> Result<meta::Regex, RegexValidationError> {
    meta::Builder::new()
        .configure(
            meta::Config::new()
                .nfa_size_limit(Some(complexity_limit))
                // This is purely a performance setting. This is the default, but it might be worth testing this in benchmarks for a better number
                .hybrid_cache_capacity(2 * (1 << 20)),
        )
        .syntax(
            regex_automata::util::syntax::Config::default()
                .dot_matches_new_line(false)
                .unicode(true),
        )
        .build(converted_pattern)
        .map_err(|regex_err| {
            if regex_err.size_limit().is_some() {
                RegexValidationError::TooComplex
            } else {
                // Internally the `regex` crate does this conversion, so we do it too
                RegexValidationError::InvalidSyntax
            }
        })
}

#[cfg(test)]
mod test {
    use crate::validation::{
        get_regex_complexity_estimate_very_slow, validate_and_create_regex, validate_regex,
        RegexValidationError,
    };

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
            validate_regex(".{1000}{1000}"),
            Err(RegexValidationError::TooComplex)
        );
    }

    #[test]
    fn high_repetition_pattern_is_rejected() {
        assert_eq!(
            validate_regex(".{10000}"),
            Err(RegexValidationError::ExceededQuantifierLimit)
        );
    }

    #[test]
    fn test_invalid_range_quantifiers() {
        assert_eq!(
            validate_regex(".{100,1}"),
            Err(RegexValidationError::InvalidSyntax)
        );
    }

    #[test]
    fn dot_new_line() {
        let regex = validate_and_create_regex(".").unwrap();
        assert!(!regex.is_match("\n"));
    }

    #[test]
    fn test_complexity() {
        // These values may change slightly when the `regex` crate is updated. As long as they
        // are close, the test should be updated, otherwise the complexity limit may need to
        // be adjusted.

        assert_eq!(get_regex_complexity_estimate_very_slow("x"), Ok(1));
        assert_eq!(get_regex_complexity_estimate_very_slow("x{1,10}"), Ok(920));
        assert_eq!(get_regex_complexity_estimate_very_slow("."), Ok(1144));
        assert_eq!(
            get_regex_complexity_estimate_very_slow(".{1,10}"),
            Ok(10536)
        );
        assert_eq!(
            get_regex_complexity_estimate_very_slow(".{1,1000}"),
            Ok(1_040_136)
        );
    }

    #[test]
    fn test_empty_match_without_empty_string() {
        assert_eq!(
            validate_regex("\\bx{0,2}\\b"),
            Err(RegexValidationError::MatchesEmptyString)
        );
    }
}
