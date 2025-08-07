use std::convert::From;
use thiserror::Error;

use crate::{
    match_action::MatchActionValidationError, proximity_keywords::ProximityKeywordsValidationError,
    RegexValidationError,
};

impl From<CreateScannerError> for i64 {
    fn from(value: CreateScannerError) -> i64 {
        match value {
            CreateScannerError::InvalidRegex(_) => -2,
            CreateScannerError::InvalidKeywords(_) => -3,
            CreateScannerError::InvalidMatchAction(_) => -4,
            CreateScannerError::InvalidMatchValidator(_) => -5,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum MatchValidatorCreationError {
    #[error("Internal error while creating the match validator")]
    InternalError,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum CreateScannerError {
    //The regex is invalid (too long, too complex, etc.)
    #[error(transparent)]
    InvalidRegex(#[from] RegexValidationError),
    /// The included keywords config is invalid (empty keyword, too many keywords, etc.)
    #[error(transparent)]
    InvalidKeywords(#[from] ProximityKeywordsValidationError),
    /// Invalid configuration of a match action
    #[error(transparent)]
    InvalidMatchAction(#[from] MatchActionValidationError),
    /// The match validator cannot be created
    #[error(transparent)]
    InvalidMatchValidator(#[from] MatchValidatorCreationError),
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum MatchValidationError {
    #[error("No MatchValidationType provided")]
    NoMatchValidationType,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ScannerError {
    #[error("Transient error while scanning")]
    Transient(String),
}

#[cfg(test)]
mod test {
    use crate::match_action::MatchActionValidationError;
    use crate::proximity_keywords::ProximityKeywordsValidationError;
    use crate::{CreateScannerError, RegexValidationError};

    fn test_error(error: CreateScannerError, expected_display: &str) {
        assert_eq!(error.to_string(), expected_display)
    }

    #[test]
    fn test_invalid_keywords() {
        test_error(
            CreateScannerError::InvalidKeywords(ProximityKeywordsValidationError::EmptyKeyword),
            "Empty keywords are not allowed",
        );

        test_error(
            CreateScannerError::InvalidKeywords(ProximityKeywordsValidationError::TooManyKeywords),
            "No more than 50 keywords are allowed",
        );

        test_error(
            CreateScannerError::InvalidKeywords(ProximityKeywordsValidationError::KeywordTooLong(
                10,
            )),
            "Keywords cannot be longer than the look ahead character count (10)",
        );

        test_error(
            CreateScannerError::InvalidKeywords(
                ProximityKeywordsValidationError::InvalidLookAheadCharacterCount,
            ),
            "Look ahead character count should be bigger than 0 and cannot be longer than 50",
        )
    }

    #[test]
    fn test_invalid_regex() {
        test_error(
            CreateScannerError::InvalidRegex(RegexValidationError::InvalidSyntax),
            "Invalid regex syntax",
        );
        test_error(
            CreateScannerError::InvalidRegex(RegexValidationError::ExceededDepthLimit),
            "The regex pattern is nested too deeply",
        );
        test_error(
            CreateScannerError::InvalidRegex(RegexValidationError::TooComplex),
            "The regex has exceeded the complexity limit (try simplifying the regex)",
        );
        test_error(
            CreateScannerError::InvalidRegex(RegexValidationError::MatchesEmptyString),
            "Regex patterns are not allowed to match an empty string",
        );
    }

    #[test]
    fn test_match_action() {
        test_error(
            CreateScannerError::InvalidMatchAction(
                MatchActionValidationError::PartialRedactionNumCharsZero,
            ),
            "Partial redaction chars must be non-zero",
        );
    }
}
