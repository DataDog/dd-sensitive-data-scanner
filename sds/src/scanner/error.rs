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
            CreateScannerError::InvalidMetadata(_) => -6,
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
    // The metadata used to create the scanner is invalid
    #[error(transparent)]
    InvalidMetadata(#[from] ScannerMetadataError)
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum MatchValidationError {
    #[error("No MatchValidationType provided")]
    NoMatchValidationType,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ScannerMetadataError {
    //ID
    #[error("ID is too short, must be at least {0} characters long")]
    IdTooShort(usize),

    //Name
    #[error("`name` field must not be trim empty")]
    NameTrimEmpty,
    #[error("`name` field is too long, at most {0} characters are allowed, the current name has {1} characters")]
    NameTooLong(usize, usize),
    #[error("`description` field must not be trim empty")]

    //Description
    DescriptionTrimEmpty,
    #[error("`description` field is too long, at most {0} characters are allowed, the current description has {1} characters")]
    DescriptionTooLong(usize, usize),
    #[error("`description` field is not correctly formatted, description should follow the template:
              ```
              [DESCRIPTION OF THE SENSITIVE DATA FORMAT]

              Examples of matching formats: [Example of matching format: if a single example]
              - `[EXAMPLE_1]`
              - `[EXAMPLE_2]`
              ```
              current description:
              ```
              %s
              ```")]
    DescriptionFormatInvalid,
    #[error("`description` example {0} does not match the rule's pattern")]
    DescriptionExampleDoesNotMatch(String),

    //Priority
    #[error("`priority` field should between 1 and 5")]
    PriorityInvalidValue,

    //Tags
    #[error("tag `{0}` in the `tags` field is not valid, all tags should be <key:value>")]
    InvalidTag(String),
    #[error("`{0}` tag is required but is missing in the `tags` field")]
    MissingTag(String),

    //Labels
    #[error("label `{0}` in the `labels` field is not valid, all labels should be <key:value>")]
    InvalidLabel(String),


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
