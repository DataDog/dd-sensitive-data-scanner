use std::convert::From;

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
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CreateScannerError {
    /// The regex is invalid (too long, too complex, etc.)
    InvalidRegex(RegexValidationError),
    /// The included keywords config is invalid (empty keyword, too many keywords, etc.)
    InvalidKeywords(ProximityKeywordsValidationError),
    /// Invalid configuration of a match action
    InvalidMatchAction(MatchActionValidationError),
}

impl From<RegexValidationError> for CreateScannerError {
    fn from(err: RegexValidationError) -> Self {
        CreateScannerError::InvalidRegex(err)
    }
}

impl From<ProximityKeywordsValidationError> for CreateScannerError {
    fn from(err: ProximityKeywordsValidationError) -> Self {
        CreateScannerError::InvalidKeywords(err)
    }
}

impl From<MatchActionValidationError> for CreateScannerError {
    fn from(value: MatchActionValidationError) -> Self {
        CreateScannerError::InvalidMatchAction(value)
    }
}
