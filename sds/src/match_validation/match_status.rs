use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone, Serialize, Deserialize)]
pub enum MatchStatus {
    // The ordering here is important, values further down the list have a higher priority when merging.
    NotChecked,
    NotAvailable,
    /// Missing matches that are required for the match to be checked
    MissingDependentMatch,
    Invalid,
    ValidationError(ValidationError),
    Valid,
}

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone, Serialize, Deserialize)]
pub enum ValidationError {
    LackingConditionsCoverage(LackingConditionsInfo),
    HttpError(HttpErrorInfo),
}

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone, Serialize, Deserialize)]
pub struct HttpErrorInfo {
    pub status_code: u16,
    pub message: String,
}

#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone, Serialize, Deserialize)]
pub struct LackingConditionsInfo {
    pub status_code: u16,
    pub body_length: usize,
}

impl std::fmt::Display for MatchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchStatus::NotChecked => write!(f, "NotChecked"),
            MatchStatus::NotAvailable => write!(f, "NotAvailable"),
            MatchStatus::Invalid => write!(f, "Invalid"),
            MatchStatus::MissingDependentMatch => write!(f, "MissingDependentMatch",),
            MatchStatus::ValidationError(validation_error) => {
                write!(f, "Error({})", validation_error)
            }
            MatchStatus::Valid => write!(f, "Valid"),
        }
    }
}

impl std::fmt::Display for HttpErrorInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Http error: status_code: {}, message: {}",
            self.status_code, self.message
        )
    }
}

impl std::fmt::Display for LackingConditionsInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "No condition matched response with status_code: {} and body_length: {}",
            self.status_code, self.body_length
        )
    }
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::LackingConditionsCoverage(inner) => inner.fmt(f),
            ValidationError::HttpError(inner) => inner.fmt(f),
        }
    }
}

impl MatchStatus {
    // Order matters as we want to update the match_status only if the new match_status has higher priority.
    // (in case of split key where we try different combinations of id and secret (aws use-case))
    pub fn merge(&mut self, new_status: MatchStatus) {
        // If the new and old status are both HttpError with differing messages, we concatenate the message part.
        if let (
            MatchStatus::ValidationError(ValidationError::HttpError(HttpErrorInfo {
                status_code: old_status_code,
                message: old_message,
            })),
            MatchStatus::ValidationError(ValidationError::HttpError(HttpErrorInfo {
                status_code: _new_status_code,
                message: new_message,
            })),
        ) = (&self, &new_status)
            && old_message != new_message
        {
            *self = MatchStatus::ValidationError(ValidationError::HttpError(HttpErrorInfo {
                status_code: *old_status_code,
                message: format!("{}, {}", old_message, new_message),
            }));
            return;
        }
        if new_status > *self {
            *self = new_status;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge() {
        let mut status = MatchStatus::NotChecked;
        status.merge(MatchStatus::NotAvailable);
        assert_eq!(status, MatchStatus::NotAvailable);

        status.merge(MatchStatus::Invalid);
        assert_eq!(status, MatchStatus::Invalid);

        status.merge(MatchStatus::Error("error".to_string()));
        assert_eq!(status, MatchStatus::Error("error".to_string()));

        status.merge(MatchStatus::Valid);
        assert_eq!(status, MatchStatus::Valid);
    }
    #[test]
    fn test_merge_lower_prio() {
        let mut status = MatchStatus::Valid;
        status.merge(MatchStatus::NotChecked);
        assert_eq!(status, MatchStatus::Valid);

        status.merge(MatchStatus::NotAvailable);
        assert_eq!(status, MatchStatus::Valid);

        status.merge(MatchStatus::Invalid);
        assert_eq!(status, MatchStatus::Valid);

        status.merge(MatchStatus::Error("error".to_string()));
        assert_eq!(status, MatchStatus::Valid);

        status = MatchStatus::Error("error".to_string());
        status.merge(MatchStatus::NotChecked);

        assert_eq!(status, MatchStatus::Error("error".to_string()));

        status.merge(MatchStatus::NotAvailable);
        assert_eq!(status, MatchStatus::Error("error".to_string()));

        status.merge(MatchStatus::Invalid);
        assert_eq!(status, MatchStatus::Error("error".to_string()));

        status = MatchStatus::Invalid;
        status.merge(MatchStatus::NotChecked);
        assert_eq!(status, MatchStatus::Invalid);

        status.merge(MatchStatus::NotAvailable);
        assert_eq!(status, MatchStatus::Invalid);

        status = MatchStatus::NotAvailable;
        status.merge(MatchStatus::NotChecked);
        assert_eq!(status, MatchStatus::NotAvailable);
    }
}
