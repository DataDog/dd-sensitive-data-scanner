#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone)]
pub enum MatchStatus {
    // The ordering here is important, values further down the list have a higher priority when merging.
    NotChecked,
    NotAvailable,
    Invalid,
    Error(String),
    Valid,
}

impl std::fmt::Display for MatchStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchStatus::NotChecked => write!(f, "NotChecked"),
            MatchStatus::NotAvailable => write!(f, "NotAvailable"),
            MatchStatus::Invalid => write!(f, "Invalid"),
            MatchStatus::Error(msg) => write!(f, "Error({})", msg),
            MatchStatus::Valid => write!(f, "Valid"),
        }
    }
}

impl MatchStatus {
    // Order matters as we want to update the match_status only if the new match_status has higher priority.
    // (in case of split key where we try different combinations of id and secret (aws use-case))
    pub fn merge(&mut self, new_status: MatchStatus) {
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
