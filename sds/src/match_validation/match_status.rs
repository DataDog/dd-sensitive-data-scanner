// Order matters as we want to update the match_status only if the new match_status has higher priority.
// (in case of split key where we try different combinations of id and secret (aws usecase))
#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone)]
pub enum MatchStatus {
    NotChecked,
    NotAvailable,
    Error(String),
    Invalid,
    Valid,
}
