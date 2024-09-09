#[derive(Debug, PartialEq, PartialOrd, Ord, Eq, Clone)]
pub enum MatchStatus {
    NotChecked,
    NotAvailable,
    Error(String),
    Invalid,
    Valid,
}
