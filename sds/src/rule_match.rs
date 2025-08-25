use crate::match_validation::match_status::MatchStatus;
use crate::{StringMatch, encoding::Encoding, path::Path};
use std::fmt::Debug;
use std::fmt::{Display, Formatter};

/// Metadata about a rule match.
#[derive(Debug, PartialEq, PartialOrd, Ord, Eq)]
pub struct RuleMatch {
    /// The index of the rule that matched. This preserves the order
    /// of rules that were passed into the scanner.
    pub rule_index: usize,

    /// The path where the match occurred
    pub path: Path<'static>,

    /// The type of replacement that happened
    pub replacement_type: ReplacementType,

    /// The start of the match. This points to the replaced text, and not the original text.
    /// The index is based off of the encoding for the event.
    pub start_index: usize,

    /// The end, exclusive of the match. This points to the replaced text, and not
    /// the original text.
    /// The index is based off of the encoding for the event.
    pub end_index_exclusive: usize,

    ///  the difference between the end (UTF8 byte index) of the match data in the
    ///  **INPUT** string and the end (UTF8 byte index) of the match data applied to the new **OUTPUT** string after match actions
    ///  performed.
    pub shift_offset: isize,

    // matched string copied from content. If scanner has the return_matches set to true
    pub match_value: Option<String>,

    // match status updated by the validate_matches scanner method
    pub match_status: MatchStatus,
}

pub struct InternalRuleMatch<E: Encoding> {
    /// index of the rule that matched
    pub rule_index: usize,

    /// The index of the start of the match from the **INPUT** string (byte index of a UTF8 string)
    pub utf8_start: usize,

    /// The index of the end of a match from the **INPUT** string, exclusive (byte index of a UTF8 string)
    pub utf8_end: usize,

    /// The start index of the match, converted to a different encoding
    pub custom_start: <E as Encoding>::Index,

    /// The end index of the match, converted to a different encoding
    pub custom_end: <E as Encoding>::Index,
}

impl<E: Encoding> InternalRuleMatch<E> {
    pub fn new(rule_index: usize, string_match: StringMatch) -> Self {
        Self {
            rule_index,
            utf8_start: string_match.start,
            utf8_end: string_match.end,
            custom_start: E::zero_index(),
            custom_end: E::zero_index(),
        }
    }

    pub fn len(&self) -> usize {
        self.utf8_end - self.utf8_start
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReplacementType {
    None,
    Placeholder,
    Hash,
    PartialStart,
    PartialEnd,
}

impl Display for ReplacementType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplacementType::None => write!(f, "none"),
            ReplacementType::Placeholder => write!(f, "placeholder"),
            ReplacementType::Hash => write!(f, "hash"),
            ReplacementType::PartialStart => write!(f, "partial_beginning"),
            ReplacementType::PartialEnd => write!(f, "partial_end"),
        }
    }
}
