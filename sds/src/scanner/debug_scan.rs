use crate::{Event, RootRuleConfig, RuleConfig, RuleMatch, Scanner, ScannerError};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugRuleMatch {
    pub rule_match: RuleMatch,
    pub status: DebugRuleMatchStatus,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum DebugRuleMatchStatus {
    Matched,
    MissingIncludedKeyword,
    IncludedKeywordTooFar,
    ExcludedKeyword,
    NotInIncludedNamespace,
    Suppressed,
    ChecksumFailed,
}

pub fn debug_scan<E: Event>(
    event: &mut E,
    rule: RootRuleConfig<Arc<dyn RuleConfig>>,
) -> Result<Vec<DebugRuleMatch>, ScannerError> {
    // Currently only works with scanners containing a single regex rule and nothing else.

    let full_scanner = Scanner::builder(&[rule.clone().map_inner(|x| x as Arc<dyn RuleConfig>)])
        .build()
        .unwrap();

    let full_matches = full_scanner.scan(event)?;

    let mut output: Vec<DebugRuleMatch> = full_matches
        .into_iter()
        .map(|x| DebugRuleMatch {
            rule_match: x,
            status: DebugRuleMatchStatus::Matched,
        })
        .collect();

    if let Some(regex_rule) = rule.inner.as_regex_rule() {
        let mut regex_rule = regex_rule.clone();

        if let Some(proximity_keywords) = &mut regex_rule.proximity_keywords
            && !proximity_keywords.included_keywords.is_empty()
        {
            proximity_keywords.included_keywords = vec![];

            let scanner = Scanner::builder(&[rule.clone().map_inner(|_| regex_rule.build())])
                .build()
                .unwrap();

            let matches = scanner.scan(event)?;
            for m in matches {
                if !output.iter().any(|x| x.rule_match == m) {
                    output.push(DebugRuleMatch {
                        rule_match: m,
                        status: DebugRuleMatchStatus::MissingIncludedKeyword,
                    });
                }
            }
        }
    }

    Ok(output)

    // scan without included keywords
    // MissingIncludedKeyword,

    // custom function
    // IncludedKeywordTooFar,

    // scan with excluded keywords removed
    // ExcludedKeyword,

    // scan with full event
    // NotInIncludedNamespace,

    // directly call supressions
    // Suppressed,

    // scan without checksum
    // ChecksumFailed,

    // unimplemented!()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{MatchAction, RegexRuleConfig, RootRuleConfig};

    #[test]
    fn test_full_match() {
        let rule_config = RootRuleConfig::new(RegexRuleConfig::new("secret").build());

        let mut msg = "This is a secret".to_string();
        let matches = debug_scan(&mut msg, rule_config).unwrap();

        // Full match
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].status, DebugRuleMatchStatus::Matched);
        assert_eq!(matches[0].rule_match.start_index, 10);
    }

    #[test]
    fn test_missing_keyword() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("secret")
                .with_included_keywords(&["value"])
                .build(),
        )
        .match_action(MatchAction::redact("[REDACTED]"));

        let mut msg = "This is a secret".to_string();
        let matches = debug_scan(&mut msg, rule).unwrap();

        // Full match
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].status,
            DebugRuleMatchStatus::MissingIncludedKeyword
        );
        assert_eq!(matches[0].rule_match.start_index, 10);
    }
}
