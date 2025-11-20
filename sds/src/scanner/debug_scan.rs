use crate::{Event, MatchAction, RegexRuleConfig, RootRuleConfig, RuleConfig, RuleMatch, Scanner, ScannerError};
use std::sync::Arc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugRuleMatch {
    pub rule_match: RuleMatch,
    pub status: DebugRuleMatchStatus,
}

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
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
    mut rule: RootRuleConfig<Arc<dyn RuleConfig>>,
) -> Result<Vec<DebugRuleMatch>, ScannerError> {
    // Currently only works with scanners containing a single regex rule and nothing else.

    // prevent the output from changing
    rule.match_action = MatchAction::None;

    let full_scanner = Scanner::builder(&[rule.clone().map_inner(|x| x as Arc<dyn RuleConfig>)])
        .build()
        // TODO: Handle errors better
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
        debug_scan_regex(event, &rule, regex_rule, &mut output)?;
    }

    Ok(output)

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
}

fn debug_scan_regex<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
    output: &mut Vec<DebugRuleMatch>
) -> Result<(), ScannerError> {
    debug_scan_included_keywords(event, root_rule, regex_rule, output)?;
    debug_scan_suppressions(event, root_rule, output)?;
    Ok(())
}

fn debug_scan_included_keywords<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
    output: &mut Vec<DebugRuleMatch>
) -> Result<(), ScannerError> {
    let mut regex_rule = regex_rule.clone();

    if let Some(proximity_keywords) = &mut regex_rule.proximity_keywords
        && !proximity_keywords.included_keywords.is_empty()
    {
        proximity_keywords.included_keywords = vec![];

        let scanner = Scanner::builder(&[root_rule.clone().map_inner(|_| regex_rule.build())])
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
    Ok(())
}

fn debug_scan_suppressions<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    output: &mut Vec<DebugRuleMatch>
) -> Result<(), ScannerError> {
    if root_rule.suppressions.is_none() {
        return Ok(());
    }

    let mut root_rule = root_rule.clone();
    root_rule.suppressions = None;


    let scanner = Scanner::builder(&[root_rule])
        .build()
        .unwrap();

    let new_matches = scanner.scan(event)?;
    add_status_if_no_match(new_matches, output, DebugRuleMatchStatus::Suppressed);

    Ok(())
}


fn add_status_if_no_match(
    new_matches: Vec<RuleMatch>,
    output: &mut Vec<DebugRuleMatch>,
    status: DebugRuleMatchStatus
) {
    for m in new_matches {
        if !output.iter().any(|x| x.rule_match == m) {
            output.push(DebugRuleMatch {
                rule_match: m,
                status
            });
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{MatchAction, RegexRuleConfig, RootRuleConfig, Suppressions};

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

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].status,
            DebugRuleMatchStatus::MissingIncludedKeyword
        );
        assert_eq!(matches[0].rule_match.start_index, 10);
    }

    #[test]
    fn test_suppressions() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("secret").build(),
        )
            .match_action(MatchAction::redact("[REDACTED]"))
            .suppressions(Suppressions {
                starts_with: vec![],
                ends_with: vec![],
                exact_match: vec!["secret".to_string()],
            });

        let mut msg = "This is a secret".to_string();
        let matches = debug_scan(&mut msg, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].status,
            DebugRuleMatchStatus::Suppressed
        );
        assert_eq!(matches[0].rule_match.start_index, 10);
    }
}
