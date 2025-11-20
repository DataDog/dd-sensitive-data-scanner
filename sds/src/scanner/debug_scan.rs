use crate::{Event, MatchAction, RegexRuleConfig, RootRuleConfig, RuleConfig, RuleMatch, Scanner, ScannerError, Scope};
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
    NotInIncludedScope,
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

    /*
    --- TODO ---
    - suppressions position / text
    - keyword position / text (included and excluded)
     */

    // custom function
    // IncludedKeywordTooFar,
}

fn debug_scan_regex<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
    output: &mut Vec<DebugRuleMatch>
) -> Result<(), ScannerError> {
    debug_scan_included_keywords(event, root_rule, regex_rule, output)?;
    debug_scan_suppressions(event, root_rule, output)?;
    debug_scan_excluded_keywords(event, root_rule, regex_rule, output)?;
    debug_scan_included_scope(event, root_rule, output)?;
    debug_scan_checksum(event, root_rule, regex_rule, output)?;
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

fn debug_scan_excluded_keywords<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
    output: &mut Vec<DebugRuleMatch>
) -> Result<(), ScannerError> {
    let mut regex_rule = regex_rule.clone();

    if let Some(proximity_keywords) = &mut regex_rule.proximity_keywords
        && !proximity_keywords.excluded_keywords.is_empty()
    {
        proximity_keywords.excluded_keywords = vec![];

        let scanner = Scanner::builder(&[root_rule.clone().map_inner(|_| regex_rule.build())])
            .build()
            .unwrap();

        let matches = scanner.scan(event)?;
        add_status_if_no_match(matches, output, DebugRuleMatchStatus::ExcludedKeyword);
    }
    Ok(())
}

fn debug_scan_included_scope<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    output: &mut Vec<DebugRuleMatch>
) -> Result<(), ScannerError> {
    let new_scope = match &root_rule.scope {
        Scope::Include { include: _, exclude } => {
            Scope::Exclude(exclude.clone())
        }
        _ => {
            return Ok(())
        }
    };

    let mut root_rule = root_rule.clone();
    root_rule.scope = new_scope;

    let scanner = Scanner::builder(&[root_rule])
        .build()
        .unwrap();

    let matches = scanner.scan(event)?;
    add_status_if_no_match(matches, output, DebugRuleMatchStatus::NotInIncludedScope);
    Ok(())
}

fn debug_scan_checksum<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
    output: &mut Vec<DebugRuleMatch>
) -> Result<(), ScannerError> {
    if regex_rule.validator.is_none() {
       return Ok(());
    }

    let mut regex_rule = regex_rule.clone();
    regex_rule.validator = None;

    let scanner = Scanner::builder(&[root_rule.clone().map_inner(|_| regex_rule.build())])
        .build()
        .unwrap();

    let matches = scanner.scan(event)?;
    add_status_if_no_match(matches, output, DebugRuleMatchStatus::ChecksumFailed);
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
    use std::collections::BTreeMap;
    use super::*;
    use crate::{MatchAction, Path, PathSegment, RegexRuleConfig, RootRuleConfig, SecondaryValidator, SimpleEvent, Suppressions};

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
    fn test_missing_included_keyword() {
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
    fn test_missing_excluded_keyword() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("secret")
                .with_excluded_keywords(&["a"])
                .build(),
        )
            .match_action(MatchAction::redact("[REDACTED]"));

        let mut msg = "This is a secret".to_string();
        let matches = debug_scan(&mut msg, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].status,
            DebugRuleMatchStatus::ExcludedKeyword
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

    #[test]
    fn test_included_scope() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("secret").build(),
        )
            .match_action(MatchAction::redact("[REDACTED]"))
            .scope(Scope::include(vec![Path::from(vec![PathSegment::from("tag")])]));

        let mut map = BTreeMap::new();
        map.insert("tag".to_string(), SimpleEvent::String("Not a match".to_string()));
        map.insert("tag2".to_string(), SimpleEvent::String("This is a secret".to_string()));

        let mut event = SimpleEvent::Map(map);
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].status,
            DebugRuleMatchStatus::NotInIncludedScope
        );
        assert_eq!(matches[0].rule_match.start_index, 10);
    }

    #[test]
    fn test_checksum() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}").with_validator(Some(SecondaryValidator::LuhnChecksum)).build(),
        );

        let mut event = "1234-1234-1234-1235".to_string();
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].status,
            DebugRuleMatchStatus::ChecksumFailed
        );
    }
}
