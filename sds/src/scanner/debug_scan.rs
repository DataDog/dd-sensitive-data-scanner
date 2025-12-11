use crate::scanner::regex_rule::access_regex_caches;
use crate::scanner::regex_rule::compiled::RegexCompiledRule;
use crate::{
    CreateScannerError, Event, MatchAction, RegexRuleConfig, RootRuleConfig, RuleConfig, RuleMatch,
    Scanner, ScannerError, Scope,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugRuleMatch {
    pub rule_match: RuleMatch,
    #[serde(flatten)]
    pub status: DebugRuleMatchStatus,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum DebugRuleMatchStatus {
    Matched(MatchedInfo),
    MissingIncludedKeyword,
    IncludedKeywordTooFar,
    ExcludedKeyword(ExcludedInfo),
    NotInIncludedScope,
    InExcludedScope,
    Suppressed,
    ChecksumFailed,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MatchedInfo {
    included_keyword: Option<String>,
    included_keyword_start_index: Option<usize>,
    included_keyword_end_exclusive: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ExcludedInfo {
    pub excluded_keyword: Option<String>,
    pub excluded_keyword_start_index: Option<usize>,
    pub excluded_keyword_end_exclusive: Option<usize>,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum DebugScanError {
    #[error(transparent)]
    InvalidConfig(CreateScannerError),
    #[error(transparent)]
    ScanError(ScannerError),
}

impl From<CreateScannerError> for DebugScanError {
    fn from(value: CreateScannerError) -> Self {
        Self::InvalidConfig(value)
    }
}

impl From<ScannerError> for DebugScanError {
    fn from(value: ScannerError) -> Self {
        Self::ScanError(value)
    }
}

/// Similar to `.scan(), except more information is given for matches (such as the keyword),
/// and partial matches are also returned with a reason it wasn't a full match.
/// The current implementation is only able to return partial matches if there was a single issue.
///
/// This function should be considered experimental, and is not intended for use where performance
/// is critical.
pub fn debug_scan<E: Event>(
    event: &mut E,
    mut rule: RootRuleConfig<Arc<dyn RuleConfig>>,
) -> Result<Vec<DebugRuleMatch>, DebugScanError> {
    // prevent the output from changing
    rule.match_action = MatchAction::None;

    let full_scanner = Scanner::builder(&[rule.clone().map_inner(|x| x as Arc<dyn RuleConfig>)])
        .build()
        .map_err(DebugScanError::InvalidConfig)?;

    let full_matches = full_scanner.scan(event)?;

    let mut output: Vec<DebugRuleMatch> =
        full_matches
            .into_iter()
            .map(|rule_match| {
                let mut matched_status_info = MatchedInfo {
                    included_keyword: None,
                    included_keyword_start_index: None,
                    included_keyword_end_exclusive: None,
                };
                if let Some(compiled_regex_rule) = full_scanner.rules[0].as_regex_rule()
                    && let Some(compiled_included_keywords) = &compiled_regex_rule.included_keywords
                {
                    event.visit_string_mut(&rule_match.path, |content| {
                        access_regex_caches(|caches| {
                            if let Some(info) = compiled_included_keywords
                                .find_keyword_before_match(rule_match.start_index, caches, content)
                            {
                                matched_status_info.included_keyword = Some(info.keyword);
                                matched_status_info.included_keyword_start_index =
                                    Some(info.keyword_start_index);
                                matched_status_info.included_keyword_end_exclusive =
                                    Some(info.keyword_end_index_exclusive);
                            }
                        });
                        false
                    });
                }

                DebugRuleMatch {
                    rule_match,
                    status: DebugRuleMatchStatus::Matched(matched_status_info),
                }
            })
            .collect();

    if let Some(regex_rule) = rule.inner.as_regex_rule() {
        let regex_compiled_rule = full_scanner.rules[0].as_regex_rule().unwrap();
        debug_scan_regex(event, &rule, regex_rule, &mut output, regex_compiled_rule)?;
    }
    debug_scan_included_scope(event, &rule, &mut output)?;
    debug_scan_excluded_scope(event, &rule, &mut output)?;
    debug_scan_suppressions(event, &rule, &mut output)?;

    Ok(output)
}

fn debug_scan_regex<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
    output: &mut Vec<DebugRuleMatch>,
    regex_compiled_rule: &RegexCompiledRule,
) -> Result<(), ScannerError> {
    debug_scan_included_keywords(event, root_rule, regex_rule, output)?;
    debug_scan_excluded_keywords(event, root_rule, regex_rule, output, regex_compiled_rule)?;
    debug_scan_checksum(event, root_rule, regex_rule, output)?;
    Ok(())
}

fn debug_scan_included_keywords<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
    output: &mut Vec<DebugRuleMatch>,
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
    output: &mut Vec<DebugRuleMatch>,
    regex_compiled_rule: &RegexCompiledRule,
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

        for m in matches {
            if !output.iter().any(|x| x.rule_match == m) {
                let mut excluded_info = ExcludedInfo {
                    excluded_keyword: None,
                    excluded_keyword_start_index: None,
                    excluded_keyword_end_exclusive: None,
                };

                if let Some(compiled_excluded_keywords) = &regex_compiled_rule.excluded_keywords {
                    event.visit_string_mut(&m.path, |content| {
                        if let Some(info) = compiled_excluded_keywords
                            .get_false_positive_match(content, m.start_index)
                        {
                            excluded_info.excluded_keyword_start_index = Some(info.start());
                            excluded_info.excluded_keyword_end_exclusive = Some(info.end());
                            excluded_info.excluded_keyword =
                                Some(content[info.start()..info.end()].to_string());
                        }
                        false
                    })
                }
                output.push(DebugRuleMatch {
                    rule_match: m,
                    status: DebugRuleMatchStatus::ExcludedKeyword(excluded_info),
                });
            }
        }
    }
    Ok(())
}

fn debug_scan_included_scope<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    output: &mut Vec<DebugRuleMatch>,
) -> Result<(), ScannerError> {
    let new_scope = match &root_rule.scope {
        Scope::Include {
            include: _,
            exclude,
        } => Scope::Exclude(exclude.clone()),
        _ => return Ok(()),
    };

    let mut root_rule = root_rule.clone();
    root_rule.scope = new_scope;

    let scanner = Scanner::builder(&[root_rule]).build().unwrap();

    let matches = scanner.scan(event)?;
    add_status_if_no_match(matches, output, DebugRuleMatchStatus::NotInIncludedScope);
    Ok(())
}

fn debug_scan_excluded_scope<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    output: &mut Vec<DebugRuleMatch>,
) -> Result<(), ScannerError> {
    let new_scope = match &root_rule.scope {
        Scope::Include { include, exclude } => {
            if exclude.is_empty() {
                return Ok(());
            }
            Scope::Include {
                include: include.clone(),
                exclude: vec![],
            }
        }
        Scope::Exclude(exclude) => {
            if exclude.is_empty() {
                return Ok(());
            }
            Scope::Exclude(vec![])
        }
    };

    let mut root_rule = root_rule.clone();
    root_rule.scope = new_scope;

    let scanner = Scanner::builder(&[root_rule]).build().unwrap();

    let matches = scanner.scan(event)?;
    add_status_if_no_match(matches, output, DebugRuleMatchStatus::InExcludedScope);
    Ok(())
}

fn debug_scan_checksum<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
    output: &mut Vec<DebugRuleMatch>,
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
    output: &mut Vec<DebugRuleMatch>,
) -> Result<(), ScannerError> {
    if root_rule.suppressions.is_none() {
        return Ok(());
    }

    let mut root_rule = root_rule.clone();
    root_rule.suppressions = None;

    let scanner = Scanner::builder(&[root_rule]).build().unwrap();

    let new_matches = scanner.scan(event)?;
    add_status_if_no_match(new_matches, output, DebugRuleMatchStatus::Suppressed);

    Ok(())
}

fn add_status_if_no_match(
    new_matches: Vec<RuleMatch>,
    output: &mut Vec<DebugRuleMatch>,
    status: DebugRuleMatchStatus,
) {
    for m in new_matches {
        if !output.iter().any(|x| x.rule_match == m) {
            output.push(DebugRuleMatch {
                rule_match: m,
                status: status.clone(),
            });
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        MatchAction, Path, PathSegment, RegexRuleConfig, RootRuleConfig, SecondaryValidator,
        SimpleEvent, Suppressions,
    };
    use std::collections::BTreeMap;

    #[test]
    fn test_full_match() {
        let rule_config = RootRuleConfig::new(RegexRuleConfig::new("secret").build());

        let mut msg = "This is a secret".to_string();
        let matches = debug_scan(&mut msg, rule_config).unwrap();

        // Full match
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].status,
            DebugRuleMatchStatus::Matched(MatchedInfo {
                included_keyword: None,
                included_keyword_start_index: None,
                included_keyword_end_exclusive: None,
            })
        );
        assert_eq!(matches[0].rule_match.start_index, 10);
    }

    #[test]
    fn test_full_match_with_included_keyword() {
        let rule_config = RootRuleConfig::new(
            RegexRuleConfig::new("secret")
                .with_included_keywords(&["a"])
                .build(),
        );

        let mut msg = "This is a secret".to_string();
        let matches = debug_scan(&mut msg, rule_config).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].status,
            DebugRuleMatchStatus::Matched(MatchedInfo {
                included_keyword: Some("a".to_string()),
                included_keyword_start_index: Some(8),
                included_keyword_end_exclusive: Some(9),
            })
        );
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
    fn test_with_excluded_keyword() {
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
            DebugRuleMatchStatus::ExcludedKeyword(ExcludedInfo {
                excluded_keyword: Some("a".to_string()),
                excluded_keyword_start_index: Some(8),
                excluded_keyword_end_exclusive: Some(9),
            })
        );
    }

    #[test]
    fn test_suppressions() {
        let rule = RootRuleConfig::new(RegexRuleConfig::new("secret").build())
            .match_action(MatchAction::redact("[REDACTED]"))
            .suppressions(Suppressions {
                starts_with: vec![],
                ends_with: vec![],
                exact_match: vec!["secret".to_string()],
            });

        let mut msg = "This is a secret".to_string();
        let matches = debug_scan(&mut msg, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].status, DebugRuleMatchStatus::Suppressed);
        assert_eq!(matches[0].rule_match.start_index, 10);
    }

    #[test]
    fn test_included_scope() {
        let rule = RootRuleConfig::new(RegexRuleConfig::new("secret").build())
            .match_action(MatchAction::redact("[REDACTED]"))
            .scope(Scope::include(vec![Path::from(vec![PathSegment::from(
                "tag",
            )])]));

        let mut map = BTreeMap::new();
        map.insert(
            "tag".to_string(),
            SimpleEvent::String("Not a match".to_string()),
        );
        map.insert(
            "tag2".to_string(),
            SimpleEvent::String("This is a secret".to_string()),
        );

        let mut event = SimpleEvent::Map(map);
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].status, DebugRuleMatchStatus::NotInIncludedScope);
        assert_eq!(matches[0].rule_match.start_index, 10);
    }

    #[test]
    fn test_excluded_scope() {
        let rule = RootRuleConfig::new(RegexRuleConfig::new("secret").build())
            .match_action(MatchAction::redact("[REDACTED]"))
            .scope(Scope::exclude(vec![Path::from(vec![PathSegment::from(
                "tag",
            )])]));

        let mut map = BTreeMap::new();
        map.insert(
            "tag".to_string(),
            SimpleEvent::String("Contains a secret".to_string()),
        );

        let mut event = SimpleEvent::Map(map);
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].status, DebugRuleMatchStatus::InExcludedScope);
    }

    #[test]
    fn test_checksum() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}")
                .with_validator(Some(SecondaryValidator::LuhnChecksum))
                .build(),
        );

        let mut event = "1234-1234-1234-1235".to_string();
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].status, DebugRuleMatchStatus::ChecksumFailed);
    }
}
