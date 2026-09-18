use crate::scanner::regex_rule::access_regex_caches;
use crate::scanner::regex_rule::compiled::RegexCompiledRule;
use crate::{
    CreateScannerError, Event, MatchAction, ProximityKeywordsConfig, RegexRuleConfig,
    RootRuleConfig, RuleConfig, RuleMatch, Scanner, ScannerError, Scope,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct DebugRuleMatch {
    pub rule_match: RuleMatch,
    pub statuses: Vec<DebugRuleMatchStatus>,
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
///
/// A partial match lists every condition that rejected it, not only the first one.
/// The output is sorted by path, then by start index.
///
/// This function should be considered experimental, and is not intended for use where performance
/// is critical.
pub fn debug_scan<E: Event>(
    event: &mut E,
    mut rule: RootRuleConfig<Arc<dyn RuleConfig>>,
) -> Result<Vec<DebugRuleMatch>, DebugScanError> {
    // prevent the output from changing
    rule.match_action = MatchAction::None;

    let full_scanner = single_rule_scanner(rule.clone())?;
    let full_matches = full_scanner.scan(event)?;
    let mut output =
        matched_debug_matches(event, full_matches, full_scanner.rules[0].as_regex_rule());

    let relaxed_rule = relaxed_rule_from(&rule);
    let probes = condition_probes(event, &rule, &relaxed_rule)?;
    if !probes.is_empty() {
        let candidates = single_rule_scanner(relaxed_rule)?.scan(event)?;
        let partials = partial_debug_matches(
            event,
            candidates,
            &probes,
            full_scanner.rules[0].as_regex_rule(),
            &output,
        );
        output.extend(partials);
    }

    output.sort_by(|left, right| {
        left.rule_match.path.cmp(&right.rule_match.path).then(
            left.rule_match
                .start_index
                .cmp(&right.rule_match.start_index),
        )
    });

    Ok(output)
}

fn single_rule_scanner(
    rule: RootRuleConfig<Arc<dyn RuleConfig>>,
) -> Result<Scanner, DebugScanError> {
    Scanner::builder(&[rule])
        .build()
        .map_err(DebugScanError::InvalidConfig)
}

/// The rule with every condition disabled: open scope, no suppressions, no keywords, no
/// validator. Scanning with it yields every regex candidate.
fn relaxed_rule_from(
    rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
) -> RootRuleConfig<Arc<dyn RuleConfig>> {
    let mut relaxed_rule = rule.clone();
    relaxed_rule.scope = Scope::all();
    relaxed_rule.suppressions = None;
    if let Some(regex_rule) = rule.inner.as_regex_rule() {
        let mut relaxed_regex_rule = regex_rule.clone();
        relaxed_regex_rule.proximity_keywords = None;
        relaxed_regex_rule.validator = None;
        relaxed_rule = relaxed_rule.map_inner(|_| relaxed_regex_rule.build());
    }
    relaxed_rule
}

fn cloned_relaxed_regex_rule(
    relaxed_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
) -> RegexRuleConfig {
    relaxed_rule
        .inner
        .as_regex_rule()
        .expect("relaxing a regex rule must preserve its rule type")
        .clone()
}

fn matched_debug_matches<E: Event>(
    event: &mut E,
    full_matches: Vec<RuleMatch>,
    regex_compiled_rule: Option<&RegexCompiledRule>,
) -> Vec<DebugRuleMatch> {
    full_matches
        .into_iter()
        .map(|rule_match| {
            let matched_info = included_keyword_info(event, &rule_match, regex_compiled_rule);
            DebugRuleMatch {
                rule_match,
                statuses: vec![DebugRuleMatchStatus::Matched(matched_info)],
            }
        })
        .collect()
}

/// Partial matches: regex candidates the full scanner rejected, each with the list of
/// conditions that rejected it.
fn partial_debug_matches<E: Event>(
    event: &mut E,
    candidates: Vec<RuleMatch>,
    probes: &[ConditionProbe],
    regex_compiled_rule: Option<&RegexCompiledRule>,
    full_matches: &[DebugRuleMatch],
) -> Vec<DebugRuleMatch> {
    let mut partials = Vec::new();
    for candidate in candidates {
        if full_matches
            .iter()
            .any(|full_match| full_match.rule_match == candidate)
        {
            continue;
        }

        let statuses = failing_statuses(event, &candidate, probes, regex_compiled_rule);

        // Each probe enables exactly one condition on top of the fully relaxed rule, so a candidate
        // the full scanner rejected is expected to fail at least one probe. This guard is defensive:
        // scanning advances one character past a rejected match but jumps to the end of an accepted
        // one, so which offsets get examined depends on the active conditions and the attribution is
        // not guaranteed by construction. An empty list is dropped rather than reported, because
        // consumers treat a match with no failing condition as a full match.
        if !statuses.is_empty() {
            partials.push(DebugRuleMatch {
                rule_match: candidate,
                statuses,
            });
        }
    }
    partials
}

fn failing_statuses<E: Event>(
    event: &mut E,
    candidate: &RuleMatch,
    probes: &[ConditionProbe],
    regex_compiled_rule: Option<&RegexCompiledRule>,
) -> Vec<DebugRuleMatchStatus> {
    probes
        .iter()
        .filter(|probe| {
            !probe
                .matches
                .iter()
                .any(|probe_match| probe_match == candidate)
        })
        .map(|probe| {
            probe
                .condition
                .status(event, candidate, regex_compiled_rule)
        })
        .collect()
}

#[derive(Clone, Copy)]
enum DebugCondition {
    IncludedKeyword,
    ExcludedKeyword,
    Checksum,
    IncludedScope,
    ExcludedScope,
    Suppression,
}

impl DebugCondition {
    fn status<E: Event>(
        self,
        event: &mut E,
        rule_match: &RuleMatch,
        regex_compiled_rule: Option<&RegexCompiledRule>,
    ) -> DebugRuleMatchStatus {
        match self {
            Self::IncludedKeyword => DebugRuleMatchStatus::MissingIncludedKeyword,
            Self::ExcludedKeyword => DebugRuleMatchStatus::ExcludedKeyword(excluded_keyword_info(
                event,
                rule_match,
                regex_compiled_rule,
            )),
            Self::Checksum => DebugRuleMatchStatus::ChecksumFailed,
            Self::IncludedScope => DebugRuleMatchStatus::NotInIncludedScope,
            Self::ExcludedScope => DebugRuleMatchStatus::InExcludedScope,
            Self::Suppression => DebugRuleMatchStatus::Suppressed,
        }
    }
}

struct ConditionProbe {
    condition: DebugCondition,
    matches: Vec<RuleMatch>,
}

/// One probe per configured condition, each active in isolation: a candidate absent from a
/// probe's matches was rejected by that condition. The probe order determines the status
/// order of the output.
fn condition_probes<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    relaxed_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
) -> Result<Vec<ConditionProbe>, DebugScanError> {
    let mut probes = Vec::new();

    if let Some(regex_rule) = root_rule.inner.as_regex_rule() {
        if let Some(probe) = included_keyword_probe(event, relaxed_rule, regex_rule)? {
            probes.push(probe);
        }
        if let Some(probe) = excluded_keyword_probe(event, relaxed_rule, regex_rule)? {
            probes.push(probe);
        }
        if let Some(probe) = checksum_probe(event, relaxed_rule, regex_rule)? {
            probes.push(probe);
        }
    }

    if let Some(probe) = included_scope_probe(event, root_rule, relaxed_rule)? {
        probes.push(probe);
    }
    if let Some(probe) = excluded_scope_probe(event, root_rule, relaxed_rule)? {
        probes.push(probe);
    }
    if let Some(probe) = suppression_probe(event, root_rule, relaxed_rule)? {
        probes.push(probe);
    }

    Ok(probes)
}

fn included_keyword_probe<E: Event>(
    event: &mut E,
    relaxed_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
) -> Result<Option<ConditionProbe>, DebugScanError> {
    let Some(proximity_keywords) = &regex_rule.proximity_keywords else {
        return Ok(None);
    };
    if proximity_keywords.included_keywords.is_empty() {
        return Ok(None);
    }

    let mut condition_regex_rule = cloned_relaxed_regex_rule(relaxed_rule);
    condition_regex_rule.proximity_keywords = Some(ProximityKeywordsConfig {
        excluded_keywords: vec![],
        ..proximity_keywords.clone()
    });

    scan_probe(
        event,
        relaxed_rule
            .clone()
            .map_inner(|_| condition_regex_rule.build()),
        DebugCondition::IncludedKeyword,
    )
    .map(Some)
}

fn excluded_keyword_probe<E: Event>(
    event: &mut E,
    relaxed_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
) -> Result<Option<ConditionProbe>, DebugScanError> {
    let Some(proximity_keywords) = &regex_rule.proximity_keywords else {
        return Ok(None);
    };
    if proximity_keywords.excluded_keywords.is_empty() {
        return Ok(None);
    }

    let mut condition_regex_rule = cloned_relaxed_regex_rule(relaxed_rule);
    condition_regex_rule.proximity_keywords = Some(ProximityKeywordsConfig {
        included_keywords: vec![],
        ..proximity_keywords.clone()
    });

    scan_probe(
        event,
        relaxed_rule
            .clone()
            .map_inner(|_| condition_regex_rule.build()),
        DebugCondition::ExcludedKeyword,
    )
    .map(Some)
}

fn checksum_probe<E: Event>(
    event: &mut E,
    relaxed_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    regex_rule: &RegexRuleConfig,
) -> Result<Option<ConditionProbe>, DebugScanError> {
    if regex_rule.validator.is_none() {
        return Ok(None);
    }

    let mut condition_regex_rule = cloned_relaxed_regex_rule(relaxed_rule);
    condition_regex_rule.validator = regex_rule.validator.clone();

    scan_probe(
        event,
        relaxed_rule
            .clone()
            .map_inner(|_| condition_regex_rule.build()),
        DebugCondition::Checksum,
    )
    .map(Some)
}

fn included_scope_probe<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    relaxed_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
) -> Result<Option<ConditionProbe>, DebugScanError> {
    let Scope::Include { include, .. } = &root_rule.scope else {
        return Ok(None);
    };

    let mut condition_rule = relaxed_rule.clone();
    condition_rule.scope = Scope::include(include.clone());

    scan_probe(event, condition_rule, DebugCondition::IncludedScope).map(Some)
}

fn excluded_scope_probe<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    relaxed_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
) -> Result<Option<ConditionProbe>, DebugScanError> {
    let (Scope::Include { exclude, .. } | Scope::Exclude(exclude)) = &root_rule.scope;
    if exclude.is_empty() {
        return Ok(None);
    }

    let mut condition_rule = relaxed_rule.clone();
    condition_rule.scope = Scope::exclude(exclude.clone());

    scan_probe(event, condition_rule, DebugCondition::ExcludedScope).map(Some)
}

fn suppression_probe<E: Event>(
    event: &mut E,
    root_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
    relaxed_rule: &RootRuleConfig<Arc<dyn RuleConfig>>,
) -> Result<Option<ConditionProbe>, DebugScanError> {
    let Some(suppressions) = &root_rule.suppressions else {
        return Ok(None);
    };
    if suppressions.starts_with.is_empty()
        && suppressions.ends_with.is_empty()
        && suppressions.exact_match.is_empty()
    {
        return Ok(None);
    }

    let mut condition_rule = relaxed_rule.clone();
    condition_rule.suppressions = Some(suppressions.clone());

    scan_probe(event, condition_rule, DebugCondition::Suppression).map(Some)
}

fn scan_probe<E: Event>(
    event: &mut E,
    rule: RootRuleConfig<Arc<dyn RuleConfig>>,
    condition: DebugCondition,
) -> Result<ConditionProbe, DebugScanError> {
    let scanner = single_rule_scanner(rule)?;
    Ok(ConditionProbe {
        condition,
        matches: scanner.scan(event)?,
    })
}

fn included_keyword_info<E: Event>(
    event: &mut E,
    rule_match: &RuleMatch,
    regex_compiled_rule: Option<&RegexCompiledRule>,
) -> MatchedInfo {
    let mut included_info = MatchedInfo {
        included_keyword: None,
        included_keyword_start_index: None,
        included_keyword_end_exclusive: None,
    };

    if let Some(compiled_included_keywords) =
        regex_compiled_rule.and_then(|rule| rule.included_keywords.as_ref())
    {
        event.visit_string_mut(&rule_match.path, |content| {
            access_regex_caches(|caches| {
                if let Some(info) = compiled_included_keywords.find_keyword_before_match(
                    rule_match.start_index,
                    caches,
                    content,
                ) {
                    included_info.included_keyword = Some(info.keyword);
                    included_info.included_keyword_start_index = Some(info.keyword_start_index);
                    included_info.included_keyword_end_exclusive =
                        Some(info.keyword_end_index_exclusive);
                }
            });
            false
        });
    }

    included_info
}

fn excluded_keyword_info<E: Event>(
    event: &mut E,
    rule_match: &RuleMatch,
    regex_compiled_rule: Option<&RegexCompiledRule>,
) -> ExcludedInfo {
    let mut excluded_info = ExcludedInfo {
        excluded_keyword: None,
        excluded_keyword_start_index: None,
        excluded_keyword_end_exclusive: None,
    };

    if let Some(compiled_excluded_keywords) =
        regex_compiled_rule.and_then(|rule| rule.excluded_keywords.as_ref())
    {
        event.visit_string_mut(&rule_match.path, |content| {
            if let Some(info) =
                compiled_excluded_keywords.get_false_positive_match(content, rule_match.start_index)
            {
                excluded_info.excluded_keyword_start_index = Some(info.start());
                excluded_info.excluded_keyword_end_exclusive = Some(info.end());
                excluded_info.excluded_keyword =
                    Some(content[info.start()..info.end()].to_string());
            }
            false
        });
    }

    excluded_info
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        EventVisitor, MatchAction, Path, PathSegment, RegexRuleConfig, RootRuleConfig,
        SecondaryValidator, SimpleEvent, Suppressions, Utf8Encoding,
    };
    use std::collections::BTreeMap;

    struct CountingEvent {
        content: String,
        visit_count: usize,
    }

    impl Event for CountingEvent {
        type Encoding = Utf8Encoding;

        fn visit_event<'path>(
            &'path mut self,
            visitor: &mut impl EventVisitor<'path>,
        ) -> Result<(), ScannerError> {
            self.visit_count += 1;
            visitor.visit_string(&self.content).map(|_| ())
        }

        fn visit_string_mut(&mut self, _path: &Path, visit: impl FnOnce(&mut String) -> bool) {
            (visit)(&mut self.content);
        }
    }

    #[test]
    fn test_full_match() {
        let rule_config = RootRuleConfig::new(RegexRuleConfig::new("secret").build());

        let mut msg = "This is a secret".to_string();
        let matches = debug_scan(&mut msg, rule_config).unwrap();

        // Full match
        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].statuses,
            vec![DebugRuleMatchStatus::Matched(MatchedInfo {
                included_keyword: None,
                included_keyword_start_index: None,
                included_keyword_end_exclusive: None,
            })]
        );
        assert_eq!(matches[0].rule_match.start_index, 10);
    }

    #[test]
    fn test_rule_without_conditions_scans_event_once() {
        let rule = RootRuleConfig::new(RegexRuleConfig::new("secret").build());
        let mut event = CountingEvent {
            content: "secret".to_string(),
            visit_count: 0,
        };

        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(event.visit_count, 1);
    }

    #[test]
    fn test_rule_with_empty_suppressions_scans_event_once() {
        let rule = RootRuleConfig::new(RegexRuleConfig::new("secret").build())
            .suppressions(Suppressions::default());
        let mut event = CountingEvent {
            content: "secret".to_string(),
            visit_count: 0,
        };

        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(event.visit_count, 1);
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
            matches[0].statuses,
            vec![DebugRuleMatchStatus::Matched(MatchedInfo {
                included_keyword: Some("a".to_string()),
                included_keyword_start_index: Some(8),
                included_keyword_end_exclusive: Some(9),
            })]
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
            matches[0].statuses,
            vec![DebugRuleMatchStatus::MissingIncludedKeyword]
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
            matches[0].statuses,
            vec![DebugRuleMatchStatus::ExcludedKeyword(ExcludedInfo {
                excluded_keyword: Some("a".to_string()),
                excluded_keyword_start_index: Some(8),
                excluded_keyword_end_exclusive: Some(9),
            })]
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
        assert_eq!(matches[0].statuses, vec![DebugRuleMatchStatus::Suppressed]);
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
        assert_eq!(
            matches[0].statuses,
            vec![DebugRuleMatchStatus::NotInIncludedScope]
        );
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
        assert_eq!(
            matches[0].statuses,
            vec![DebugRuleMatchStatus::InExcludedScope]
        );
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
        assert_eq!(
            matches[0].statuses,
            vec![DebugRuleMatchStatus::ChecksumFailed]
        );
    }

    #[test]
    fn test_missing_included_keyword_and_checksum_failure() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("[0-9]+")
                .with_included_keywords(&["value"])
                .with_validator(Some(SecondaryValidator::LuhnChecksum))
                .build(),
        );

        let mut event = "1234".to_string();
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].statuses,
            vec![
                DebugRuleMatchStatus::MissingIncludedKeyword,
                DebugRuleMatchStatus::ChecksumFailed,
            ]
        );
    }

    #[test]
    fn test_multi_status_serialization() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("[0-9]+")
                .with_included_keywords(&["value"])
                .with_validator(Some(SecondaryValidator::LuhnChecksum))
                .build(),
        );
        let mut event = "1234".to_string();

        let matches = debug_scan(&mut event, rule).unwrap();
        let serialized_match = serde_json::to_value(&matches[0]).unwrap();

        assert_eq!(
            serialized_match["statuses"],
            serde_json::json!([
                { "status": "MissingIncludedKeyword" },
                { "status": "ChecksumFailed" }
            ])
        );
        assert!(serialized_match.get("status").is_none());
    }

    #[test]
    fn test_included_keyword_too_far_deserialization() {
        let status: DebugRuleMatchStatus =
            serde_json::from_str(r#"{"status":"IncludedKeywordTooFar"}"#).unwrap();

        assert_eq!(status, DebugRuleMatchStatus::IncludedKeywordTooFar);
    }

    #[test]
    fn test_missing_included_keyword_and_suppression() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("secret")
                .with_included_keywords(&["value"])
                .build(),
        )
        .suppressions(Suppressions {
            starts_with: vec![],
            ends_with: vec![],
            exact_match: vec!["secret".to_string()],
        });

        let mut event = "secret".to_string();
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].statuses,
            vec![
                DebugRuleMatchStatus::MissingIncludedKeyword,
                DebugRuleMatchStatus::Suppressed,
            ]
        );
    }

    #[test]
    fn test_three_simultaneous_failures() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("[0-9]+")
                .with_included_keywords(&["value"])
                .with_validator(Some(SecondaryValidator::LuhnChecksum))
                .build(),
        )
        .suppressions(Suppressions {
            starts_with: vec![],
            ends_with: vec![],
            exact_match: vec!["1234".to_string()],
        });

        let mut event = "1234".to_string();
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].statuses,
            vec![
                DebugRuleMatchStatus::MissingIncludedKeyword,
                DebugRuleMatchStatus::ChecksumFailed,
                DebugRuleMatchStatus::Suppressed,
            ]
        );
    }

    #[test]
    fn test_outside_included_scope_and_inside_excluded_scope() {
        let rule = RootRuleConfig::new(RegexRuleConfig::new("secret").build()).scope(
            Scope::include_and_exclude(
                vec![Path::from(vec![PathSegment::from("allowed")])],
                vec![Path::from(vec![PathSegment::from("blocked")])],
            ),
        );

        let mut map = BTreeMap::new();
        map.insert(
            "blocked".to_string(),
            SimpleEvent::String("secret".to_string()),
        );
        let mut event = SimpleEvent::Map(map);
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].statuses,
            vec![
                DebugRuleMatchStatus::NotInIncludedScope,
                DebugRuleMatchStatus::InExcludedScope,
            ]
        );
    }

    #[test]
    fn test_multipass_rejection_reports_excluded_scope() {
        let rule = RootRuleConfig::new(RegexRuleConfig::new("secret").build()).scope(
            Scope::exclude(vec![Path::from(vec![PathSegment::from("outside")])]),
        );

        let mut map = BTreeMap::new();
        map.insert(
            "allowed".to_string(),
            SimpleEvent::String("secret".to_string()),
        );
        map.insert(
            "outside".to_string(),
            SimpleEvent::String("secret".to_string()),
        );
        let mut event = SimpleEvent::Map(map);

        let matches = debug_scan(&mut event, rule).unwrap();
        let allowed_match = matches
            .iter()
            .find(|debug_match| {
                debug_match.rule_match.path == Path::from(vec![PathSegment::from("allowed")])
            })
            .unwrap();

        assert_eq!(
            allowed_match.statuses,
            vec![DebugRuleMatchStatus::InExcludedScope]
        );
    }

    #[test]
    fn test_excluded_keyword_and_checksum_failure_preserve_keyword_info() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("[0-9]+")
                .with_excluded_keywords(&["blocked"])
                .with_validator(Some(SecondaryValidator::LuhnChecksum))
                .build(),
        );

        let mut event = "blocked 1234".to_string();
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].statuses,
            vec![
                DebugRuleMatchStatus::ExcludedKeyword(ExcludedInfo {
                    excluded_keyword: Some("blocked".to_string()),
                    excluded_keyword_start_index: Some(0),
                    excluded_keyword_end_exclusive: Some(7),
                }),
                DebugRuleMatchStatus::ChecksumFailed,
            ]
        );
    }

    #[test]
    fn test_missing_included_keyword_and_excluded_keyword() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("secret")
                .with_included_keywords(&["value"])
                .with_excluded_keywords(&["blocked"])
                .build(),
        );

        let mut event = "blocked secret".to_string();
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].statuses,
            vec![
                DebugRuleMatchStatus::MissingIncludedKeyword,
                DebugRuleMatchStatus::ExcludedKeyword(ExcludedInfo {
                    excluded_keyword: Some("blocked".to_string()),
                    excluded_keyword_start_index: Some(0),
                    excluded_keyword_end_exclusive: Some(7),
                }),
            ]
        );
    }

    #[test]
    fn test_missing_included_keyword_and_excluded_scope() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("secret")
                .with_included_keywords(&["value"])
                .build(),
        )
        .scope(Scope::exclude(vec![Path::from(vec![PathSegment::from(
            "tag",
        )])]));

        let mut map = BTreeMap::new();
        map.insert("tag".to_string(), SimpleEvent::String("secret".to_string()));

        let mut event = SimpleEvent::Map(map);
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(
            matches[0].statuses,
            vec![
                DebugRuleMatchStatus::MissingIncludedKeyword,
                DebugRuleMatchStatus::InExcludedScope,
            ]
        );
    }

    #[test]
    fn test_each_candidate_reports_its_own_statuses() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("[0-9]+")
                .with_excluded_keywords(&["blocked"])
                .build(),
        )
        .suppressions(Suppressions {
            starts_with: vec![],
            ends_with: vec![],
            exact_match: vec!["4242".to_string()],
        });

        let mut map = BTreeMap::new();
        map.insert(
            "excluded".to_string(),
            SimpleEvent::String("blocked 1234".to_string()),
        );
        map.insert(
            "suppressed".to_string(),
            SimpleEvent::String("4242".to_string()),
        );

        let mut event = SimpleEvent::Map(map);
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 2);
        assert_eq!(
            matches[0].rule_match.path,
            Path::from(vec![PathSegment::from("excluded")])
        );
        assert_eq!(
            matches[0].statuses,
            vec![DebugRuleMatchStatus::ExcludedKeyword(ExcludedInfo {
                excluded_keyword: Some("blocked".to_string()),
                excluded_keyword_start_index: Some(0),
                excluded_keyword_end_exclusive: Some(7),
            })]
        );
        assert_eq!(
            matches[1].rule_match.path,
            Path::from(vec![PathSegment::from("suppressed")])
        );
        assert_eq!(matches[1].statuses, vec![DebugRuleMatchStatus::Suppressed]);
    }

    #[test]
    fn test_full_match_and_partial_match_in_same_event() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("secret")
                .with_excluded_keywords(&["blocked"])
                .build(),
        );

        let mut map = BTreeMap::new();
        map.insert(
            "allowed".to_string(),
            SimpleEvent::String("secret".to_string()),
        );
        map.insert(
            "blocked".to_string(),
            SimpleEvent::String("blocked secret".to_string()),
        );

        let mut event = SimpleEvent::Map(map);
        let matches = debug_scan(&mut event, rule).unwrap();

        assert_eq!(matches.len(), 2);
        assert_eq!(
            matches[0].rule_match.path,
            Path::from(vec![PathSegment::from("allowed")])
        );
        assert_eq!(
            matches[0].statuses,
            vec![DebugRuleMatchStatus::Matched(MatchedInfo {
                included_keyword: None,
                included_keyword_start_index: None,
                included_keyword_end_exclusive: None,
            })]
        );
        assert_eq!(
            matches[1].rule_match.path,
            Path::from(vec![PathSegment::from("blocked")])
        );
        assert_eq!(
            matches[1].statuses,
            vec![DebugRuleMatchStatus::ExcludedKeyword(ExcludedInfo {
                excluded_keyword: Some("blocked".to_string()),
                excluded_keyword_start_index: Some(0),
                excluded_keyword_end_exclusive: Some(7),
            })]
        );
    }

    #[test]
    fn test_no_regex_candidate_returns_no_matches() {
        let rule = RootRuleConfig::new(
            RegexRuleConfig::new("secret")
                .with_included_keywords(&["value"])
                .with_validator(Some(SecondaryValidator::LuhnChecksum))
                .build(),
        );

        let mut event = "nothing to find".to_string();
        let matches = debug_scan(&mut event, rule).unwrap();

        assert!(matches.is_empty());
    }
}
