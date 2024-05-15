use crate::RuleConfigTrait;
use crate::{Labels, MatchAction, RegexRuleConfig, Scope};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::BufReader;
use std::path::Path;

#[derive(Serialize, Deserialize)]
pub struct StandardRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub priority: u32,
    pub pattern: String,
    #[serde(default)]
    pub included_keywords: Vec<String>,
    pub tags: Vec<String>,
    pub labels: Vec<String>,
}

pub fn get_standard_rules<P: AsRef<Path>>(
    directory: P,
) -> Result<Vec<StandardRule>, Box<dyn std::error::Error>> {
    let mut rules = vec![];
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.path().is_dir() {
            rules.extend(get_standard_rules(entry.path())?);
        } else {
            let file = fs::File::open(entry.path())?;
            let reader = BufReader::new(file);
            rules.push(serde_yaml::from_reader(reader)?);
        }
    }
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(rules)
}

/// This is just a helper method to convert standard rules into configuration to make
/// creating a scanner easier. If you want to customize match_action, scope, or anything else
/// per rule, the config should be created manually.
pub fn get_simple_standard_rule_configs(
    rules: &[StandardRule],
    match_action: MatchAction,
    scope: Scope,
) -> Vec<Box<dyn RuleConfigTrait>> {
    rules
        .iter()
        .map(|rule| {
            Box::new(RegexRuleConfig {
                pattern: rule.pattern.clone(),
                match_action: match_action.clone(),
                scope: scope.clone(),
                proximity_keywords: None,
                validator: None,
                // Labels on the `StandardRule` are inteded to be added to the event if there is a match, not necessarily
                // for observability metrics, which is what the `labels` here is used for
                labels: Labels::empty(),
            }) as Box<dyn RuleConfigTrait>
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Scanner;

    #[test]
    fn test_get_standard_rules() {
        let rules = get_standard_rules("data/test_standard_rules").unwrap();
        assert_eq!(rules.len(), 2);

        // Rules should be sorted by id
        assert_eq!(rules[0].id, "bhfh3o786gy");
        assert_eq!(rules[1].id, "oa873tg4iluhan3");
    }

    #[test]
    fn test_standard_rule_config() {
        let rules = get_standard_rules("data/test_standard_rules").unwrap();
        let configs = get_simple_standard_rule_configs(
            &rules,
            MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            },
            Scope::all(),
        );
        let scanner = Scanner::new(&configs).unwrap();

        let mut content = "hello wonderful world, this is a test of the standard rules".to_string();

        let rule_matches = scanner.scan(&mut content);

        // Rules should be sorted by id
        assert_eq!(rule_matches.len(), 2);
        assert_eq!(
            content,
            "hello wonderful [REDACTED], this is a [REDACTED] of the standard rules"
        );
    }
}
