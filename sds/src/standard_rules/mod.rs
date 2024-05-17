use crate::{Labels, MatchAction, RegexRuleConfig, Scope};
use crate::{ProximityKeywordsConfig, RuleConfigTrait, SecondaryValidator};
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io::{BufReader, Write};
use std::path::Path;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct StandardRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub pattern: String,

    #[serde(default)]
    pub included_keywords: Vec<String>,

    #[serde(default)]
    pub validators: Vec<StandardRuleValidator>,

    /// Priority is not currently used by this library, but the data is available.
    pub priority: u32,

    /// Tags are not currently used by this library, but the data is available.
    #[serde(default)]
    pub tags: Vec<String>,

    /// Labels are not currently used by this library, but the data is available.
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum StandardRuleValidator {
    LuhnChecksum,
}

pub fn parse_standard_rules<P: AsRef<Path>>(
    directory: P,
) -> Result<Vec<StandardRule>, Box<dyn std::error::Error>> {
    let mut rules: Vec<StandardRule> = vec![];
    visit_files(directory, &mut |reader| {
        rules.push(serde_yaml::from_reader(reader)?);
        Ok(())
    })?;
    rules.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(rules)
}

pub fn serialize_standard_rules_list(rules: &[StandardRule], out: &mut impl Write) {
    serde_yaml::to_writer(out, rules).unwrap();
}

/// This is just a helper method to convert standard rules into configuration to make
/// creating a scanner easier. If you want to customize match_action, scope, or anything else
/// per rule, the config should be created manually.
pub fn get_simple_standard_rule_configs(
    rules: &[StandardRule],
    match_action: MatchAction,
    scope: Scope,
    proximity_keywords_look_ahead_count: Option<usize>,
) -> Vec<Box<dyn RuleConfigTrait>> {
    rules
        .iter()
        .map(|rule| {
            Box::new(RegexRuleConfig {
                pattern: rule.pattern.clone(),
                match_action: match_action.clone(),
                scope: scope.clone(),
                proximity_keywords: get_proximity_keywords(
                    &rule.included_keywords,
                    proximity_keywords_look_ahead_count,
                ),
                labels: Labels::empty(),
                validator: get_secondary_validator(&rule.validators),
            }) as Box<dyn RuleConfigTrait>
        })
        .collect()
}

fn get_proximity_keywords(
    included_keywords: &[String],
    count: Option<usize>,
) -> Option<ProximityKeywordsConfig> {
    let count = count?;

    if included_keywords.is_empty() {
        return None;
    }
    Some(ProximityKeywordsConfig {
        look_ahead_character_count: count,
        included_keywords: included_keywords.to_vec(),
        excluded_keywords: vec![],
    })
}

// Convert from `StandardRuleValidator` to `SecondaryValidator`
fn get_secondary_validator(validators: &[StandardRuleValidator]) -> Option<SecondaryValidator> {
    if validators.len() > 1 {
        panic!("More than 1 validator is not yet supported");
    }

    validators.first().map(|validator| match validator {
        StandardRuleValidator::LuhnChecksum => SecondaryValidator::LuhnChecksum,
    })
}

pub mod test_framework {
    use super::*;
    use crate::Scanner;
    use std::collections::{BTreeMap, HashMap};

    #[derive(Serialize, Deserialize)]
    pub struct StandardRuleTest {
        pub description: String,
        pub input: String,
        pub output: String,
        #[serde(default)]
        pub use_included_keywords: bool,
    }

    #[derive(PartialEq, PartialOrd, Ord, Eq)]
    pub struct TestFailure {
        pub rule_id: String,
        pub rule_name: String,
        pub test_description: String,
        pub expected_output: String,
        pub actual_output: String,
    }

    pub struct TestResults {
        pub failures: Vec<TestFailure>,
        pub successful_count: u32,
    }

    #[derive(Serialize, Deserialize)]
    struct StandardRuleTests {
        // The schema of this intentionally matches `StandardRule` so it can share the same file
        pub id: String,
        #[serde(default)]
        pub tests: Vec<StandardRuleTest>,
    }

    pub fn get_standard_rule_tests<P: AsRef<Path>>(
        directory: P,
    ) -> Result<BTreeMap<String, Vec<StandardRuleTest>>, Box<dyn std::error::Error>> {
        let mut test_cases = BTreeMap::new();
        visit_files(directory, &mut |reader| {
            let tests: StandardRuleTests = serde_yaml::from_reader(reader)?;
            test_cases
                .entry(tests.id)
                .or_insert(vec![])
                .extend(tests.tests);
            Ok(())
        })?;
        Ok(test_cases)
    }

    pub fn run_tests<P: AsRef<Path> + Clone>(directory: P) -> TestResults {
        let rules = parse_standard_rules(directory.clone()).unwrap();
        let rule_map: HashMap<String, StandardRule> =
            HashMap::from_iter(rules.into_iter().map(|rule| (rule.id.clone(), rule)));
        let tests = get_standard_rule_tests(directory).unwrap();

        let mut test_failures = vec![];
        let mut success_count = 0;

        for (rule_id, test_cases) in tests {
            let rule = rule_map
                .get(&rule_id)
                .expect("Standard rule not found for test");

            for test_case in test_cases {
                let scanner = Scanner::new(&get_simple_standard_rule_configs(
                    &[rule.clone()],
                    MatchAction::Redact {
                        replacement: "[REDACTED]".to_string(),
                    },
                    Scope::all(),
                    if test_case.use_included_keywords {
                        Some(30)
                    } else {
                        None
                    },
                ))
                .unwrap();

                let mut content = test_case.input.clone();
                let _rule_matches = scanner.scan(&mut content);
                if content == test_case.output {
                    success_count += 1;
                } else {
                    test_failures.push(TestFailure {
                        rule_id: rule_id.clone(),
                        rule_name: rule.name.clone(),
                        test_description: test_case.description,
                        expected_output: test_case.output,
                        actual_output: content,
                    });
                }
            }
        }
        test_failures.sort();
        TestResults {
            failures: test_failures,
            successful_count: success_count,
        }
    }
}

pub fn visit_files<P: AsRef<Path>>(
    directory: P,
    visitor: &mut impl FnMut(BufReader<File>) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // let mut rules = vec![];
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.path().is_dir() {
            visit_files(entry.path(), visitor)?;
        } else {
            let file = fs::File::open(entry.path())?;
            let reader = BufReader::new(file);
            visitor(reader)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Scanner;

    #[test]
    fn test_get_standard_rules() {
        let rules = parse_standard_rules("data/test_standard_rules").unwrap();
        assert_eq!(rules.len(), 3);

        // Rules should be sorted by id
        assert_eq!(rules[0].id, "bhfh3o786gy");
        assert_eq!(rules[1].id, "nbha3h7uah4ya34");
        assert_eq!(rules[2].id, "oa873tg4iluhan3");
    }

    #[test]
    fn test_standard_rule_config() {
        let rules = parse_standard_rules("data/test_standard_rules").unwrap();
        let configs = get_simple_standard_rule_configs(
            &rules,
            MatchAction::Redact {
                replacement: "[REDACTED]".to_string(),
            },
            Scope::all(),
            Some(30),
        );
        let scanner = Scanner::new(&configs).unwrap();

        let mut content = "hello wonderful world, this is a test of the standard rules".to_string();

        let rule_matches = scanner.scan(&mut content);

        assert_eq!(rule_matches.len(), 2);
        assert_eq!(
            content,
            "hello wonderful [REDACTED], this is a [REDACTED] of the standard rules"
        );
    }

    #[test]
    fn test_standard_rule_test_framework() {
        let results = test_framework::run_tests("data/test_standard_rules");
        let test_failures = results.failures;
        assert_eq!(test_failures.len(), 2);

        assert_eq!(test_failures[0].rule_id, "nbha3h7uah4ya34");
        assert_eq!(test_failures[0].rule_name, "Credit Card");
        assert_eq!(test_failures[0].expected_output, "[REDACTED]");
        assert_eq!(test_failures[0].actual_output, "1234-1234-1234-1234");
        assert_eq!(test_failures[0].test_description, "Invalid checksum test");

        assert_eq!(test_failures[1].rule_id, "oa873tg4iluhan3");
        assert_eq!(test_failures[1].rule_name, "Hello World");
        assert_eq!(test_failures[1].expected_output, "hello world");
        assert_eq!(test_failures[1].actual_output, "hello [REDACTED]");
        assert_eq!(
            test_failures[1].test_description,
            "Invalid test - expected to fail"
        );
    }
}
