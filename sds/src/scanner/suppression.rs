use ahash::AHashSet;
use regex_automata::{Input, meta};
use regex_syntax::ast::{Alternation, Assertion, AssertionKind, Ast, Concat, Flags, Group};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use thiserror::Error;

use crate::{
    RegexCaches,
    ast_utils::{literal_ast, span},
    scanner::regex_rule::{SharedRegex, get_memoized_regex},
};

const MAX_SUPPRESSIONS_COUNT: usize = 30;
const MAX_SUPPRESSION_LENGTH: usize = 1000;

#[serde_as]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Suppressions {
    #[serde(default)]
    pub starts_with: Vec<String>,
    #[serde(default)]
    pub ends_with: Vec<String>,
    #[serde(default)]
    pub exact_match: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum SuppressionValidationError {
    #[error("No more than {} suppressions are allowed", MAX_SUPPRESSIONS_COUNT)]
    TooManySuppressions,

    #[error("Individual suppressions cannot be empty")]
    EmptySuppression,

    #[error(
        "Suppressions cannot be longer than {} characters",
        MAX_SUPPRESSION_LENGTH
    )]
    SuppressionTooLong,

    #[error("Duplicate suppressions are not allowed")]
    DuplicateSuppression,
}

pub struct CompiledSuppressions {
    pub suppressions_pattern: Option<SharedRegex>,
}

impl CompiledSuppressions {
    pub fn should_match_be_suppressed(
        &self,
        match_content: &str,
        regex_caches: &mut RegexCaches,
    ) -> bool {
        if let Some(suppressions) = &self.suppressions_pattern {
            suppressions
                .search_half_with(
                    &mut regex_caches.get(suppressions).cache,
                    &Input::new(match_content).earliest(true),
                )
                .is_some()
        } else {
            false
        }
    }
}

fn validate_suppressions_list(suppressions: &[String]) -> Result<(), SuppressionValidationError> {
    if suppressions.len() > MAX_SUPPRESSIONS_COUNT {
        return Err(SuppressionValidationError::TooManySuppressions);
    }
    if AHashSet::from_iter(suppressions).len() != suppressions.len() {
        return Err(SuppressionValidationError::DuplicateSuppression);
    }
    for suppression in suppressions {
        if suppression.len() > MAX_SUPPRESSION_LENGTH {
            return Err(SuppressionValidationError::SuppressionTooLong);
        }
        if suppression.is_empty() {
            return Err(SuppressionValidationError::EmptySuppression);
        }
    }
    Ok(())
}

impl TryFrom<Suppressions> for CompiledSuppressions {
    type Error = SuppressionValidationError;

    fn try_from(config: Suppressions) -> Result<Self, SuppressionValidationError> {
        validate_suppressions_list(&config.starts_with)?;
        validate_suppressions_list(&config.ends_with)?;
        validate_suppressions_list(&config.exact_match)?;
        let suppressions_ast = compile_suppressions_pattern(&config);
        let pattern = suppressions_ast.to_string();
        let mut builder = meta::Regex::builder();
        let regex_builder =
            builder.syntax(regex_automata::util::syntax::Config::default().case_insensitive(true));

        let suppressions_regex = get_memoized_regex(&pattern, |p| regex_builder.build(p)).unwrap();
        Ok(Self {
            suppressions_pattern: Some(suppressions_regex),
        })
    }
}

fn compile_suppressions_pattern(config: &Suppressions) -> Ast {
    let mut asts = vec![];
    asts.extend(suppressions_ast(&config.starts_with, true, false));
    asts.extend(suppressions_ast(&config.ends_with, false, true));
    asts.extend(suppressions_ast(&config.exact_match, true, true));
    Ast::Alternation(Alternation { span: span(), asts })
}

fn suppressions_ast(suppressions: &[String], start_anchor: bool, end_anchor: bool) -> Vec<Ast> {
    let mut asts = vec![];
    for suppression in suppressions {
        asts.push(suppression_ast(suppression, start_anchor, end_anchor));
    }
    asts
}

fn suppression_ast(suppression: &str, start_anchor: bool, end_anchor: bool) -> Ast {
    let mut asts = vec![];
    if start_anchor {
        asts.push(Ast::Assertion(Assertion {
            span: span(),
            kind: AssertionKind::StartLine,
        }));
    }
    for c in suppression.chars() {
        asts.push(Ast::Literal(literal_ast(c)));
    }
    if end_anchor {
        asts.push(Ast::Assertion(Assertion {
            span: span(),
            kind: AssertionKind::EndLine,
        }));
    }

    Ast::Group(Group {
        span: span(),
        kind: regex_syntax::ast::GroupKind::NonCapturing(Flags {
            span: span(),
            items: vec![],
        }),
        ast: Box::new(Ast::Concat(Concat { span: span(), asts })),
    })
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_suppression_correctly_suppresses_correctly() {
        let config = Suppressions {
            starts_with: vec!["mary".to_string()],
            ends_with: vec!["@datadoghq.com".to_string()],
            exact_match: vec!["nathan@yahoo.com".to_string()],
        };
        let compiled_config = CompiledSuppressions::try_from(config).unwrap();
        let mut caches = RegexCaches::new();
        assert!(compiled_config.should_match_be_suppressed("mary@datadoghq.com", &mut caches));
        assert!(compiled_config.should_match_be_suppressed("nathan@yahoo.com", &mut caches));
        assert!(compiled_config.should_match_be_suppressed("john@datadoghq.com", &mut caches));
        assert!(!compiled_config.should_match_be_suppressed("john@yahoo.com", &mut caches));
        assert!(!compiled_config.should_match_be_suppressed("john mary john", &mut caches));
        assert!(compiled_config.should_match_be_suppressed("mary john john", &mut caches));
    }

    #[test]
    fn test_suppressions_ast_is_built_properly() {
        let config = Suppressions {
            starts_with: vec!["mary".to_string(), "john".to_string()],
            ends_with: vec!["@datadoghq.com".to_string()],
            exact_match: vec!["nathan@yahoo.com".to_string()],
        };
        let ast = compile_suppressions_pattern(&config);
        assert_eq!(
            ast.to_string(),
            r"(?:^mary)|(?:^john)|(?:@datadoghq\.com$)|(?:^nathan@yahoo\.com$)"
        );
    }
}
