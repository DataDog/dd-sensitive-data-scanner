use rand::{Rng, rngs::StdRng};
use regex_syntax::{
    ParserBuilder,
    hir::{Hir, HirKind, translate::Translator},
};

use crate::normalization::rust_regex_adapter::convert_sds_ast_to_rust_regex_ast;
use crate::parser::ast::Ast;
use crate::parser::regex_parser::parse_regex_pattern;

use super::FakerValidationError;
use super::ast_preprocess::strip_assertions;

const MAX_REPEAT: u32 = 100;
const SDS_MATCH_CAPTURE_NAME: &str = "sds_match";
const UNSUPPORTED_ZERO_WIDTH_ASSERTION_REASON: &str = "zero-width assertions are unsupported for faker regex generation; put the generated value in a named `sds_match` capture group";

pub fn build(regex: &str, rng: &mut StdRng) -> String {
    let generator =
        compile_generator(regex).expect("pseudonymization regex should have been validated");
    rng.sample(generator)
}

pub fn validate(regex: &str) -> Result<(), FakerValidationError> {
    compile_generator(regex).map(|_| ())
}

fn compile_generator(regex: &str) -> Result<rand_regex::Regex, FakerValidationError> {
    let hir = generator_hir(regex)?;
    rand_regex::Regex::with_hir(hir, MAX_REPEAT).map_err(|error| generator_error(regex, error))
}

fn generator_hir(regex: &str) -> Result<Hir, FakerValidationError> {
    let hir = parse_hir(regex, regex)?;
    if let Some(capture_hir) = find_named_capture(&hir, SDS_MATCH_CAPTURE_NAME) {
        return Ok(capture_hir);
    }

    let sds_ast = parse_regex_pattern(regex).map_err(|_| FakerValidationError::RegexInvalid {
        regex: regex.to_string(),
    })?;

    let generator_ast = strip_assertions(sds_ast);
    if matches!(generator_ast, Ast::Empty) {
        return Err(FakerValidationError::RegexUnsupported {
            regex: regex.to_string(),
            reason: UNSUPPORTED_ZERO_WIDTH_ASSERTION_REASON.to_string(),
        });
    }

    let rust_ast = convert_sds_ast_to_rust_regex_ast(&generator_ast).map_err(|_| {
        FakerValidationError::RegexInvalid {
            regex: regex.to_string(),
        }
    })?;

    translate_rust_ast_to_hir(&rust_ast, regex)
}

fn parse_hir(pattern: &str, error_regex: &str) -> Result<Hir, FakerValidationError> {
    ParserBuilder::new()
        .build()
        .parse(pattern)
        .map_err(|_| FakerValidationError::RegexInvalid {
            regex: error_regex.to_string(),
        })
}

fn find_named_capture(hir: &Hir, name: &str) -> Option<Hir> {
    match hir.kind() {
        HirKind::Capture(capture) => {
            if capture.name.as_deref() == Some(name) {
                Some((*capture.sub).clone())
            } else {
                find_named_capture(&capture.sub, name)
            }
        }
        HirKind::Repetition(repetition) => find_named_capture(&repetition.sub, name),
        HirKind::Concat(hirs) | HirKind::Alternation(hirs) => {
            hirs.iter().find_map(|hir| find_named_capture(hir, name))
        }
        HirKind::Empty | HirKind::Literal(_) | HirKind::Class(_) | HirKind::Look(_) => None,
    }
}

fn translate_rust_ast_to_hir(
    rust_ast: &regex_syntax::ast::Ast,
    error_regex: &str,
) -> Result<Hir, FakerValidationError> {
    let pattern = rust_ast.to_string();
    Translator::new()
        .translate(&pattern, rust_ast)
        .map_err(|_| FakerValidationError::RegexInvalid {
            regex: error_regex.to_string(),
        })
}

fn generator_error(regex: &str, error: rand_regex::Error) -> FakerValidationError {
    match error {
        rand_regex::Error::Anchor => FakerValidationError::RegexUnsupported {
            regex: regex.to_string(),
            reason: UNSUPPORTED_ZERO_WIDTH_ASSERTION_REASON.to_string(),
        },
        rand_regex::Error::Syntax(_) => FakerValidationError::RegexInvalid {
            regex: regex.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn build_uses_ascii_digits_for_perl_digit_class() {
        let mut rng = StdRng::seed_from_u64(42);

        let output = build(r"0\d( ?\d{2}){4}", &mut rng);

        assert!(output.chars().all(|c| c == ' ' || c.is_ascii_digit()));
    }

    #[test]
    fn validate_accepts_scanner_pattern_with_sds_match_capture() {
        let regex = r##"(?-u:\b)(?<sds_match>ops_ey[I-L][[a-zA-Z0-9_]=\-]{200,})(?:\x{A}?$|[[\x{D}\x{A}\x{9}\x{C}\x{B}\x{20}]\)\]\}"'>\&]|\\[rn])"##;

        assert_eq!(validate(regex), Ok(()));
    }

    #[test]
    fn build_generates_from_sds_match_capture_only() {
        let regex = r##"(?-u:\b)(?<sds_match>ops_ey[I-L][[a-zA-Z0-9_]=\-]{200,})(?:\x{A}?$|[[\x{D}\x{A}\x{9}\x{C}\x{B}\x{20}]\)\]\}"'>\&]|\\[rn])"##;
        let mut rng = StdRng::seed_from_u64(42);

        let output = build(regex, &mut rng);

        assert!(
            ::regex::Regex::new(r"^ops_ey[I-L][a-zA-Z0-9_=\-]{200,}$")
                .unwrap()
                .is_match(&output)
        );
    }

    #[test]
    fn validate_accepts_scanner_pattern_with_stripped_assertions() {
        let regex = r"\b[a-z]{3}\b";

        assert_eq!(validate(regex), Ok(()));
    }

    #[test]
    fn build_generates_from_pattern_with_stripped_assertions() {
        let regex = r"\b[a-z]{3}\b";
        let mut rng = StdRng::seed_from_u64(42);

        let output = build(regex, &mut rng);

        assert_eq!(output.len(), 3);
        assert!(output.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn validate_strips_assertions_around_literal() {
        let regex = r"\bfoo$";

        assert_eq!(validate(regex), Ok(()));
    }

    #[test]
    fn validate_rejects_assertion_only_pattern() {
        let regex = r"^\b$";

        assert_eq!(
            validate(regex),
            Err(FakerValidationError::RegexUnsupported {
                regex: regex.to_string(),
                reason: UNSUPPORTED_ZERO_WIDTH_ASSERTION_REASON.to_string(),
            })
        );
    }

    #[test]
    fn sds_match_capture_preserves_nested_character_class_semantics() {
        let mut rng = StdRng::seed_from_u64(42);

        let output = build(r"(?<sds_match>[[a-c]x]{100})", &mut rng);

        assert_eq!(output.len(), 100);
        assert!(output.chars().all(|c| matches!(c, 'a'..='c' | 'x')));
    }
}
