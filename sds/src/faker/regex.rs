use rand::{Rng, rngs::StdRng};
use regex_syntax::{
    ParserBuilder,
    hir::{Capture, Hir, HirKind, Repetition, translate::Translator},
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
    let hir = clamp_repetitions(generator_hir(regex)?, MAX_REPEAT);
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

fn clamp_repetitions(hir: Hir, max_repeat: u32) -> Hir {
    match hir.kind() {
        HirKind::Repetition(rep) => {
            let mut rep = rep.clone();
            clamp_repetition_bounds(&mut rep, max_repeat);
            rep.sub = Box::new(clamp_repetitions((*rep.sub).clone(), max_repeat));
            Hir::repetition(rep)
        }
        HirKind::Capture(capture) => Hir::capture(Capture {
            index: capture.index,
            name: capture.name.clone(),
            sub: Box::new(clamp_repetitions((*capture.sub).clone(), max_repeat)),
        }),
        HirKind::Concat(hirs) => Hir::concat(
            hirs.iter()
                .cloned()
                .map(|hir| clamp_repetitions(hir, max_repeat))
                .collect(),
        ),
        HirKind::Alternation(hirs) => Hir::alternation(
            hirs.iter()
                .cloned()
                .map(|hir| clamp_repetitions(hir, max_repeat))
                .collect(),
        ),
        _ => hir,
    }
}

fn clamp_repetition_bounds(rep: &mut Repetition, max_repeat: u32) {
    let actual_min = rep.min;
    let actual_max = rep.max;

    let capped_actual_max = actual_max
        .map(|max| max.min(max_repeat))
        .unwrap_or(max_repeat);
    rep.min = actual_min;
    rep.max = Some(actual_min.max(capped_actual_max));
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

    fn all_repetition_bounds(hir: &Hir, out: &mut Vec<(u32, Option<u32>)>) {
        match hir.kind() {
            HirKind::Repetition(rep) => out.push((rep.min, rep.max)),
            HirKind::Concat(hirs) | HirKind::Alternation(hirs) => {
                for sub in hirs {
                    all_repetition_bounds(sub, out);
                }
            }
            HirKind::Capture(capture) => all_repetition_bounds(&capture.sub, out),
            _ => {}
        }
    }

    #[test]
    fn clamp_repetition_bounds_caps_large_quantifiers() {
        let cases = [
            ((780, Some(1200)), (780, Some(780))),
            ((50, Some(150)), (50, Some(100))),
            ((50, None), (50, Some(100))),
            ((200, None), (200, Some(200))),
            ((5, Some(10)), (5, Some(10))),
        ];

        for ((actual_min, actual_max), expected) in cases {
            let regex = format!(r"(?<sds_match>x[a-z]{{{actual_min},{}}})", actual_max.map_or_else(String::new, |max| max.to_string()));
            let hir = clamp_repetitions(generator_hir(&regex).unwrap(), MAX_REPEAT);
            let mut repetitions = Vec::new();
            all_repetition_bounds(&hir, &mut repetitions);
            assert_eq!(repetitions, vec![expected], "regex={regex}");
        }
    }

    #[test]
    fn validate_accepts_large_quantifier_scanner_pattern() {
        // Illustrative scanner-style pattern (not a real rule): long bounded quantifier in sds_match.
        let regex = r##"(?:^|\s)(?<sds_match>example_token_[a-z]{780,1200})(?:$|\s)"##;
        assert_eq!(validate(regex), Ok(()));
    }

    #[test]
    fn build_clamps_large_bounded_quantifiers_to_max_repeat() {
        let mut rng = StdRng::seed_from_u64(42);

        let output = build(r"(?<sds_match>example_[a-z]{780,1200})", &mut rng);

        assert_eq!(output.len(), "example_".len() + 780);
        assert!(output.starts_with("example_"));
        assert!(output.chars().skip(8).all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn validate_accepts_scanner_pattern_with_sds_match_capture() {
        // Illustrative scanner-style pattern with an unbounded large minimum quantifier.
        let regex = r##"(?-u:\b)(?<sds_match>example_prefix_[a-z]{200,})(?:$|\s)"##;

        assert_eq!(validate(regex), Ok(()));
    }

    #[test]
    fn build_generates_from_sds_match_capture_only() {
        let regex = r##"(?-u:\b)(?<sds_match>example_prefix_[a-z]{200,})(?:$|\s)"##;
        let mut rng = StdRng::seed_from_u64(42);

        let output = build(regex, &mut rng);

        assert!(output.starts_with("example_prefix_"));
        assert!(
            output
                .chars()
                .skip("example_prefix_".len())
                .all(|c| c.is_ascii_lowercase()),
        );
        assert!(output.len() <= "example_prefix_".len() + 200);
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
