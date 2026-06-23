use std::rc::Rc;

use crate::parser::ast::{
    Ast, CaptureGroup, Group, NamedCapturingGroup, NonCapturingGroup, Repetition,
};

pub(crate) fn strip_assertions(ast: Ast) -> Ast {
    match ast {
        Ast::Assertion(_) => Ast::Empty,
        Ast::Concat(children) => concat_children(
            children
                .into_iter()
                .map(strip_assertions)
                .filter(|child| !matches!(child, Ast::Empty))
                .collect(),
        ),
        Ast::Alternation(children) => {
            Ast::Alternation(children.into_iter().map(strip_assertions).collect())
        }
        Ast::Repetition(repetition) => {
            let inner = strip_assertions((*repetition.inner).clone());
            if matches!(inner, Ast::Empty) {
                Ast::Empty
            } else {
                Ast::Repetition(Repetition {
                    quantifier: repetition.quantifier,
                    inner: Rc::new(inner),
                })
            }
        }
        Ast::Group(group) => {
            let inner = match group.as_ref() {
                Group::Capturing(capturing) => {
                    let inner = strip_assertions(capturing.inner.clone());
                    if matches!(inner, Ast::Empty) {
                        return Ast::Empty;
                    }
                    Group::Capturing(CaptureGroup { inner })
                }
                Group::NonCapturing(non_capturing) => {
                    let inner = strip_assertions(non_capturing.inner.clone());
                    if matches!(inner, Ast::Empty) {
                        return Ast::Empty;
                    }
                    Group::NonCapturing(NonCapturingGroup {
                        flags: non_capturing.flags.clone(),
                        inner,
                    })
                }
                Group::NamedCapturing(named) => {
                    let inner = strip_assertions(named.inner.clone());
                    if matches!(inner, Ast::Empty) {
                        return Ast::Empty;
                    }
                    Group::NamedCapturing(NamedCapturingGroup {
                        name: named.name.clone(),
                        inner,
                    })
                }
            };
            Ast::Group(Rc::new(inner))
        }
        other => other,
    }
}

fn concat_children(children: Vec<Ast>) -> Ast {
    match children.as_slice() {
        [] => Ast::Empty,
        [child] => child.clone(),
        _ => Ast::Concat(children),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::normalization::rust_regex_adapter::{
        convert_sds_ast_to_rust_regex_ast, convert_to_rust_regex,
    };
    use crate::parser::regex_parser::parse_regex_pattern;

    #[test]
    fn strip_assertions_removes_word_boundaries() {
        let cases = [
            (r"\bfoo\b", "foo"),
            (r"^foo$", "foo"),
            (r"foo", "foo"),
            (r"\ba+\b", "a+"),
            (r"\bfoo", "foo"),
            (r"foo\b", "foo"),
            (r"(?:\b)foo", "foo"),
            (r"\b", ""),
            (r"^\b$", ""),
        ];

        for (input, expected) in cases {
            let stripped = strip_assertions(parse_regex_pattern(input).unwrap());

            if expected.is_empty() {
                assert!(matches!(stripped, Ast::Empty), "input: {input}");
                continue;
            }

            assert_eq!(
                convert_sds_ast_to_rust_regex_ast(&stripped)
                    .unwrap()
                    .to_string(),
                convert_to_rust_regex(expected).unwrap(),
                "input: {input}"
            );
        }
    }
}
