use crate::parser::ast::{
    AsciiClassKind as SdsAsciiClassKind, AsciiClassKind, AssertionType as SdsAssertionType,
    Ast as SdsAst, BracketCharacterClassItem as SdsBracketCharacterClassItem,
    BracketCharacterClassItem, CharacterClass, Flag as SdsFlag, Flags as SdsFlags,
    Group as SdsGroup, Literal, PerlCharacterClass as SdsPerlCharacterClass,
    Quantifier as SdsQuantifier, QuantifierKind as SdsQuantifierKind, Repetition as SdsRepetition,
    UnicodePropertyClass as SdsUnicodePropertyClass,
};
use crate::parser::error::ParseError;
use crate::parser::regex_parser::parse_regex_pattern;
use regex_syntax::ast::{
    Alternation as RegexAlternation, Assertion as RegexAssertion,
    AssertionKind as RegexAssertionKind, Ast as RegexAst, CaptureName as RegexCaptureName,
    Class as RegexClass, ClassAscii as RegexClassAscii, ClassAsciiKind as RegexClassAsciiKind,
    ClassBracketed as RegexClassBracketed, ClassSet as RegexClassSet,
    ClassSetItem as RegexClassSetItem, ClassSetRange as RegexClassSetRange,
    ClassSetUnion as RegexClassSetUnion, ClassUnicode as RegexClassUnicode,
    ClassUnicodeKind as RegexClassUnicodeKind, Concat as RegexConcat, Flag as RegexFlag,
    Flags as RegexFlags, FlagsItem as RegexFlagsItem, FlagsItemKind as RegexFlagsItemKind,
    Group as RegexGroup, GroupKind as RegexGroupKind, HexLiteralKind as RegexHexLiteralKind,
    Literal as RegexLiteral, LiteralKind as RegexLiteralKind, Position,
    Repetition as RegexRepetition, RepetitionKind as RegexRepetitionKind,
    RepetitionOp as RegexRepetitionOp, RepetitionRange, SetFlags as RegexSetFlags, Span,
};
use std::rc::Rc;

const ASCII_WHITESPACE_CHARS: &[char] = &['\x0D', '\x0A', '\x09', '\x0C', '\x0B', '\x20'];
pub const QUANTIFIER_LIMIT: u32 = 3000;
/// This takes an SDS style regex pattern and converts it to a pattern
/// compatible with the Rust `regex` crate.
///
/// If this function returns successfully, the provided String is not necessarily
/// a valid SDS regex pattern. For example, complexity limits, empty matching, .etc are
/// not things that are checked here.
///
/// This conversion guarantees that the matching behavior is identical, but it
/// makes no attempt to preserve the exact syntax used. This is only intended
/// to feed directly into a regex engine, and not intended for human readability.
pub fn convert_to_rust_regex(pattern: &str) -> Result<String, ParseError> {
    let sds_ast = parse_regex_pattern(pattern)?;
    let regex_ast = convert_ast(&sds_ast)?;
    Ok(regex_ast.to_string())
}

// This is private since only ASTs generated from the parser are supported.
// (Manually crafted ASTs may cause issues).
fn convert_ast(sds_ast: &SdsAst) -> Result<RegexAst, ParseError> {
    Ok(match sds_ast {
        SdsAst::Empty => RegexAst::Empty(span()),
        SdsAst::Literal(c) => RegexAst::Literal(convert_literal(*c, LiteralKind::Normal)),
        SdsAst::Concat(list) => RegexAst::Concat(RegexConcat {
            span: span(),
            asts: list.iter().map(convert_ast).collect::<Result<_, _>>()?,
        }),
        SdsAst::Group(group) => {
            match group.as_ref() {
                SdsGroup::Capturing(capturing_group) => {
                    RegexAst::Group(RegexGroup {
                        span: span(),
                        // The group index is not used for conversion, so a dummy "0" is provided
                        kind: RegexGroupKind::CaptureIndex(0),
                        ast: Box::new(convert_ast(&capturing_group.inner)?),
                    })
                }
                SdsGroup::NonCapturing(non_capturing) => RegexAst::Group(RegexGroup {
                    span: span(),
                    kind: RegexGroupKind::NonCapturing(convert_flags(&non_capturing.flags)),
                    ast: Box::new(convert_ast(&non_capturing.inner)?),
                }),
                SdsGroup::NamedCapturing(named_capturing) => RegexAst::Group(RegexGroup {
                    span: span(),
                    kind: RegexGroupKind::CaptureName {
                        starts_with_p: false,
                        name: RegexCaptureName {
                            span: span(),
                            name: named_capturing.name.clone(),
                            // The group index is not used for conversion, so a dummy "0" is provided
                            index: 0,
                        },
                    },
                    ast: Box::new(convert_ast(&named_capturing.inner)?),
                }),
            }
        }
        SdsAst::Alternation(list) => RegexAst::Alternation(RegexAlternation {
            span: span(),
            asts: list.iter().map(convert_ast).collect::<Result<_, _>>()?,
        }),
        SdsAst::Flags(flags) => RegexAst::Flags(RegexSetFlags {
            span: span(),
            flags: convert_flags(flags),
        }),
        SdsAst::Repetition(repetition) => RegexAst::Repetition(RegexRepetition {
            span: span(),
            op: RegexRepetitionOp {
                span: span(),
                kind: match repetition.quantifier.kind {
                    SdsQuantifierKind::ZeroOrMore => RegexRepetitionKind::ZeroOrMore,
                    SdsQuantifierKind::RangeExact(exact) => {
                        if exact > QUANTIFIER_LIMIT {
                            return Err(ParseError::ExceededQuantifierLimit);
                        }
                        RegexRepetitionKind::Range(RepetitionRange::Exactly(exact))
                    }
                    SdsQuantifierKind::RangeMinMax(min, max) => {
                        if min > QUANTIFIER_LIMIT || max > QUANTIFIER_LIMIT {
                            return Err(ParseError::ExceededQuantifierLimit);
                        }
                        RegexRepetitionKind::Range(RepetitionRange::Bounded(min, max))
                    }
                    SdsQuantifierKind::RangeMin(min) => {
                        if min > QUANTIFIER_LIMIT {
                            return Err(ParseError::ExceededQuantifierLimit);
                        }
                        RegexRepetitionKind::Range(RepetitionRange::AtLeast(min))
                    }
                    SdsQuantifierKind::ZeroOrOne => RegexRepetitionKind::ZeroOrOne,
                    SdsQuantifierKind::OneOrMore => RegexRepetitionKind::OneOrMore,
                },
            },
            greedy: !repetition.quantifier.lazy,
            ast: Box::new(convert_ast(&repetition.inner)?),
        }),
        SdsAst::Assertion(assertion_type) => match assertion_type {
            SdsAssertionType::WordBoundary => {
                // The "Unicode" flag is disabled to disable the equivalent of Hyperscans UCP flag
                RegexAst::Group(RegexGroup {
                    span: span(),
                    kind: RegexGroupKind::NonCapturing(RegexFlags {
                        span: span(),
                        items: vec![
                            RegexFlagsItem {
                                span: span(),
                                kind: RegexFlagsItemKind::Negation,
                            },
                            RegexFlagsItem {
                                span: span(),
                                kind: RegexFlagsItemKind::Flag(RegexFlag::Unicode),
                            },
                        ],
                    }),
                    ast: Box::new(RegexAst::Assertion(RegexAssertion {
                        span: span(),
                        kind: RegexAssertionKind::WordBoundary,
                    })),
                })
            }
            SdsAssertionType::NotWordBoundary => {
                // The "Unicode" flag is disabled to disable the equivalent of Hyperscans UCP flag
                RegexAst::Group(RegexGroup {
                    span: span(),
                    kind: RegexGroupKind::NonCapturing(RegexFlags {
                        span: span(),
                        items: vec![
                            RegexFlagsItem {
                                span: span(),
                                kind: RegexFlagsItemKind::Negation,
                            },
                            RegexFlagsItem {
                                span: span(),
                                kind: RegexFlagsItemKind::Flag(RegexFlag::Unicode),
                            },
                        ],
                    }),
                    ast: Box::new(RegexAst::Assertion(RegexAssertion {
                        span: span(),
                        kind: RegexAssertionKind::NotWordBoundary,
                    })),
                })
            }
            SdsAssertionType::StartLine => RegexAst::Assertion(RegexAssertion {
                span: span(),
                kind: RegexAssertionKind::StartLine,
            }),
            SdsAssertionType::EndLine => {
                // This is not directly supported in Rust. (Rust does not allow the optional \n)
                // $ is converted to \n?$
                RegexAst::Concat(RegexConcat {
                    span: span(),
                    asts: vec![
                        RegexAst::Repetition(RegexRepetition {
                            span: span(),
                            op: RegexRepetitionOp {
                                span: span(),
                                kind: RegexRepetitionKind::ZeroOrOne,
                            },
                            greedy: true,
                            ast: Box::new(RegexAst::Literal(RegexLiteral {
                                span: span(),
                                kind: RegexLiteralKind::HexBrace(RegexHexLiteralKind::X),
                                c: '\n',
                            })),
                        }),
                        RegexAst::Assertion(RegexAssertion {
                            span: span(),
                            kind: RegexAssertionKind::EndLine,
                        }),
                    ],
                })
            }
            SdsAssertionType::StartText => RegexAst::Assertion(RegexAssertion {
                span: span(),
                kind: RegexAssertionKind::StartText,
            }),
            SdsAssertionType::EndText => RegexAst::Assertion(RegexAssertion {
                span: span(),
                kind: RegexAssertionKind::EndText,
            }),
            SdsAssertionType::EndTextOptionalNewline => {
                // This is not directly supported in Rust.
                // \Z is converted to \n?\z
                convert_ast(&SdsAst::Concat(vec![
                    SdsAst::Repetition(SdsRepetition {
                        quantifier: SdsQuantifier {
                            lazy: false,
                            kind: SdsQuantifierKind::ZeroOrOne,
                        },
                        inner: Rc::new(SdsAst::Literal(Literal {
                            c: '\n',
                            // the `x` flag should not ignore this, so it's escaped
                            escaped: true,
                        })),
                    }),
                    SdsAst::Assertion(SdsAssertionType::EndText),
                ]))?
            }
        },
        SdsAst::CharacterClass(class) => match class {
            CharacterClass::Bracket(bracket) => {
                let items = convert_bracket_items(&bracket.items);

                RegexAst::Class(RegexClass::Bracketed(RegexClassBracketed {
                    span: span(),
                    negated: bracket.negated,
                    kind: RegexClassSet::Item(RegexClassSetItem::Union(RegexClassSetUnion {
                        span: span(),
                        items,
                    })),
                }))
            }
            CharacterClass::Perl(perl) => {
                RegexAst::Class(RegexClass::Bracketed(convert_perl_class(perl)))
            }
            CharacterClass::Dot => RegexAst::Dot(span()),
            CharacterClass::UnicodeProperty(class) => {
                RegexAst::Class(RegexClass::Unicode(convert_unicode_class(class)))
            }
            CharacterClass::HorizontalWhitespace => {
                RegexAst::Class(RegexClass::Bracketed(horizontal_whitespace(false)))
            }
            CharacterClass::NotHorizontalWhitespace => {
                RegexAst::Class(RegexClass::Bracketed(horizontal_whitespace(true)))
            }
            CharacterClass::VerticalWhitespace => {
                RegexAst::Class(RegexClass::Bracketed(vertical_whitespace(false)))
            }
            CharacterClass::NotVerticalWhitespace => {
                RegexAst::Class(RegexClass::Bracketed(vertical_whitespace(true)))
            }
        },
    })
}

fn horizontal_whitespace(negated: bool) -> RegexClassBracketed {
    RegexClassBracketed {
        span: span(),
        negated,
        kind: RegexClassSet::Item(RegexClassSetItem::Union(RegexClassSetUnion {
            span: span(),
            items: vec![
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: ' ',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: '\t',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
            ],
        })),
    }
}

fn vertical_whitespace(negated: bool) -> RegexClassBracketed {
    RegexClassBracketed {
        span: span(),
        negated,
        kind: RegexClassSet::Item(RegexClassSetItem::Union(RegexClassSetUnion {
            span: span(),
            items: vec![
                RegexClassSetItem::Literal(convert_literal(
                    // vertical tab
                    Literal {
                        c: '\x0B',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: '\n',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
                RegexClassSetItem::Literal(convert_literal(
                    // form feed
                    Literal {
                        c: '\x0C',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: '\r',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
            ],
        })),
    }
}

fn convert_bracket_items(items: &[SdsBracketCharacterClassItem]) -> Vec<RegexClassSetItem> {
    let mut output: Vec<RegexClassSetItem> = vec![];

    for item in items {
        match item {
            BracketCharacterClassItem::Literal(c) => {
                output.push(RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: *c,
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )));
            }
            BracketCharacterClassItem::Range(start, end) => {
                output.push(RegexClassSetItem::Range(RegexClassSetRange {
                    span: span(),
                    start: convert_literal(
                        Literal {
                            c: *start,
                            escaped: false,
                        },
                        LiteralKind::BracketedCharacterClass,
                    ),
                    end: convert_literal(
                        Literal {
                            c: *end,
                            escaped: false,
                        },
                        LiteralKind::BracketedCharacterClass,
                    ),
                }))
            }
            BracketCharacterClassItem::PerlCharacterClass(class) => {
                output.push(RegexClassSetItem::Bracketed(Box::new(convert_perl_class(
                    class,
                ))));
            }
            BracketCharacterClassItem::UnicodeProperty(class) => {
                output.push(RegexClassSetItem::Unicode(convert_unicode_class(class)))
            }
            BracketCharacterClassItem::AsciiClass(ascii_class) => {
                output.push(RegexClassSetItem::Ascii(RegexClassAscii {
                    span: span(),
                    kind: convert_ascii_class_kind(&ascii_class.kind),
                    negated: ascii_class.negated,
                }))
            }
            BracketCharacterClassItem::HorizontalWhitespace => {
                output.push(RegexClassSetItem::Bracketed(Box::new(
                    horizontal_whitespace(false),
                )));
            }
            BracketCharacterClassItem::NotHorizontalWhitespace => {
                output.push(RegexClassSetItem::Bracketed(Box::new(
                    horizontal_whitespace(true),
                )));
            }
            BracketCharacterClassItem::VerticalWhitespace => {
                output.push(RegexClassSetItem::Bracketed(Box::new(vertical_whitespace(
                    false,
                ))));
            }
            BracketCharacterClassItem::NotVerticalWhitespace => {
                output.push(RegexClassSetItem::Bracketed(Box::new(vertical_whitespace(
                    true,
                ))));
            }
        };
    }
    output
}

fn convert_ascii_class_kind(kind: &SdsAsciiClassKind) -> RegexClassAsciiKind {
    match kind {
        AsciiClassKind::Alnum => RegexClassAsciiKind::Alnum,
        AsciiClassKind::Alpha => RegexClassAsciiKind::Alpha,
        AsciiClassKind::Ascii => RegexClassAsciiKind::Ascii,
        AsciiClassKind::Blank => RegexClassAsciiKind::Blank,
        AsciiClassKind::Cntrl => RegexClassAsciiKind::Cntrl,
        AsciiClassKind::Digit => RegexClassAsciiKind::Digit,
        AsciiClassKind::Graph => RegexClassAsciiKind::Graph,
        AsciiClassKind::Lower => RegexClassAsciiKind::Lower,
        AsciiClassKind::Print => RegexClassAsciiKind::Print,
        AsciiClassKind::Punct => RegexClassAsciiKind::Punct,
        AsciiClassKind::Space => RegexClassAsciiKind::Space,
        AsciiClassKind::Upper => RegexClassAsciiKind::Upper,
        AsciiClassKind::Word => RegexClassAsciiKind::Word,
        AsciiClassKind::Xdigit => RegexClassAsciiKind::Xdigit,
    }
}

fn convert_unicode_class(class: &SdsUnicodePropertyClass) -> RegexClassUnicode {
    RegexClassUnicode {
        span: span(),
        negated: class.negate,
        kind: RegexClassUnicodeKind::Named(class.name.clone()),
    }
}

fn convert_literal(literal: Literal, kind: LiteralKind) -> RegexLiteral {
    let kind = if regex_syntax::is_meta_character(literal.c) {
        RegexLiteralKind::Meta
    } else if kind == LiteralKind::BracketedCharacterClass && literal.c.is_whitespace() {
        // Rust's "x" flag ignores _all_ whitespace, where in the SDS standard syntax (and PCRE2)
        // "x" doesn't ignore whitespace in bracketed character classes. If the literal is being
        // used in a bracketed character class, all whitespace is hex encoded to ensure it
        // is never ignored.
        RegexLiteralKind::HexBrace(RegexHexLiteralKind::X)
    } else if kind == LiteralKind::Normal && ASCII_WHITESPACE_CHARS.contains(&literal.c) {
        // The HexBrace kind is usually preferred since it makes whitespace characters easier
        // to read, but escaping whitespace can change the behavior of the `x` (extended / verbose)
        // flag, so the format is kept for those
        if literal.escaped {
            RegexLiteralKind::HexBrace(RegexHexLiteralKind::X)
        } else {
            RegexLiteralKind::Verbatim
        }
    } else {
        // escape non-printable characters
        if (literal.c as u32) < 32 && regex_syntax::is_escapeable_character(literal.c) {
            RegexLiteralKind::HexBrace(RegexHexLiteralKind::X)
        } else {
            RegexLiteralKind::Verbatim
        }
    };
    RegexLiteral {
        span: span(),
        kind,
        c: literal.c,
    }
}

// These are converted to a bracketed character class to remove the automatic UCP semantics.
fn convert_perl_class(class: &SdsPerlCharacterClass) -> RegexClassBracketed {
    match class {
        SdsPerlCharacterClass::Digit => perl_class_digit(false),
        SdsPerlCharacterClass::Space => perl_class_space(false),
        SdsPerlCharacterClass::Word => perl_class_word(false),
        SdsPerlCharacterClass::NonDigit => perl_class_digit(true),
        SdsPerlCharacterClass::NonSpace => perl_class_space(true),
        SdsPerlCharacterClass::NonWord => perl_class_word(true),
    }
}

fn perl_class_digit(negated: bool) -> RegexClassBracketed {
    RegexClassBracketed {
        // [0-9]
        span: span(),
        negated,
        kind: RegexClassSet::Item(RegexClassSetItem::Range(RegexClassSetRange {
            span: span(),
            start: convert_literal(
                Literal {
                    c: '0',
                    escaped: false,
                },
                LiteralKind::BracketedCharacterClass,
            ),
            end: convert_literal(
                Literal {
                    c: '9',
                    escaped: false,
                },
                LiteralKind::BracketedCharacterClass,
            ),
        })),
    }
}

fn perl_class_space(negated: bool) -> RegexClassBracketed {
    RegexClassBracketed {
        // [\r\n\t\f\v ]
        span: span(),
        negated,
        kind: RegexClassSet::Item(RegexClassSetItem::Union(RegexClassSetUnion {
            span: span(),
            items: vec![
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: '\r',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: '\n',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: '\t',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: '\x0C',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: '\x0B',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: ' ',
                        escaped: true,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
            ],
        })),
    }
}

fn perl_class_word(negated: bool) -> RegexClassBracketed {
    RegexClassBracketed {
        // [a-zA-Z0-9_]
        span: span(),
        negated,
        kind: RegexClassSet::Item(RegexClassSetItem::Union(RegexClassSetUnion {
            span: span(),
            items: vec![
                RegexClassSetItem::Range(RegexClassSetRange {
                    span: span(),
                    start: convert_literal(
                        Literal {
                            c: 'a',
                            escaped: false,
                        },
                        LiteralKind::BracketedCharacterClass,
                    ),
                    end: convert_literal(
                        Literal {
                            c: 'z',
                            escaped: false,
                        },
                        LiteralKind::BracketedCharacterClass,
                    ),
                }),
                RegexClassSetItem::Range(RegexClassSetRange {
                    span: span(),
                    start: convert_literal(
                        Literal {
                            c: 'A',
                            escaped: false,
                        },
                        LiteralKind::BracketedCharacterClass,
                    ),
                    end: convert_literal(
                        Literal {
                            c: 'Z',
                            escaped: false,
                        },
                        LiteralKind::BracketedCharacterClass,
                    ),
                }),
                RegexClassSetItem::Range(RegexClassSetRange {
                    span: span(),
                    start: convert_literal(
                        Literal {
                            c: '0',
                            escaped: false,
                        },
                        LiteralKind::BracketedCharacterClass,
                    ),
                    end: convert_literal(
                        Literal {
                            c: '9',
                            escaped: false,
                        },
                        LiteralKind::BracketedCharacterClass,
                    ),
                }),
                RegexClassSetItem::Literal(convert_literal(
                    Literal {
                        c: '_',
                        escaped: false,
                    },
                    LiteralKind::BracketedCharacterClass,
                )),
            ],
        })),
    }
}

fn convert_flags(flags: &SdsFlags) -> RegexFlags {
    let mut items = vec![];

    // Rust doesnt allow the same flag to show up twice. Adds and removes are deduplicated,
    // and if they are in both add and remove, the add is removed.

    let mut add_flags = flags.add.clone();
    add_flags.sort();
    add_flags.dedup();

    let mut remove_flags = flags.remove.clone();
    remove_flags.sort();
    remove_flags.dedup();

    let mut flags_in_both = vec![];

    for flag in &remove_flags {
        if add_flags.contains(flag) {
            flags_in_both.push(*flag);
        }
    }

    // If a flag is both added and removed, they are processed in order, so only the removal
    // is kept.
    for flag in flags_in_both {
        add_flags.retain(|x| *x != flag);
    }

    for flag in &add_flags {
        items.push(RegexFlagsItem {
            span: span(),
            kind: RegexFlagsItemKind::Flag(convert_flag(flag)),
        });
    }
    if !remove_flags.is_empty() {
        items.push(RegexFlagsItem {
            span: span(),
            kind: RegexFlagsItemKind::Negation,
        });

        for flag in &remove_flags {
            items.push(RegexFlagsItem {
                span: span(),
                kind: RegexFlagsItemKind::Flag(convert_flag(flag)),
            });
        }
    }

    RegexFlags {
        span: span(),
        items,
    }
}

fn convert_flag(flag: &SdsFlag) -> RegexFlag {
    match flag {
        SdsFlag::CaseInsensitive => RegexFlag::CaseInsensitive,
        SdsFlag::MultiLine => RegexFlag::MultiLine,
        SdsFlag::DotMatchesNewLine => RegexFlag::DotMatchesNewLine,
        SdsFlag::IgnoreWhitespace => RegexFlag::IgnoreWhitespace,
    }
}

#[cfg(test)]
mod test {
    use crate::normalization::rust_regex_adapter::{convert_to_rust_regex, QUANTIFIER_LIMIT};
    use crate::parser::error::ParseError;
    use crate::parser::unicode_property_names::UNICODE_PROPERTY_NAMES;
    use regex::Regex;
    use std::panic::catch_unwind;

    #[test]
    fn test_conversion() {
        // a list of inputs / expected outputs
        let test_cases = [
            // cases that are different
            ("\\a", "\\x{7}"),
            ("\\i", "i"),
            ("(?P<name>foo)", "(?<name>foo)"),
            ("(?'name'foo)", "(?<name>foo)"),
            ("x{,3}", "x\\{,3\\}"),
            ("{}", "\\{\\}"),
            ("\\Z", "\\x{A}?\\z"),
            ("[]]", "[\\]]"),
            ("[{}]", "[\\{\\}]"),
            ("[-]", "[\\-]"),
            ("[a-]", "[a\\-]"),
            ("[--a]", "[\\--a]"),
            ("\\d", "[0-9]"),
            ("\\w", "[a-zA-Z0-9_]"),
            ("\\s", "[\\x{D}\\x{A}\\x{9}\\x{C}\\x{B}\\x{20}]"),
            ("\\D", "[^0-9]"),
            ("\\W", "[^a-zA-Z0-9_]"),
            ("\\S", "[^\\x{D}\\x{A}\\x{9}\\x{C}\\x{B}\\x{20}]"),
            ("\\b", "(?-u:\\b)"),
            ("\\B", "(?-u:\\B)"),
            ("(?ii:foo)", "(?i:foo)"),
            ("(?-ii:foo)", "(?-i:foo)"),
            ("(?i-i:foo)", "(?-i:foo)"),
            ("\\<", "<"),
            ("\\>", ">"),
            ("[ ]", "[\\x{20}]"),
            ("[\\Qfoo\\E]", "[foo]"),
            ("[\\Q]\\E]", "[\\]]"),
            ("\\Qfoo\\E", "foo"),
            ("\\Q\\E", ""),
            ("\\Q([x])\\E", "\\(\\[x\\]\\)"),
            ("a\\Q|\\Eb", "a\\|b"),
            ("[a&&b]", "[a\\&\\&b]"),
            ("\\cA", "\\x{1}"),
            ("\\ca", "\\x{1}"),
            ("\\cZ", "\\x{1A}"),
            ("\\cz", "\\x{1A}"),
            ("[\\b]", "[\\x{8}]"),
            ("\\e", "\\x{1B}"),
            ("\\f", "\\x{C}"),
            ("\\n", "\\x{A}"),
            ("\\r", "\\x{D}"),
            ("\\t", "\\x{9}"),
            ("\\x", "\\x{0}"),
            ("\\x1", "\\x{1}"),
            ("\\x012", "\\x{1}2"),
            ("\\h", "[\\x{20}\\x{9}]"),
            ("\\H", "[^\\x{20}\\x{9}]"),
            ("\\v", "[\\x{B}\\x{A}\\x{C}\\x{D}]"),
            ("[\\v]", "[[\\x{B}\\x{A}\\x{C}\\x{D}]]"),
            ("[\\V]", "[[^\\x{B}\\x{A}\\x{C}\\x{D}]]"),
            ("\\V", "[^\\x{B}\\x{A}\\x{C}\\x{D}]"),
            ("[.]", "[\\.]"),
            ("[\\s]", "[[\\x{D}\\x{A}\\x{9}\\x{C}\\x{B}\\x{20}]]"),
            ("[\\habc]", "[[\\x{20}\\x{9}]abc]"),
            ("x{3}?", "x{3}?"),
            ("$", "\\x{A}?$"),
            // cases that are the same
            ("", ""),
            ("^", "^"),
            ("a b", "a b"),
            ("a", "a"),
            ("😏", "😏"),
            ("\\*", "\\*"),
            ("abc", "abc"),
            ("(?:abc)", "(?:abc)"),
            ("(?i:abc)", "(?i:abc)"),
            ("(?imsx:abc)", "(?imsx:abc)"),
            ("(a)", "(a)"),
            ("(a(b))", "(a(b))"),
            ("(?<name>foo)", "(?<name>foo)"),
            ("a|b|c", "a|b|c"),
            ("(?imsx)foo", "(?imsx)foo"),
            ("x+", "x+"),
            ("x*", "x*"),
            ("x?", "x?"),
            ("x+?", "x+?"),
            ("x*?", "x*?"),
            ("x??", "x??"),
            ("x{3}", "x{3}"),
            ("x{3,4}", "x{3,4}"),
            ("x{3,}", "x{3,}"),
            ("\\^", "\\^"),
            ("\\$", "\\$"),
            ("\\A", "\\A"),
            ("\\z", "\\z"),
            (".", "."),
            ("[x]", "[x]"),
            ("[^x]", "[^x]"),
            ("[a-z]", "[a-z]"),
            ("[[:alnum:]]", "[[:alnum:]]"),
            ("[[:alpha:]]", "[[:alpha:]]"),
            ("[[:ascii:]]", "[[:ascii:]]"),
            ("[[:blank:]]", "[[:blank:]]"),
            ("[[:cntrl:]]", "[[:cntrl:]]"),
            ("[[:digit:]]", "[[:digit:]]"),
            ("[[:graph:]]", "[[:graph:]]"),
            ("[[:lower:]]", "[[:lower:]]"),
            ("[[:print:]]", "[[:print:]]"),
            ("[[:punct:]]", "[[:punct:]]"),
            ("[[:space:]]", "[[:space:]]"),
            ("[[:upper:]]", "[[:upper:]]"),
            ("[[:word:]]", "[[:word:]]"),
            ("[[:xdigit:]]", "[[:xdigit:]]"),
            ("[[:^alnum:]]", "[[:^alnum:]]"),
            ("[[:^alpha:]]", "[[:^alpha:]]"),
            ("[[:^ascii:]]", "[[:^ascii:]]"),
            ("[[:^blank:]]", "[[:^blank:]]"),
            ("[[:^cntrl:]]", "[[:^cntrl:]]"),
            ("[[:^digit:]]", "[[:^digit:]]"),
            ("[[:^graph:]]", "[[:^graph:]]"),
            ("[[:^lower:]]", "[[:^lower:]]"),
            ("[[:^print:]]", "[[:^print:]]"),
            ("[[:^punct:]]", "[[:^punct:]]"),
            ("[[:^space:]]", "[[:^space:]]"),
            ("[[:^upper:]]", "[[:^upper:]]"),
            ("[[:^word:]]", "[[:^word:]]"),
            ("[[:^xdigit:]]", "[[:^xdigit:]]"),
            ("(?:x|)y", "(?:x|)y"),
        ];

        let mut dynamic_test_cases = vec![];

        // add all unicode categories to tests
        for property_name in UNICODE_PROPERTY_NAMES {
            let pattern = format!("\\p{{{}}}", property_name);
            dynamic_test_cases.push((pattern.clone(), pattern));
        }

        for (input, expected_output) in test_cases
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .into_iter()
            .chain(dynamic_test_cases)
        {
            let actual_output = match catch_unwind(|| convert_to_rust_regex(&input).unwrap()) {
                Ok(x) => x,
                Err(err) => {
                    println!("Input caused a panic: {:?}", input);
                    panic!("{:?}", err);
                }
            };

            if actual_output != expected_output {
                println!("  Actual bytes: {:?}", actual_output.clone().into_bytes());
                println!(
                    "Expected bytes: {:?}",
                    expected_output.to_string().into_bytes()
                );
                panic!(
                    "Conversion failed for input: {}\n  Actual: {}\nExpected: {}",
                    input, actual_output, expected_output
                );
            }

            // ensure it's actually a valid regex
            Regex::new(&actual_output).unwrap();
        }
    }

    #[test]
    fn test_validation() {
        // exact repetition
        assert!(convert_to_rust_regex(&format!("x{{{}}}", QUANTIFIER_LIMIT)).is_ok());
        assert_eq!(
            convert_to_rust_regex(&format!("x{{{}}}", QUANTIFIER_LIMIT + 1)),
            Err(ParseError::ExceededQuantifierLimit)
        );

        // range repetition (only the max needs to be tested since it must be larger than the min)
        assert!(convert_to_rust_regex(&format!(
            "x{{{},{}}}",
            QUANTIFIER_LIMIT - 1,
            QUANTIFIER_LIMIT
        ))
        .is_ok());
        assert_eq!(
            convert_to_rust_regex(&format!(
                "x{{{},{}}}",
                QUANTIFIER_LIMIT,
                QUANTIFIER_LIMIT + 1
            )),
            Err(ParseError::ExceededQuantifierLimit)
        );

        // min range repetition
        assert!(convert_to_rust_regex(&format!("x{{{},}}", QUANTIFIER_LIMIT)).is_ok());
        assert_eq!(
            convert_to_rust_regex(&format!("x{{{},}}", QUANTIFIER_LIMIT + 1)),
            Err(ParseError::ExceededQuantifierLimit)
        );
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum LiteralKind {
    Normal,
    BracketedCharacterClass,
}

// creates a dummy span (which isn't used here, but is required for the RegexAst)
fn span() -> Span {
    Span::new(Position::new(0, 0, 0), Position::new(0, 0, 0))
}
