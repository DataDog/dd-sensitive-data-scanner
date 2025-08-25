use super::ast::{
    AsciiClass, AsciiClassKind, AssertionType, Ast, BracketCharacterClass,
    BracketCharacterClassItem, CaptureGroup, CharacterClass, Flag, Flags, Group,
    NamedCapturingGroup, NonCapturingGroup, PerlCharacterClass, Quantifier, QuantifierKind,
    Repetition, UnicodePropertyClass,
};
use super::input::Input;
use super::unicode_property_names::UNICODE_PROPERTY_NAMES;
use crate::parser::ast::Literal;
use crate::parser::error::ParseError;
use nom::IResult;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_until};
use nom::character::complete::{digit1, none_of, one_of};
use nom::combinator::{eof, map, opt, recognize};
use nom::error::ErrorKind;
use nom::multi::{many_m_n, many0, many1, separated_list1};
use nom::sequence::{delimited, tuple};
use std::rc::Rc;
use std::str::FromStr;

type ParseResult<'a, T> = IResult<Input<'a>, T, ParseError>;

const ASCII_LETTERS: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ASCII_LETTERS_WITH_UNDERSCORE: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
const ASCII_ALPHANUMERIC_WITH_UNDERSCORE: &str =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_";
const HEX_DIGIT: &str = "0123456789ABCDEFabcdef";

// characters not allowed in different types of literals
const ESCAPED_LITERAL_DENY_LIST: &str = "0123456789cgklopuxzABCEGKLNPQRUXZ";
const BRACKETED_CHARACTER_CLASS_DENY_LIST: &str = "]";
const LITERAL_DENY_LIST: &str = "|[().+?*^$";
const RECURSION_LIMIT: usize = 50;

/// Parses the regex syntax into an AST. Only syntax supported by SDS will parse correctly here.
/// A successful parse does NOT guarantee this is a valid pattern for SDS, but all valid
/// patterns are guaranteed to parse correctly.
pub fn parse_regex_pattern(input: &str) -> Result<Ast, ParseError> {
    let (_, ast) = regex_pattern(Input::from((input, 0))).map_err(|err| match err {
        nom::Err::Incomplete(_) => ParseError::InvalidSyntax,
        nom::Err::Error(x) => x,
        nom::Err::Failure(x) => x,
    })?;
    Ok(ast)
}

fn regex_pattern(input: Input) -> ParseResult<Ast> {
    let (input, ast) = expression(input)?;
    let (input, _) = eof(input)?;
    Ok((input, ast))
}

fn expression(input: Input) -> ParseResult<Ast> {
    let (input, ast) = alternate_expression(input)?;
    Ok((input, ast))
}

fn alternate_expression(input: Input) -> ParseResult<Ast> {
    let (input, children) = separated_list1(tag("|"), opt(concat_expression))(input)?;
    let children: Vec<Ast> = children
        .into_iter()
        .map(|ast| ast.unwrap_or(Ast::Empty))
        .collect();
    if children.len() == 1 {
        Ok((input, children.first().unwrap().clone()))
    } else {
        Ok((input, Ast::Alternation(children)))
    }
}

fn concat_expression(input: Input) -> ParseResult<Ast> {
    let (input, children) = many1(atomic)(input)?;
    if children.len() == 1 {
        Ok((input, children.first().unwrap().clone()))
    } else {
        Ok((input, Ast::Concat(children)))
    }
}

// a single part of an expression
fn atomic(input: Input) -> ParseResult<Ast> {
    // The ordering here is important.
    let (input, inner) = alt((
        quote_expression,
        map(flags_expression, Ast::Flags),
        map(group, |group| Ast::Group(Rc::new(group))),
        map(assertion, Ast::Assertion),
        map(character_class, Ast::CharacterClass),
        map(literal(LiteralKind::Normal), Ast::Literal),
    ))(input)?;

    let (input, quantifier) = opt(quantifier)(input)?;
    if let Some(quantifier) = quantifier {
        Ok((
            input,
            Ast::Repetition(Repetition {
                quantifier,
                inner: Rc::new(inner),
            }),
        ))
    } else {
        Ok((input, inner))
    }
}

fn quote_expression(input: Input) -> ParseResult<Ast> {
    let (input, literals) = quoted_literals(input)?;
    let literals = literals
        .into_iter()
        .map(|c| Ast::Literal(Literal { c, escaped: true }))
        .collect::<Vec<_>>();
    let ast = match literals.len() {
        0 => Ast::Empty,
        1 => literals.first().unwrap().clone(),
        _ => Ast::Concat(literals),
    };
    Ok((input, ast))
}

fn quantifier(input: Input) -> ParseResult<Quantifier> {
    let (input, kind) = alt((
        map(tag("*"), |_| QuantifierKind::ZeroOrMore),
        map(tag("+"), |_| QuantifierKind::OneOrMore),
        map(tag("?"), |_| QuantifierKind::ZeroOrOne),
        quantifier_range_exact,
        quantifier_range_min_max,
        quantifier_range_min,
    ))(input)?;
    let (input, lazy) = opt(tag("?"))(input)?;
    Ok((
        input,
        Quantifier {
            lazy: lazy.is_some(),
            kind,
        },
    ))
}

fn quantifier_range_exact(input: Input) -> ParseResult<QuantifierKind> {
    let (input, _) = tag("{")(input)?;
    let (input, exact_count) = integer(input)?;
    let (input, _) = tag("}")(input)?;
    Ok((input, QuantifierKind::RangeExact(exact_count)))
}

fn quantifier_range_min_max(input: Input) -> ParseResult<QuantifierKind> {
    let (input, _) = tag("{")(input)?;
    let (input, min_count) = integer(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, max_count) = integer(input)?;
    let (input, _) = tag("}")(input)?;
    Ok((input, QuantifierKind::RangeMinMax(min_count, max_count)))
}

fn quantifier_range_min(input: Input) -> ParseResult<QuantifierKind> {
    let (input, _) = tag("{")(input)?;
    let (input, min_count) = integer(input)?;
    let (input, _) = tag(",")(input)?;
    let (input, _) = tag("}")(input)?;
    Ok((input, QuantifierKind::RangeMin(min_count)))
}

fn assertion(input: Input) -> ParseResult<AssertionType> {
    alt((
        map(tag("\\b"), |_| AssertionType::WordBoundary),
        map(tag("\\B"), |_| AssertionType::NotWordBoundary),
        map(tag("^"), |_| AssertionType::StartLine),
        map(tag("$"), |_| AssertionType::EndLine),
        map(tag("\\A"), |_| AssertionType::StartText),
        map(tag("\\z"), |_| AssertionType::EndText),
        map(tag("\\Z"), |_| AssertionType::EndTextOptionalNewline),
    ))(input)
}

fn character_class(input: Input) -> ParseResult<CharacterClass> {
    alt((
        map(tag("."), |_| CharacterClass::Dot),
        map(tag("\\h"), |_| CharacterClass::HorizontalWhitespace),
        map(tag("\\H"), |_| CharacterClass::NotHorizontalWhitespace),
        map(tag("\\v"), |_| CharacterClass::VerticalWhitespace),
        map(tag("\\V"), |_| CharacterClass::NotVerticalWhitespace),
        map(bracket_character_class, |class| {
            CharacterClass::Bracket(class)
        }),
        map(perl_character_class, CharacterClass::Perl),
        map(unicode_property_class, |class| {
            CharacterClass::UnicodeProperty(class)
        }),
    ))(input)
}

fn unicode_property_class(input: Input) -> ParseResult<UnicodePropertyClass> {
    alt((
        map(
            delimited(tag("\\p{"), unicode_property_name, tag("}")),
            |name: &str| UnicodePropertyClass {
                negate: false,
                name: name.to_string(),
            },
        ),
        map(
            delimited(tag("\\P{"), unicode_property_name, tag("}")),
            |name| UnicodePropertyClass {
                negate: true,
                name: name.to_string(),
            },
        ),
    ))(input)
}

fn unicode_property_name(input: Input<'_>) -> ParseResult<'_, &str> {
    let (input, name) = recognize(many0(one_of(ASCII_LETTERS_WITH_UNDERSCORE)))(input)?;
    if UNICODE_PROPERTY_NAMES.contains(&name.value) {
        Ok((input, name.value))
    } else {
        Err(nom::Err::Error(ParseError::InvalidSyntax))
    }
}

fn flags_expression(input: Input) -> ParseResult<Flags> {
    let (input, _) = tag("(?")(input)?;
    let (input, flags) = flags(input)?;
    let (input, _) = tag(")")(input)?;
    Ok((input, flags))
}

fn group(mut input: Input) -> ParseResult<Group> {
    input.depth += 1;
    if input.depth > RECURSION_LIMIT {
        return Err(nom::Err::Failure(ParseError::ExceededDepthLimit));
    }
    let result = alt((
        map(non_capturing_group, Group::NonCapturing),
        map(capture_group, Group::Capturing),
        map(named_capture_group, Group::NamedCapturing),
    ))(input);

    match result {
        Ok((mut input, group)) => {
            input.depth -= 1;
            Ok((input, group))
        }
        Err(err) => Err(err),
    }
}

fn capture_group(input: Input) -> ParseResult<CaptureGroup> {
    let (input, _) = tag("(")(input)?;
    let (input, inner) = expression(input)?;
    let (input, _) = tag(")")(input)?;
    Ok((input, CaptureGroup { inner }))
}

fn named_capture_group(input: Input) -> ParseResult<NamedCapturingGroup> {
    let (input, (_, name, _, inner, _)) = alt((
        tuple((
            alt((tag("(?<"), tag("(?P<"))),
            capture_group_name,
            tag(">"),
            expression,
            tag(")"),
        )),
        tuple((
            tag("(?'"),
            capture_group_name,
            tag("'"),
            expression,
            tag(")"),
        )),
    ))(input)?;

    Ok((
        input,
        NamedCapturingGroup {
            name: name.to_string(),
            inner,
        },
    ))
}

fn non_capturing_group(input: Input) -> ParseResult<NonCapturingGroup> {
    let (input, _) = tag("(?")(input)?;
    let (input, flags) = flags(input)?;
    let (input, _) = tag(":")(input)?;
    let (input, inner) = expression(input)?;
    let (input, _) = tag(")")(input)?;

    Ok((input, NonCapturingGroup { flags, inner }))
}

fn flags(input: Input) -> ParseResult<Flags> {
    let (input, add) = many0(flag)(input)?;
    let (input, remove) = opt(tuple((tag("-"), many0(flag))))(input)?;

    Ok((
        input,
        Flags {
            add,
            remove: remove.map(|x| x.1).unwrap_or(vec![]),
        },
    ))
}

fn flag(input: Input) -> ParseResult<Flag> {
    alt((
        map(tag("i"), |_| Flag::CaseInsensitive),
        map(tag("m"), |_| Flag::MultiLine),
        map(tag("s"), |_| Flag::DotMatchesNewLine),
        map(tag("x"), |_| Flag::IgnoreWhitespace),
    ))(input)
}

fn bracket_character_class(input: Input) -> ParseResult<BracketCharacterClass> {
    let (input, _) = tag("[")(input)?;
    let (input, negated) = opt(tag("^"))(input)?;

    // "]" is only allowed if it's the very first char
    let (input, closing_bracket) = opt(tag("]"))(input)?;

    let (input, items) = many0(bracket_character_class_item)(input)?;
    let mut items: Vec<_> = items.into_iter().flatten().collect();
    let (input, _) = tag("]")(input)?;

    if closing_bracket.is_some() {
        items.insert(0, BracketCharacterClassItem::Literal(']'));
    }

    if items.is_empty() {
        // An empty bracket character class is not valid
        return Err(nom::Err::Error(ParseError::InvalidSyntax));
    }

    Ok((
        input,
        BracketCharacterClass {
            negated: negated.is_some(),
            items,
        },
    ))
}

fn bracket_character_class_item(input: Input) -> ParseResult<Vec<BracketCharacterClassItem>> {
    // the order here is important
    alt((
        map(perl_character_class, |class| {
            vec![BracketCharacterClassItem::PerlCharacterClass(class)]
        }),
        map(tag("\\h"), |_| {
            vec![BracketCharacterClassItem::HorizontalWhitespace]
        }),
        map(tag("\\H"), |_| {
            vec![BracketCharacterClassItem::NotHorizontalWhitespace]
        }),
        map(tag("\\v"), |_| {
            vec![BracketCharacterClassItem::VerticalWhitespace]
        }),
        map(tag("\\V"), |_| {
            vec![BracketCharacterClassItem::NotVerticalWhitespace]
        }),
        bracket_character_class_quoted_literals,
        map(bracket_character_class_ascii_class, |item| vec![item]),
        map(bracket_character_class_item_range, |item| vec![item]),
        map(bracket_character_class_item_literal, |item| vec![item]),
    ))(input)
}

fn quoted_literals(input: Input) -> ParseResult<Vec<char>> {
    let (input, _) = tag("\\Q")(input)?;
    let (input, literals) = take_until("\\E")(input)?;
    let (input, _) = tag("\\E")(input)?;
    Ok((input, literals.value.chars().collect()))
}

fn bracket_character_class_quoted_literals(
    input: Input,
) -> ParseResult<Vec<BracketCharacterClassItem>> {
    let (input, literals) = quoted_literals(input)?;
    let items = literals
        .into_iter()
        .map(BracketCharacterClassItem::Literal)
        .collect();

    Ok((input, items))
}

fn bracket_character_class_ascii_class(input: Input) -> ParseResult<BracketCharacterClassItem> {
    let (input, _) = tag("[:")(input)?;
    let (input, negated) = opt(tag("^"))(input)?;
    let (input, ascii_class_kind) = alt((
        map(tag("alnum"), |_| AsciiClassKind::Alnum),
        map(tag("alpha"), |_| AsciiClassKind::Alpha),
        map(tag("ascii"), |_| AsciiClassKind::Ascii),
        map(tag("blank"), |_| AsciiClassKind::Blank),
        map(tag("cntrl"), |_| AsciiClassKind::Cntrl),
        map(tag("digit"), |_| AsciiClassKind::Digit),
        map(tag("graph"), |_| AsciiClassKind::Graph),
        map(tag("lower"), |_| AsciiClassKind::Lower),
        map(tag("print"), |_| AsciiClassKind::Print),
        map(tag("punct"), |_| AsciiClassKind::Punct),
        map(tag("space"), |_| AsciiClassKind::Space),
        map(tag("upper"), |_| AsciiClassKind::Upper),
        map(tag("word"), |_| AsciiClassKind::Word),
        map(tag("xdigit"), |_| AsciiClassKind::Xdigit),
    ))(input)?;
    let (input, _) = tag(":]")(input)?;
    Ok((
        input,
        BracketCharacterClassItem::AsciiClass(AsciiClass {
            negated: negated.is_some(),
            kind: ascii_class_kind,
        }),
    ))
}

fn bracket_character_class_item_literal(input: Input) -> ParseResult<BracketCharacterClassItem> {
    alt((
        map(literal(LiteralKind::BracketedCharacterClass), |literal| {
            BracketCharacterClassItem::Literal(literal.c)
        }),
        map(perl_character_class, |class| {
            BracketCharacterClassItem::PerlCharacterClass(class)
        }),
        map(unicode_property_class, |class| {
            BracketCharacterClassItem::UnicodeProperty(class)
        }),
    ))(input)
}

fn bracket_character_class_item_range(input: Input) -> ParseResult<BracketCharacterClassItem> {
    let (input, start) = literal(LiteralKind::BracketedCharacterClass)(input)?;
    let (input, _) = tag("-")(input)?;
    let (input, end) = literal(LiteralKind::BracketedCharacterClass)(input)?;
    Ok((input, BracketCharacterClassItem::Range(start.c, end.c)))
}

fn perl_character_class(input: Input) -> ParseResult<PerlCharacterClass> {
    alt((
        map(tag("\\d"), |_| PerlCharacterClass::Digit),
        map(tag("\\s"), |_| PerlCharacterClass::Space),
        map(tag("\\w"), |_| PerlCharacterClass::Word),
        map(tag("\\D"), |_| PerlCharacterClass::NonDigit),
        map(tag("\\S"), |_| PerlCharacterClass::NonSpace),
        map(tag("\\W"), |_| PerlCharacterClass::NonWord),
    ))(input)
}

enum LiteralKind {
    BracketedCharacterClass,
    Normal,
}

fn escaped_literal(input: Input) -> ParseResult<Literal> {
    let (input, c) = alt((
        escaped_control_sequence,
        map(tag("a"), |_| '\x07'),
        map(tag("b"), |_| '\x08'),
        map(tag("e"), |_| '\x1B'),
        map(tag("f"), |_| '\x0C'),
        map(tag("n"), |_| '\n'),
        map(tag("r"), |_| '\r'),
        map(tag("t"), |_| '\t'),
        map(tag("v"), |_| '\x0B'),
        hex_escaped_literal,
    ))(input)?;
    Ok((input, Literal { c, escaped: true }))
}

fn escaped_control_sequence(input: Input) -> ParseResult<char> {
    let (input, _) = tag("c")(input)?;
    let (input, c) = one_of(ASCII_LETTERS)(input)?;
    let control_char = char::from_u32((c.to_ascii_lowercase() as u32) - ('a' as u32) + 1).unwrap();
    Ok((input, control_char))
}

fn hex_escaped_literal(input: Input) -> ParseResult<char> {
    let (input, (has_brace, hex_string)) = alt((
        map(
            tuple((tag("x{"), recognize(take_until("}")), tag("}"))),
            |(_, hex, _)| (true, hex),
        ),
        map(
            tuple((tag("x"), recognize(many_m_n(0, 2, hex_digit)))),
            |(_, hex)| (false, hex),
        ),
    ))(input)?;

    let hex_value = if has_brace {
        u32::from_str_radix(hex_string.value, 16)
            .map_err(|_| nom::Err::Failure(ParseError::InvalidSyntax))?
    } else {
        // this will only be invalid if it's empty (which means 0)
        u32::from_str_radix(hex_string.value, 16).unwrap_or(0)
    };
    let c = char::from_u32(hex_value).ok_or(nom::Err::Failure(ParseError::InvalidSyntax))?;
    Ok((input, c))
}

fn literal(kind: LiteralKind) -> impl FnMut(Input) -> ParseResult<Literal> {
    move |input: Input| {
        let (input, backslash) = opt(tag("\\"))(input)?;
        if backslash.is_some() {
            alt((
                escaped_literal,
                map(none_of(ESCAPED_LITERAL_DENY_LIST), |c| Literal {
                    c,
                    escaped: true,
                }),
            ))(input)
        } else {
            let (input, c) = match kind {
                LiteralKind::BracketedCharacterClass => {
                    none_of(BRACKETED_CHARACTER_CLASS_DENY_LIST)(input)?
                }
                LiteralKind::Normal => none_of(LITERAL_DENY_LIST)(input)?,
            };
            Ok((input, Literal { c, escaped: false }))
        }
    }
}

fn hex_digit(input: Input) -> ParseResult<char> {
    one_of(HEX_DIGIT)(input)
}

fn integer(input: Input) -> ParseResult<u32> {
    let (input, digits) = digit1(input)?;
    let value =
        u32::from_str(digits.value).map_err(|_| nom::Err::Error(ParseError::InvalidSyntax))?;
    Ok((input, value))
}

fn capture_group_name(input: Input<'_>) -> ParseResult<'_, &str> {
    let (input, value) = recognize(tuple((
        one_of(ASCII_LETTERS_WITH_UNDERSCORE),
        many0(one_of(ASCII_ALPHANUMERIC_WITH_UNDERSCORE)),
    )))(input)?;

    Ok((input, value.value))
}

// error types are ignored here, so this is used as a shortcut to specifying a real error type
struct GenericError<'a>(Input<'a>);

impl<'a> From<GenericError<'a>> for nom::Err<nom::error::Error<Input<'a>>> {
    fn from(value: GenericError<'a>) -> Self {
        nom::Err::Error(nom::error::Error::new(value.0, ErrorKind::Fail))
    }
}

// A failure that should cause overall parsing to fail immediately (instead of backtracking).
struct UnrecoverableError<'a>(Input<'a>);

impl<'a> From<UnrecoverableError<'a>> for nom::Err<nom::error::Error<Input<'a>>> {
    fn from(value: UnrecoverableError<'a>) -> Self {
        nom::Err::Failure(nom::error::Error::new(value.0, ErrorKind::Fail))
    }
}

#[cfg(test)]
mod test {
    use crate::parser::regex_parser::{RECURSION_LIMIT, parse_regex_pattern};

    fn generate_pattern_with_depth(depth: usize) -> String {
        "(".repeat(depth) + "x" + &")".repeat(depth)
    }

    #[test]
    fn test_recursion_limit() {
        assert!(parse_regex_pattern(&generate_pattern_with_depth(1)).is_ok());
        assert!(parse_regex_pattern(&generate_pattern_with_depth(2)).is_ok());
        assert!(parse_regex_pattern(&generate_pattern_with_depth(RECURSION_LIMIT - 1)).is_ok());
        assert!(parse_regex_pattern(&generate_pattern_with_depth(RECURSION_LIMIT)).is_err());
        assert!(
            parse_regex_pattern(&generate_pattern_with_depth(RECURSION_LIMIT + 10_000)).is_err()
        );
    }

    #[test]
    fn test_parse_failures() {
        // all of the following should FAIL to parse. (Positive tests are in `rust_regex_adapter`).
        let patterns = [
            "\\x{}",
            "\\x{999999}",
            "[\\A]",
            "[\\Z]",
            "\\012",
            "\\c",
            "\\N{U+1234}",
            "\\N",
            "\\u",
            "\\U",
            "\\u{1234}",
            "\\u12",
            "\\C",
            "\\R",
            "\\X",
            "\\p",
            "\\p{}",
            "\\p{invalid}",
        ];
        for pattern in patterns {
            if parse_regex_pattern(pattern).is_ok() {
                panic!("Expected pattern to fail parsing:\n{pattern}");
            }
        }
    }
}
