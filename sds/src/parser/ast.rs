use serde::{Deserialize, Serialize};
use std::rc::Rc;

/// The Abstract Syntax Tree describing a regex pattern. The AST is designed
/// to preserve behavior, but doesn't necessarily preserve the exact syntax.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "content")]
pub enum Ast {
    Empty,
    Literal(Literal),
    Concat(Vec<Ast>),
    Group(Rc<Group>),
    CharacterClass(CharacterClass),
    Alternation(Vec<Ast>),
    Repetition(Repetition),
    Assertion(AssertionType),
    Flags(Flags),
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Literal {
    #[serde(rename = "value")]
    pub c: char,

    // whether a literal is escaped or not can change the behavior in some cases,
    // such as whether or not it's ignored by the `x` (extended / verbose) flag.
    pub escaped: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "group_type", content = "content")]
pub enum Group {
    Capturing(CaptureGroup),
    NonCapturing(NonCapturingGroup),
    NamedCapturing(NamedCapturingGroup),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaptureGroup {
    pub inner: Ast,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NonCapturingGroup {
    pub flags: Flags,
    pub inner: Ast,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NamedCapturingGroup {
    pub name: String,
    pub inner: Ast,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CharacterClass {
    Bracket(BracketCharacterClass),
    Perl(PerlCharacterClass),
    Dot,
    HorizontalWhitespace,
    NotHorizontalWhitespace,
    VerticalWhitespace,
    NotVerticalWhitespace,
    UnicodeProperty(UnicodePropertyClass),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnicodePropertyClass {
    pub negate: bool,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum QuantifierKind {
    /// *
    ZeroOrMore,
    /// {n}
    RangeExact(u32),
    /// {n,m}
    RangeMinMax(u32, u32),
    /// {n,}
    RangeMin(u32),
    /// ?
    ZeroOrOne,
    /// +
    OneOrMore,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Quantifier {
    pub lazy: bool,
    pub kind: QuantifierKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PerlCharacterClass {
    Digit,
    Space,
    Word,
    NonDigit,
    NonSpace,
    NonWord,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BracketCharacterClass {
    pub negated: bool,
    pub items: Vec<BracketCharacterClassItem>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum BracketCharacterClassItem {
    Literal(char),
    Range(char, char),
    PerlCharacterClass(PerlCharacterClass),
    UnicodeProperty(UnicodePropertyClass),
    AsciiClass(AsciiClass),
    HorizontalWhitespace,
    NotHorizontalWhitespace,
    VerticalWhitespace,
    NotVerticalWhitespace,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AsciiClass {
    pub negated: bool,
    pub kind: AsciiClassKind,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AsciiClassKind {
    Alnum,
    Alpha,
    Ascii,
    Blank,
    Cntrl,
    Digit,
    Graph,
    Lower,
    Print,
    Punct,
    Space,
    Upper,
    Word,
    Xdigit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Repetition {
    #[serde(rename = "quantifier")]
    pub quantifier: Quantifier,
    #[serde(rename = "expression")]
    pub inner: Rc<Ast>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssertionType {
    /// \b
    WordBoundary,

    /// \B
    NotWordBoundary,

    /// ^
    StartLine,

    /// $
    EndLine,

    /// \A
    StartText,

    /// \z
    EndText,
    EndTextOptionalNewline,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Flags {
    pub add: Vec<Flag>,
    pub remove: Vec<Flag>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Flag {
    /// i
    CaseInsensitive,

    /// m
    MultiLine,

    /// s
    DotMatchesNewLine,

    /// x
    IgnoreWhitespace,
}
