use std::rc::Rc;

/// The Abstract Syntax Tree describing a regex pattern. The AST is designed
/// to preserve behavior, but doesn't necessarily preserve the exact syntax.
#[derive(Clone, Debug)]
pub enum Ast {
    Empty,
    Literal(Literal),
    Concat(Vec<Ast>),
    Group(Rc<Group>),
    CharacterClass(CharacterClass),
    // May be empty
    Alternation(Vec<Ast>),
    Repetition(Repetition),
    Assertion(AssertionType),
    Flags(Flags),
}

#[derive(Copy, Clone, Debug)]
pub struct Literal {
    pub c: char,

    // whether a literal is escaped or not can change the behavior in some cases,
    // such as whether or not it's ignored by the `x` (extended / verbose) flag.
    pub escaped: bool,
}

#[derive(Clone, Debug)]
pub enum Group {
    Capturing(CaptureGroup),
    NonCapturing(NonCapturingGroup),
    NamedCapturing(NamedCapturingGroup),
}

#[derive(Clone, Debug)]
pub struct CaptureGroup {
    pub inner: Ast,
}

#[derive(Clone, Debug)]
pub struct NonCapturingGroup {
    pub flags: Flags,
    pub inner: Ast,
}

#[derive(Clone, Debug)]
pub struct NamedCapturingGroup {
    pub name: String,
    pub inner: Ast,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct UnicodePropertyClass {
    pub negate: bool,
    pub name: String,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct Quantifier {
    pub lazy: bool,
    pub kind: QuantifierKind,
}

#[derive(Clone, Debug)]
pub enum PerlCharacterClass {
    Digit,
    Space,
    Word,
    NonDigit,
    NonSpace,
    NonWord,
}

#[derive(Clone, Debug)]
pub struct BracketCharacterClass {
    pub negated: bool,
    pub items: Vec<BracketCharacterClassItem>,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct AsciiClass {
    pub negated: bool,
    pub kind: AsciiClassKind,
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
pub struct Repetition {
    pub quantifier: Quantifier,
    pub inner: Rc<Ast>,
}

#[derive(Clone, Debug)]
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

    /// \Z
    EndTextOptionalNewline,
}

#[derive(Clone, Debug)]
pub struct Flags {
    /// Flags before a "-"
    pub add: Vec<Flag>,
    /// Flags after a "-"
    pub remove: Vec<Flag>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
