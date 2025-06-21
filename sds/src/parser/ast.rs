use serde::{Serialize, Serializer};
use std::rc::Rc;
use serde::ser::SerializeMap;
use regex_syntax::ast::Alternation;
/// The Abstract Syntax Tree describing a regex pattern. The AST is designed
/// to preserve behavior, but doesn't necessarily preserve the exact syntax.
#[derive(Serialize, Clone, Debug)]
pub enum Ast {
    Empty,
    //Char
    Literal(Literal),
    //abc  - Alternative
    Concat(Vec<Ast>),
    // Group
    Group(Rc<Group>),
    // CharacterClass
    CharacterClass(CharacterClass),
    // May be empty
    //  Disjunction
    // a|b|c
    Alternation(Vec<Ast>),
    // Repetition
    Repetition(Repetition),
    // Assertion
    Assertion(AssertionType),
    // Tree -> Flags
    Flags(Flags),
}


impl Serialize for Ast {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_map(Some(2))?;
        match self {
         Ast::Literal(literal) => {
             serializer..se
        }
        }
        state.serialize_entry("type", "Alternative")?;

        if let Ast::Alternation(expression) = self {
            state.serialize_entry("expressions", expression)?;
        } else {
            state.serialize_entry("expressions", &vec![])?;
        }
        state.end()
    }
}

#[derive(Serialize, Copy, Clone, Debug)]
pub struct Literal {
    #[serde(rename = "value")]
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

impl Serialize for Group {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_map(Some(4))?;
        state.serialize_entry("type", "Group")?;
        match self {
            Group::Capturing(group) => {
                state.serialize_entry("capturing", &false)?;
                state.serialize_entry("name", "")?;
                state.serialize_entry("expression", &group.inner)?;
            }
            Group::NonCapturing(group) => {
                state.serialize_entry("capturing", &true)?;
                state.serialize_entry("name", "")?;
                state.serialize_entry("expression", &group.inner)?;
            }
            Group::NamedCapturing(group) => {
                state.serialize_entry("capturing", &true)?;
                state.serialize_entry("name", &group.name)?;
                state.serialize_entry("expression", &group.inner)?;
            }
        }
        state.end()
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct CaptureGroup {
    pub inner: Ast,
}

#[derive(Serialize, Clone, Debug)]
pub struct NonCapturingGroup {
    pub flags: Flags,
    pub inner: Ast,
}

#[derive(Serialize, Clone, Debug)]
pub struct NamedCapturingGroup {
    pub name: String,
    pub inner: Ast,
}

#[derive(Serialize, Clone, Debug)]
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

#[derive(Serialize, Clone, Debug)]
pub struct UnicodePropertyClass {
    pub negate: bool,
    pub name: String,
}

#[derive(Serialize, Clone, Debug)]
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

#[derive(Serialize, Clone, Debug)]
pub struct Quantifier {
    pub lazy: bool,
    pub kind: QuantifierKind,
}

#[derive(Serialize, Clone, Debug)]
pub enum PerlCharacterClass {
    Digit,
    Space,
    Word,
    NonDigit,
    NonSpace,
    NonWord,
}

#[derive(Serialize, Clone, Debug)]
pub struct BracketCharacterClass {
    pub negated: bool,
    pub items: Vec<BracketCharacterClassItem>,
}

#[derive(Serialize, Clone, Debug)]
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

#[derive(Serialize, Clone, Debug)]
pub struct AsciiClass {
    pub negated: bool,
    pub kind: AsciiClassKind,
}

#[derive(Serialize, Clone, Debug)]
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

#[derive(Serialize, Clone, Debug)]
pub struct Repetition {
    pub quantifier: Quantifier,
    pub inner: Rc<Ast>,
}

#[derive(Serialize, Clone, Debug)]
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

#[derive(Serialize, Clone, Debug)]
pub struct Flags {
    /// Flags before a "-"
    pub add: Vec<Flag>,
    /// Flags after a "-"
    pub remove: Vec<Flag>,
}

#[derive(Serialize, Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
