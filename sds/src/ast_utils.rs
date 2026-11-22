use regex_syntax::ast::{Literal, LiteralKind, Position, Span};

pub(crate) fn should_push_word_boundary(c: char) -> bool {
    c.is_ascii_alphabetic() || c.is_ascii_digit()
}

pub(crate) fn literal_ast(c: char) -> Literal {
    let kind = if regex_syntax::is_meta_character(c) {
        LiteralKind::Meta
    } else {
        LiteralKind::Verbatim
    };
    Literal {
        span: span(),
        kind,
        c,
    }
}

// creates a unused span required for the RegexAst
pub(crate) fn span() -> Span {
    Span::new(Position::new(0, 0, 0), Position::new(0, 0, 0))
}
