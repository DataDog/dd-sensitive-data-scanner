use regex_syntax::ast::{
    Alternation, Assertion, AssertionKind, Ast, Flag, Flags, FlagsItem, FlagsItemKind, Group,
    GroupKind, Literal, LiteralKind, Position, Span,
};

pub(crate) fn should_push_word_boundary(c: char) -> bool {
    c.is_ascii_alphabetic() || c.is_ascii_digit()
}

pub(crate) fn any_char(chars: &[char]) -> Ast {
    let mut asts = vec![];

    for c in chars {
        asts.push(Ast::Literal(literal_ast(*c)));
    }

    Ast::Group(Group {
        span: span(),
        kind: GroupKind::NonCapturing(Flags {
            span: span(),
            items: vec![],
        }),
        ast: Box::new(Ast::Alternation(Alternation { span: span(), asts })),
    })
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

pub(crate) fn non_capturing_group(inner: Ast, flags: Vec<FlagsItem>) -> Ast {
    Ast::Group(Group {
        span: span(),
        kind: GroupKind::NonCapturing(Flags {
            span: span(),
            items: flags,
        }),
        ast: Box::new(inner),
    })
}

pub(crate) fn word_boundary() -> Ast {
    // The "Unicode" flag is disabled to disable the equivalent of Hyperscans UCP flag
    let inner = Ast::Assertion(Assertion {
        span: span(),
        kind: AssertionKind::WordBoundary,
    });

    let flags = vec![
        FlagsItem {
            span: span(),
            kind: FlagsItemKind::Negation,
        },
        FlagsItem {
            span: span(),
            kind: FlagsItemKind::Flag(Flag::Unicode),
        },
    ];

    non_capturing_group(inner, flags)
}
