use crate::parser::ast::{
    AsciiClass, AsciiClassKind, AssertionType, Ast, BracketCharacterClass,
    BracketCharacterClassItem, CharacterClass, Flag, Flags, Group, PerlCharacterClass,
    QuantifierKind, UnicodePropertyClass,
};
use crate::parser::regex_parser::parse_regex_pattern;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstNode {
    pub node_type: String,
    pub description: String,
    pub start: usize,
    pub end: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub children: Option<Vec<AstNode>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Value>,
}

/// Explains a regex pattern by parsing it and converting it to an AST with position tracking.
///
/// # Arguments
/// * `pattern` - The regex pattern string to explain
///
/// # Returns
/// * `Ok(AstNode)` - The root AST node with descriptions and positions if the pattern is valid
/// * `Err(String)` - An error message if the pattern is invalid
pub fn explain_regex(pattern: &str) -> Result<AstNode, String> {
    parse_regex_pattern(pattern)
        .map(|ast| {
            let mut node = ast_to_node_with_tracking(&ast, pattern, 0);
            // Fix the end position to match the actual pattern length
            // This is necessary because ast_to_string doesn't preserve
            // all escape sequences (e.g., \/ in bracket classes)
            node.end = pattern.len();
            node
        })
        .map_err(|err| format!("{:?}", err))
}

fn ast_to_string(ast: &Ast) -> String {
    match ast {
        Ast::Empty => String::new(),
        Ast::Literal(lit) => {
            if lit.escaped {
                format!("\\{}", lit.c)
            } else {
                lit.c.to_string()
            }
        }
        Ast::Concat(items) => items.iter().map(ast_to_string).collect(),
        Ast::Alternation(alts) => alts.iter().map(ast_to_string).collect::<Vec<_>>().join("|"),
        Ast::Group(group) => match group.as_ref() {
            Group::Capturing(g) => format!("({})", ast_to_string(&g.inner)),
            Group::NonCapturing(g) => {
                format!("(?{}:{})", format_flags(&g.flags), ast_to_string(&g.inner))
            }
            Group::NamedCapturing(g) => format!("(?<{}>{})", g.name, ast_to_string(&g.inner)),
        },
        Ast::Repetition(rep) => {
            let quantifier = match &rep.quantifier.kind {
                QuantifierKind::ZeroOrMore => "*".to_string(),
                QuantifierKind::OneOrMore => "+".to_string(),
                QuantifierKind::ZeroOrOne => "?".to_string(),
                QuantifierKind::RangeExact(n) => format!("{{{}}}", n),
                QuantifierKind::RangeMinMax(min, max) => format!("{{{},{}}}", min, max),
                QuantifierKind::RangeMin(min) => format!("{{{},}}", min),
            };
            let lazy = if rep.quantifier.lazy { "?" } else { "" };
            format!("{}{}{}", ast_to_string(&rep.inner), quantifier, lazy)
        }
        Ast::CharacterClass(class) => match class {
            CharacterClass::Dot => ".".to_string(),
            CharacterClass::Perl(perl) => match perl {
                PerlCharacterClass::Digit => "\\d",
                PerlCharacterClass::Space => "\\s",
                PerlCharacterClass::Word => "\\w",
                PerlCharacterClass::NonDigit => "\\D",
                PerlCharacterClass::NonSpace => "\\S",
                PerlCharacterClass::NonWord => "\\W",
            }
            .to_string(),
            CharacterClass::Bracket(bracket) => format_bracket_character_class(bracket),
            CharacterClass::HorizontalWhitespace => "\\h".to_string(),
            CharacterClass::NotHorizontalWhitespace => "\\H".to_string(),
            CharacterClass::VerticalWhitespace => "\\v".to_string(),
            CharacterClass::NotVerticalWhitespace => "\\V".to_string(),
            CharacterClass::UnicodeProperty(prop) => format_unicode_property(prop),
        },
        Ast::Assertion(assertion) => match assertion {
            AssertionType::WordBoundary => "\\b",
            AssertionType::NotWordBoundary => "\\B",
            AssertionType::StartLine => "^",
            AssertionType::EndLine => "$",
            AssertionType::StartText => "\\A",
            AssertionType::EndText => "\\z",
            AssertionType::EndTextOptionalNewline => "\\Z",
        }
        .to_string(),
        Ast::Flags(flags) => format!("(?{})", format_flags(flags)),
    }
}

fn ast_to_node_with_tracking(ast: &Ast, pattern: &str, offset: usize) -> AstNode {
    let node_str = ast_to_string(ast);
    let node_len = node_str.len();
    let start = offset.min(pattern.len());
    let end = (offset + node_len).min(pattern.len()).max(start);

    // Note: The end position for groups is corrected in ast_to_node_with_range

    ast_to_node_with_range(ast, pattern, start, end, offset)
}

fn find_matching_paren(pattern: &str, start: usize) -> Option<usize> {
    let bytes = pattern.as_bytes();
    if start >= bytes.len() || bytes[start] != b'(' {
        return None;
    }

    let mut depth = 0;
    let mut i = start;

    while i < bytes.len() {
        let ch = bytes[i];

        // Handle escape sequences
        if ch == b'\\' && i + 1 < bytes.len() {
            i += 2; // Skip the backslash and the next character
            continue;
        }

        // Check for brackets (character classes)
        if ch == b'[' {
            i += 1;
            // Inside bracket class - find the closing ]
            while i < bytes.len() {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    i += 2; // Skip escaped character
                    continue;
                }
                if bytes[i] == b']' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }

        // Check for parentheses
        match ch {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i + 1); // +1 to include the ')'
                }
            }
            _ => {}
        }

        i += 1;
    }

    None
}

fn ast_to_node_with_range(
    ast: &Ast,
    pattern: &str,
    start: usize,
    end: usize,
    offset: usize,
) -> AstNode {
    // SAFETY FIRST: Validate and clamp all positions
    let start = start.min(pattern.len());
    let end = end.min(pattern.len()).max(start);

    match ast {
        Ast::Empty => AstNode {
            node_type: "Empty".to_string(),
            description: "Empty expression (matches nothing)".to_string(),
            start,
            end,
            children: None,
            properties: None,
        },

        Ast::Literal(lit) => {
            let char_display = if lit.c.is_control() || lit.c.is_whitespace() {
                format!("'{}'", lit.c.escape_default())
            } else {
                format!("'{}'", lit.c)
            };

            AstNode {
                node_type: "Literal".to_string(),
                description: format!("Literal character {}.", char_display),
                start,
                end,
                children: None,
                properties: Some(serde_json::json!({
                    "character": lit.c.to_string(),
                    "escaped": lit.escaped,
                })),
            }
        }

        Ast::Concat(items) => {
            // For concatenation, track positions of each child
            let mut children = Vec::new();
            let mut current_offset = offset;

            for item in items {
                let child_str = ast_to_string(item);
                let child_len = child_str.len();
                let child_start = current_offset.min(pattern.len());
                let child_end = (current_offset + child_len)
                    .min(pattern.len())
                    .max(child_start);

                let child =
                    ast_to_node_with_range(item, pattern, child_start, child_end, current_offset);

                // Use the actual end position of the child (which may be corrected for groups)
                // instead of the calculated length from ast_to_string
                current_offset = child.end;
                children.push(child);
            }

            AstNode {
                node_type: "Concatenation".to_string(),
                description: format!("Concatenation of {} elements.", items.len()),
                start,
                end,
                children: Some(children),
                properties: None,
            }
        }

        Ast::Alternation(alts) => {
            // For alternation, each alternative gets its own position
            // Note: positions will overlap since alternatives are mutually exclusive
            let mut children = Vec::new();
            let mut current_offset = offset;

            for (i, alt) in alts.iter().enumerate() {
                let alt_str = ast_to_string(alt);
                let alt_len = alt_str.len();
                let alt_start = current_offset.min(pattern.len());
                let alt_end = (current_offset + alt_len).min(pattern.len()).max(alt_start);

                let child =
                    ast_to_node_with_range(alt, pattern, alt_start, alt_end, current_offset);
                children.push(child);

                // Move past this alternative and the '|' separator
                current_offset += alt_len;
                if i < alts.len() - 1 {
                    current_offset += 1; // for the '|'
                }
            }

            AstNode {
                node_type: "Alternation".to_string(),
                description: format!(
                    "An alternation. Choose the first expression that matches from {} alternatives.",
                    alts.len()
                ),
                start,
                end,
                children: Some(children),
                properties: None,
            }
        }

        Ast::Group(group) => {
            let (node_type, description, inner, prefix_len) = match group.as_ref() {
                Group::Capturing(g) => (
                    "Capturing Group",
                    "A capture group.",
                    &g.inner,
                    1, // "("
                ),
                Group::NonCapturing(g) => {
                    let flags_str = format_flags(&g.flags);
                    (
                        "Non-Capturing Group",
                        "A non-capturing group.",
                        &g.inner,
                        3 + flags_str.len(), // "(?flags:"
                    )
                }
                Group::NamedCapturing(g) => (
                    "Named Capturing Group",
                    format!("A named capture group '{}'.", g.name).leak() as &str,
                    &g.inner,
                    4 + g.name.len(), // "(?<name>"
                ),
            };

            // Inner content starts after the opening syntax
            let inner_offset = offset + prefix_len;
            let inner_str = ast_to_string(inner);
            let inner_len = inner_str.len();
            let inner_start = inner_offset.min(pattern.len());
            let inner_end = (inner_offset + inner_len)
                .min(pattern.len())
                .max(inner_start);

            let child =
                ast_to_node_with_range(inner, pattern, inner_start, inner_end, inner_offset);

            // Fix the end position: ast_to_string doesn't preserve escape sequences,
            // so we need to find the actual closing parenthesis
            let actual_end = find_matching_paren(pattern, start).unwrap_or(end);

            AstNode {
                node_type: node_type.to_string(),
                description: description.to_string(),
                start,
                end: actual_end,
                children: Some(vec![child]),
                properties: None,
            }
        }

        Ast::Repetition(rep) => {
            // Inner element comes first, quantifier follows
            let inner_str = ast_to_string(&rep.inner);
            let inner_len = inner_str.len();
            let inner_start = offset.min(pattern.len());
            let inner_end = (offset + inner_len).min(pattern.len()).max(inner_start);

            let child = ast_to_node_with_range(&rep.inner, pattern, inner_start, inner_end, offset);

            let (description, properties) = match &rep.quantifier.kind {
                QuantifierKind::ZeroOrMore => (
                    "Zero or more times (*)",
                    serde_json::json!({"lazy": rep.quantifier.lazy}),
                ),
                QuantifierKind::OneOrMore => (
                    "One or more times (+)",
                    serde_json::json!({"lazy": rep.quantifier.lazy}),
                ),
                QuantifierKind::ZeroOrOne => (
                    "Zero or one time (?)",
                    serde_json::json!({"lazy": rep.quantifier.lazy}),
                ),
                QuantifierKind::RangeExact(n) => (
                    format!("Exactly {} times", n).leak() as &str,
                    serde_json::json!({"min": n, "max": n, "lazy": rep.quantifier.lazy}),
                ),
                QuantifierKind::RangeMinMax(min, max) => (
                    format!("Between {} and {} times", min, max).leak() as &str,
                    serde_json::json!({"min": min, "max": max, "lazy": rep.quantifier.lazy}),
                ),
                QuantifierKind::RangeMin(min) => (
                    format!("{} or more times", min).leak() as &str,
                    serde_json::json!({"min": min, "max": null, "lazy": rep.quantifier.lazy}),
                ),
            };

            let full_desc = if rep.quantifier.lazy {
                format!("{} (lazy)", description)
            } else {
                description.to_string()
            };

            AstNode {
                node_type: "Repetition".to_string(),
                description: full_desc,
                start,
                end,
                children: Some(vec![child]),
                properties: Some(properties),
            }
        }

        Ast::CharacterClass(class) => {
            let (description, node_type) = match class {
                CharacterClass::Dot => (
                    "Matches any character except \\n. Enable the s flag to match any character, including \\n.".to_string(),
                    "Dot".to_string()
                ),
                CharacterClass::Perl(perl) => {
                    let (name, desc) = describe_perl_character_class(perl);
                    (format!("{} {}", name, desc), "Perl Character Class".to_string())
                },
                CharacterClass::Bracket(bracket) => {
                    let desc = if bracket.negated {
                        "Matches anything that is not listed inside the brackets."
                    } else {
                        "Matches any character listed inside the brackets."
                    };
                    (desc.to_string(), "Character Class".to_string())
                },
                CharacterClass::HorizontalWhitespace => (
                    "\\h Matches a space or tab ([\\x{20}\\t]).".to_string(),
                    "Horizontal Whitespace".to_string()
                ),
                CharacterClass::NotHorizontalWhitespace => (
                    "\\H Matches anything that does not match with \\h.".to_string(),
                    "Not Horizontal Whitespace".to_string()
                ),
                CharacterClass::VerticalWhitespace => (
                    "\\v Matches ASCII vertical space ([\\x{B}\\x{A}\\x{C}\\x{D}]).".to_string(),
                    "Vertical Whitespace".to_string()
                ),
                CharacterClass::NotVerticalWhitespace => (
                    "\\V Matches anything that does not match with \\v.".to_string(),
                    "Not Vertical Whitespace".to_string()
                ),
                CharacterClass::UnicodeProperty(prop) => {
                    let prefix = if prop.negate { "\\P" } else { "\\p" };
                    let desc = format!("{}{{{}}} Matches anything that matches the unicode property {}.", prefix, prop.name, prop.name);
                    (desc, "Unicode Property".to_string())
                },
            };

            // For bracket character classes, add child nodes for each item
            let children = match class {
                CharacterClass::Bracket(bracket) => {
                    Some(create_bracket_class_children(bracket, pattern, offset + 1)) // +1 for '['
                }
                _ => None,
            };

            AstNode {
                node_type,
                description,
                start,
                end,
                children,
                properties: None,
            }
        }

        Ast::Assertion(assertion) => {
            let (symbol, desc) = match assertion {
                AssertionType::WordBoundary => ("\\b", "A word boundary."),
                AssertionType::NotWordBoundary => ("\\B", "Not a word boundary."),
                AssertionType::StartLine => ("^", "Start of a line."),
                AssertionType::EndLine => ("$", "End of a line."),
                AssertionType::StartText => ("\\A", "Start of text."),
                AssertionType::EndText => ("\\z", "End of text."),
                AssertionType::EndTextOptionalNewline => (
                    "\\Z",
                    "End of text (or before a \\n that is immediately before the end of the text).",
                ),
            };

            AstNode {
                node_type: "Assertion".to_string(),
                description: format!("{} {}", symbol, desc),
                start,
                end,
                children: None,
                properties: Some(serde_json::json!({
                    "assertion_type": symbol,
                })),
            }
        }

        Ast::Flags(flags) => {
            let flags_str = format_flags(flags);
            let flag_descriptions = describe_flags(flags);
            AstNode {
                node_type: "Flags".to_string(),
                description: if flag_descriptions.is_empty() {
                    "Flags.".to_string()
                } else {
                    format!("Flags: {}", flag_descriptions)
                },
                start,
                end,
                children: None,
                properties: Some(serde_json::json!({
                    "flags": flags_str,
                })),
            }
        }
    }
}

fn describe_perl_character_class(perl: &PerlCharacterClass) -> (&'static str, &'static str) {
    match perl {
        PerlCharacterClass::Digit => ("\\d", "Matches any ASCII digit ([0-9])."),
        PerlCharacterClass::Space => (
            "\\s",
            "Matches any ASCII whitespace ([\\r\\n\\t\\x{C}\\x{B}\\x{20}]).",
        ),
        PerlCharacterClass::Word => ("\\w", "Matches any ASCII word character ([a-zA-Z0-9_])."),
        PerlCharacterClass::NonDigit => (
            "\\D",
            "Matches anything that does not match any ASCII digit ([0-9]).",
        ),
        PerlCharacterClass::NonSpace => (
            "\\S",
            "Matches anything that does not match any ASCII whitespace ([\\r\\n\\t\\x{C}\\x{B}\\x{20}]).",
        ),
        PerlCharacterClass::NonWord => (
            "\\W",
            "Matches anything that does not match any ASCII word character ([a-zA-Z0-9_]).",
        ),
    }
}

fn describe_ascii_class_kind(kind: &AsciiClassKind) -> &'static str {
    match kind {
        AsciiClassKind::Alnum => "Alphanumeric",
        AsciiClassKind::Alpha => "Alphabetic",
        AsciiClassKind::Ascii => "Any ASCII character",
        AsciiClassKind::Blank => "A space or tab",
        AsciiClassKind::Cntrl => "A control character",
        AsciiClassKind::Digit => "Any digit",
        AsciiClassKind::Graph => "Any graphical or printing character (not a space)",
        AsciiClassKind::Lower => "Any lowercase letter",
        AsciiClassKind::Print => "Any printable character (including spaces)",
        AsciiClassKind::Punct => "Any punctuation character",
        AsciiClassKind::Space => "A whitespace",
        AsciiClassKind::Upper => "Any uppercase letter",
        AsciiClassKind::Word => "Any ASCII word character ([a-zA-Z0-9_])",
        AsciiClassKind::Xdigit => "Any hexadecimal digit",
    }
}

fn create_bracket_class_children(
    bracket: &BracketCharacterClass,
    pattern: &str,
    mut offset: usize,
) -> Vec<AstNode> {
    let mut children = Vec::new();

    // Skip negation character if present
    if bracket.negated {
        offset += 1; // Skip '^'
    }

    for (i, item) in bracket.items.iter().enumerate() {
        let is_first = i == 0;
        let is_last = i == bracket.items.len() - 1;
        let item_str = format_bracket_item(item, is_first, is_last);
        let item_len = item_str.len();

        let start = offset.min(pattern.len());
        let end = (offset + item_len).min(pattern.len()).max(start);

        let (node_type, description) = match item {
            BracketCharacterClassItem::Literal(c) => {
                ("Literal".to_string(), format!("Literal character '{}'.", c))
            }
            BracketCharacterClassItem::Range(start_char, end_char) => (
                "Character Range".to_string(),
                format!("Range from '{}' to '{}'.", start_char, end_char),
            ),
            BracketCharacterClassItem::PerlCharacterClass(perl) => {
                let (name, desc) = describe_perl_character_class(perl);
                (
                    "Perl Character Class".to_string(),
                    format!("{} {}", name, desc),
                )
            }
            BracketCharacterClassItem::UnicodeProperty(prop) => {
                let prefix = if prop.negate { "\\P" } else { "\\p" };
                (
                    "Unicode Property".to_string(),
                    format!(
                        "{}{{{}}} Matches anything that matches the unicode property {}.",
                        prefix, prop.name, prop.name
                    ),
                )
            }
            BracketCharacterClassItem::AsciiClass(ascii) => {
                let kind_name = describe_ascii_class_kind(&ascii.kind);
                (
                    "ASCII Class".to_string(),
                    if ascii.negated {
                        format!("Inverted ASCII class. {}", kind_name)
                    } else {
                        format!("ASCII class. {}", kind_name)
                    },
                )
            }
            BracketCharacterClassItem::HorizontalWhitespace => (
                "Horizontal Whitespace".to_string(),
                "\\h Matches a space or tab ([\\x{20}\\t]).".to_string(),
            ),
            BracketCharacterClassItem::NotHorizontalWhitespace => (
                "Not Horizontal Whitespace".to_string(),
                "\\H Matches anything that does not match with \\h.".to_string(),
            ),
            BracketCharacterClassItem::VerticalWhitespace => (
                "Vertical Whitespace".to_string(),
                "\\v Matches ASCII vertical space ([\\x{B}\\x{A}\\x{C}\\x{D}]).".to_string(),
            ),
            BracketCharacterClassItem::NotVerticalWhitespace => (
                "Not Vertical Whitespace".to_string(),
                "\\V Matches anything that does not match with \\v.".to_string(),
            ),
        };

        children.push(AstNode {
            node_type,
            description,
            start,
            end,
            children: None,
            properties: None,
        });

        offset += item_len;
    }

    children
}

fn format_bracket_character_class(bracket: &BracketCharacterClass) -> String {
    let mut result = String::from("[");
    if bracket.negated {
        result.push('^');
    }
    for (i, item) in bracket.items.iter().enumerate() {
        let is_first = i == 0;
        let is_last = i == bracket.items.len() - 1;
        result.push_str(&format_bracket_item(item, is_first, is_last));
    }
    result.push(']');
    result
}

fn format_bracket_item(item: &BracketCharacterClassItem, is_first: bool, is_last: bool) -> String {
    match item {
        BracketCharacterClassItem::Literal(c) => {
            // Need to escape certain characters inside brackets
            match c {
                '\\' => "\\\\".to_string(),
                ']' => "\\]".to_string(),
                '^' if is_first => "\\^".to_string(), // Only escape ^ if it's first
                '-' if !is_first && !is_last => "\\-".to_string(), // Don't escape - at start or end
                _ => c.to_string(),
            }
        }
        BracketCharacterClassItem::Range(start, end) => format!("{}-{}", start, end),
        BracketCharacterClassItem::PerlCharacterClass(perl) => match perl {
            PerlCharacterClass::Digit => "\\d",
            PerlCharacterClass::Space => "\\s",
            PerlCharacterClass::Word => "\\w",
            PerlCharacterClass::NonDigit => "\\D",
            PerlCharacterClass::NonSpace => "\\S",
            PerlCharacterClass::NonWord => "\\W",
        }
        .to_string(),
        BracketCharacterClassItem::UnicodeProperty(prop) => format_unicode_property(prop),
        BracketCharacterClassItem::AsciiClass(ascii) => format_ascii_class(ascii),
        BracketCharacterClassItem::HorizontalWhitespace => "\\h".to_string(),
        BracketCharacterClassItem::NotHorizontalWhitespace => "\\H".to_string(),
        BracketCharacterClassItem::VerticalWhitespace => "\\v".to_string(),
        BracketCharacterClassItem::NotVerticalWhitespace => "\\V".to_string(),
    }
}

fn format_unicode_property(prop: &UnicodePropertyClass) -> String {
    if prop.negate {
        format!("\\P{{{}}}", prop.name)
    } else {
        format!("\\p{{{}}}", prop.name)
    }
}

fn format_ascii_class(ascii: &AsciiClass) -> String {
    let kind_str = match ascii.kind {
        AsciiClassKind::Alnum => "alnum",
        AsciiClassKind::Alpha => "alpha",
        AsciiClassKind::Ascii => "ascii",
        AsciiClassKind::Blank => "blank",
        AsciiClassKind::Cntrl => "cntrl",
        AsciiClassKind::Digit => "digit",
        AsciiClassKind::Graph => "graph",
        AsciiClassKind::Lower => "lower",
        AsciiClassKind::Print => "print",
        AsciiClassKind::Punct => "punct",
        AsciiClassKind::Space => "space",
        AsciiClassKind::Upper => "upper",
        AsciiClassKind::Word => "word",
        AsciiClassKind::Xdigit => "xdigit",
    };
    if ascii.negated {
        format!("[:^{}:]", kind_str)
    } else {
        format!("[:{}:]", kind_str)
    }
}

fn format_flags(flags: &Flags) -> String {
    let mut result = String::new();
    for flag in &flags.add {
        result.push(match flag {
            Flag::CaseInsensitive => 'i',
            Flag::MultiLine => 'm',
            Flag::DotMatchesNewLine => 's',
            Flag::IgnoreWhitespace => 'x',
        });
    }
    if !flags.remove.is_empty() {
        result.push('-');
        for flag in &flags.remove {
            result.push(match flag {
                Flag::CaseInsensitive => 'i',
                Flag::MultiLine => 'm',
                Flag::DotMatchesNewLine => 's',
                Flag::IgnoreWhitespace => 'x',
            });
        }
    }
    result
}

fn describe_flags(flags: &Flags) -> String {
    let mut descriptions = Vec::new();
    for flag in &flags.add {
        descriptions.push(match flag {
            Flag::CaseInsensitive => "i (Case insensitive: Letters match both upper and lower case)",
            Flag::MultiLine => "m (Multi-line mode: ^ and $ match the beginning and end of line)",
            Flag::DotMatchesNewLine => "s (Single line: Allows . to match any character, when it usually matches anything except \\n)",
            Flag::IgnoreWhitespace => "x (Extended: Whitespace is ignored except in a custom character class)",
        });
    }
    if !flags.remove.is_empty() {
        for flag in &flags.remove {
            descriptions.push(match flag {
                Flag::CaseInsensitive => "Remove i (case insensitive)",
                Flag::MultiLine => "Remove m (multi-line mode)",
                Flag::DotMatchesNewLine => "Remove s (single line)",
                Flag::IgnoreWhitespace => "Remove x (extended)",
            });
        }
    }
    descriptions.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== Basic Functionality Tests ====================

    #[test]
    fn test_valid_simple_pattern() {
        let result = explain_regex("test");
        assert!(result.is_ok());
        let tree = result.unwrap();
        assert_eq!(tree.node_type, "Concatenation");
    }

    #[test]
    fn test_invalid_pattern() {
        let result = explain_regex("[");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn test_json_serialization() {
        let result = explain_regex("foo+");
        assert!(result.is_ok());
        let tree = result.unwrap();
        let json = serde_json::to_string(&tree).unwrap();
        assert!(json.contains("node_type"));
        assert!(json.contains("description"));
    }

    // ==================== Position Accuracy Tests ====================

    #[test]
    fn test_literal_positions() {
        let pattern = "abc";
        let tree = explain_regex(pattern).unwrap();

        let children = tree.children.as_ref().unwrap();
        assert_eq!(children.len(), 3);

        // Each literal should have sequential positions
        assert_eq!(children[0].start, 0);
        assert_eq!(children[0].end, 1); // 'a'

        assert_eq!(children[1].start, 1);
        assert_eq!(children[1].end, 2); // 'b'

        assert_eq!(children[2].start, 2);
        assert_eq!(children[2].end, 3); // 'c'
    }

    #[test]
    fn test_alternation_positions() {
        let pattern = "foo|bar";
        let tree = explain_regex(pattern).unwrap();

        assert_eq!(tree.node_type, "Alternation");
        let children = tree.children.as_ref().unwrap();
        assert_eq!(children.len(), 2);

        // 'foo' at 0-3
        assert_eq!(children[0].start, 0);
        assert_eq!(children[0].end, 3);

        // 'bar' at 4-7 (after '|')
        assert_eq!(children[1].start, 4);
        assert_eq!(children[1].end, 7);
    }

    #[test]
    fn test_group_positions() {
        let pattern = "(test)";
        let tree = explain_regex(pattern).unwrap();

        assert_eq!(tree.node_type, "Capturing Group");
        assert_eq!(tree.start, 0);
        assert_eq!(tree.end, 6); // "(test)"

        // Inner content at 1-5 (between parens)
        let inner = &tree.children.as_ref().unwrap()[0];
        assert_eq!(inner.start, 1);
        assert_eq!(inner.end, 5);
    }

    #[test]
    fn test_repetition_positions() {
        let pattern = r"\w{3}";
        let tree = explain_regex(pattern).unwrap();

        assert_eq!(tree.node_type, "Repetition");
        assert_eq!(tree.start, 0);
        assert_eq!(tree.end, 5); // "\w{3}"

        // Inner \w at 0-2
        let inner = &tree.children.as_ref().unwrap()[0];
        assert_eq!(inner.start, 0);
        assert_eq!(inner.end, 2);
    }

    #[test]
    fn test_assertions_positions() {
        let pattern = r"^test$";
        let tree = explain_regex(pattern).unwrap();

        let children = tree.children.as_ref().unwrap();
        assert_eq!(children.len(), 6); // ^, t, e, s, t, $

        // ^ at 0-1
        assert_eq!(children[0].node_type, "Assertion");
        assert_eq!(children[0].start, 0);
        assert_eq!(children[0].end, 1);

        // $ at 5-6
        assert_eq!(children[5].node_type, "Assertion");
        assert_eq!(children[5].start, 5);
        assert_eq!(children[5].end, 6);
    }

    #[test]
    fn test_nested_groups_positions() {
        let pattern = "((x))";
        let tree = explain_regex(pattern).unwrap();

        assert_eq!(tree.start, 0);
        assert_eq!(tree.end, 5);

        let inner1 = &tree.children.as_ref().unwrap()[0];
        assert_eq!(inner1.start, 1);
        assert_eq!(inner1.end, 4);

        let inner2 = &inner1.children.as_ref().unwrap()[0];
        assert_eq!(inner2.start, 2);
        assert_eq!(inner2.end, 3);
    }

    // ==================== Bracket Character Class Tests ====================

    #[test]
    fn test_bracket_class_reconstruction() {
        let patterns = vec![
            ("[x-z]", 5),
            ("[0-5]", 5),
            ("[-xyz._]", 8),
            ("[^abc]", 6),
            (r"[\w\d]", 6),
        ];

        for (pattern, expected_len) in patterns {
            let result = explain_regex(pattern);
            assert!(result.is_ok(), "Pattern '{}' should be valid", pattern);

            let tree = result.unwrap();
            assert_eq!(
                tree.end, expected_len,
                "Pattern '{}' length mismatch",
                pattern
            );
        }
    }

    #[test]
    fn test_bracket_class_children() {
        let pattern = "[-a-z0-9]";
        let tree = explain_regex(pattern).unwrap();

        assert_eq!(tree.node_type, "Character Class");

        // Should have children for each item
        let children = tree.children.as_ref().unwrap();
        assert!(children.len() >= 2); // At least '-' and ranges

        // Verify each child has valid positions
        for child in children {
            assert!(child.start < child.end);
            assert!(child.end <= pattern.len());
        }
    }

    #[test]
    fn test_bracket_class_with_ranges() {
        let pattern = "[a-z0-9]";
        let tree = explain_regex(pattern).unwrap();
        let children = tree.children.as_ref().unwrap();

        // Should have children for each range
        for child in children {
            validate_node_positions(child, pattern);
        }
    }

    // ==================== Complex Patterns ====================

    #[test]
    fn test_phone_number_like_pattern() {
        // Using explicit pattern, not actual phone number regex
        let pattern = r"\d{3}-\d{3}";
        let tree = explain_regex(pattern).unwrap();
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_alternation_with_groups() {
        let pattern = r"(x|y)|z";
        let tree = explain_regex(pattern).unwrap();
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_nested_repetitions() {
        let pattern = r"(x+)+";
        let tree = explain_regex(pattern).unwrap();
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_multiple_assertions() {
        let pattern = r"^\btest\b$";
        let tree = explain_regex(pattern).unwrap();
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_escaped_slash_in_bracket_class() {
        // Test pattern with escaped forward slash in bracket class
        let pattern = r"[\w.+\/=-]+";
        let result = explain_regex(pattern);

        assert!(result.is_ok(), "Pattern should be valid");
        let tree = result.unwrap();

        // The full pattern should be captured
        assert_eq!(tree.start, 0);
        assert_eq!(tree.end, pattern.len());

        // Walk through and validate all positions
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_complex_pattern_with_escape_sequences() {
        // Test pattern with named capture groups and character classes
        // This demonstrates: word boundaries, named groups, and character class ranges
        let pattern = "\\b(?<capture>example[A-Z0-9]{2})\\b";
        let result = explain_regex(pattern);

        assert!(result.is_ok(), "Pattern should be valid: {:?}", result);
        let tree = result.unwrap();

        // Root should span entire pattern
        assert_eq!(tree.start, 0, "Root should start at 0");
        assert_eq!(tree.end, pattern.len(), "Root should end at pattern length");

        // Validate all positions recursively - this will check that groups end with ')'
        validate_node_positions(&tree, pattern);
    }

    // ==================== Quantifier Tests ====================

    #[test]
    fn test_greedy_quantifiers() {
        let patterns = vec!["x*", "x+", "x?", "x{2,5}", "x{2,}"];

        for pattern in patterns {
            let tree = explain_regex(pattern).unwrap();
            assert_eq!(tree.node_type, "Repetition");

            // Greedy quantifiers have lazy: false in properties
            if let Some(properties) = &tree.properties {
                if let Some(is_lazy) = properties.get("lazy") {
                    assert_eq!(
                        is_lazy,
                        &serde_json::json!(false),
                        "Pattern '{}' should be greedy",
                        pattern
                    );
                }
            }
        }
    }

    #[test]
    fn test_lazy_quantifiers() {
        let patterns = vec!["x*?", "x+?", "x??", "x{2,5}?", "x{2,}?"];

        for pattern in patterns {
            let tree = explain_regex(pattern).unwrap();
            assert!(tree.description.contains("lazy"));
        }
    }

    // ==================== Flags Tests ====================

    #[test]
    fn test_case_insensitive_flag() {
        let pattern = "(?i)test";
        let tree = explain_regex(pattern).unwrap();
        let children = tree.children.as_ref().unwrap();

        assert_eq!(children[0].node_type, "Flags");
        assert!(children[0].description.contains("Case insensitive"));
    }

    #[test]
    fn test_multiple_flags() {
        let pattern = "(?ims)test";
        let tree = explain_regex(pattern).unwrap();
        validate_node_positions(&tree, pattern);
    }

    // ==================== Safety and Edge Cases ====================

    #[test]
    fn test_positions_never_exceed_bounds() {
        let patterns = vec![
            "x",
            "test",
            r"\d+",
            "foo|bar",
            "(test)",
            r"x{1,5}",
            "[a-z]+",
            r"\btest\b",
            "(?:foo|bar)+",
            r"x+?y*?z{2,5}?",
            r"((x|(y|z))+\.){2}",
        ];

        for pattern in patterns {
            if let Ok(tree) = explain_regex(pattern) {
                validate_node_positions(&tree, pattern);
            }
        }
    }

    #[test]
    fn test_highlighting_safety() {
        // Patterns that could potentially cause highlighting issues
        let patterns = vec![
            "test",
            r"\w+",
            "x|y",
            "(test)",
            r"x{3}-y{4}",
            "[a-z]+",
            r"x+y*z?",
            r"\btest\b",
            "(?:foo)+",
            r"(x|(y|z))",
            "((((w))))",
        ];

        for pattern in patterns {
            if let Ok(tree) = explain_regex(pattern) {
                validate_node_positions(&tree, pattern);
            }
        }
    }

    #[test]
    fn test_no_overlapping_children() {
        let pattern = "xyz";
        let tree = explain_regex(pattern).unwrap();
        let children = tree.children.unwrap();

        // Positions should be sequential
        for i in 0..children.len() - 1 {
            assert!(children[i].end <= children[i + 1].start);
        }
    }

    #[test]
    fn test_deeply_nested_groups() {
        let pattern = "((((x))))";
        let tree = explain_regex(pattern).unwrap();
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_empty_alternation() {
        let pattern = "x||y";
        let tree = explain_regex(pattern).unwrap();
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_unicode_property() {
        let pattern = r"\p{L}+";
        let tree = explain_regex(pattern).unwrap();
        validate_node_positions(&tree, pattern);
    }

    // ==================== Multi-byte Character Tests ====================

    #[test]
    fn test_emoji_in_literal() {
        // Emoji are multi-byte UTF-8 characters
        let pattern = "😀";
        let tree = explain_regex(pattern).unwrap();

        assert_eq!(tree.node_type, "Literal");
        assert_eq!(tree.start, 0);
        assert_eq!(tree.end, pattern.len()); // Should be 4 bytes

        // Verify we can safely slice
        let slice = &pattern[tree.start..tree.end];
        assert_eq!(slice, "😀");
    }

    #[test]
    fn test_emoji_in_concatenation() {
        let pattern = "a😀b";
        let tree = explain_regex(pattern).unwrap();

        assert_eq!(tree.node_type, "Concatenation");
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_emoji_in_alternation() {
        let pattern = "😀|😎";
        let tree = explain_regex(pattern).unwrap();

        assert_eq!(tree.node_type, "Alternation");
        let children = tree.children.as_ref().unwrap();
        assert_eq!(children.len(), 2);

        // Verify positions for each emoji
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_emoji_in_group() {
        let pattern = "(😀+)";
        let tree = explain_regex(pattern).unwrap();

        assert_eq!(tree.node_type, "Capturing Group");
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_mixed_ascii_and_emoji() {
        let pattern = "test😀abc";
        let tree = explain_regex(pattern).unwrap();

        validate_node_positions(&tree, pattern);

        // Ensure no child spans beyond pattern length
        fn check_bounds(node: &AstNode, pattern_len: usize) {
            assert!(
                node.end <= pattern_len,
                "Node end {} exceeds pattern length {}",
                node.end,
                pattern_len
            );
            if let Some(children) = &node.children {
                for child in children {
                    check_bounds(child, pattern_len);
                }
            }
        }
        check_bounds(&tree, pattern.len());
    }

    #[test]
    fn test_unicode_combining_characters() {
        // Combining characters (e.g., é = e + combining acute)
        let pattern = "café";
        let tree = explain_regex(pattern).unwrap();

        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_chinese_characters() {
        let pattern = "你好";
        let tree = explain_regex(pattern).unwrap();

        assert_eq!(tree.node_type, "Concatenation");
        validate_node_positions(&tree, pattern);
    }

    #[test]
    fn test_emoji_with_regex_operators() {
        let pattern = "😀+|😎*";
        let tree = explain_regex(pattern).unwrap();

        validate_node_positions(&tree, pattern);
    }

    // ==================== Helper Functions ====================

    fn validate_node_positions(node: &AstNode, pattern: &str) {
        assert!(
            node.start <= node.end,
            "Start ({}) should be <= end ({}) for {}",
            node.start,
            node.end,
            node.node_type
        );
        assert!(
            node.end <= pattern.len(),
            "End ({}) should be <= pattern length ({}) for {}",
            node.end,
            pattern.len(),
            node.node_type
        );

        // Validate that group nodes end with ')'
        if node.start < pattern.len() && node.end <= pattern.len() && node.start < node.end {
            let content = &pattern[node.start..node.end];
            if node.node_type.contains("Group") {
                assert!(
                    content.ends_with(')'),
                    "{} [{}..{}] should end with ')' but content is: {:?}",
                    node.node_type,
                    node.start,
                    node.end,
                    content
                );
            }
        }

        if let Some(children) = &node.children {
            for child in children {
                validate_node_positions(child, pattern);
            }
        }
    }
}
