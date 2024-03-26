use crate::labels::{Labels, NO_LABEL};
use crate::proximity_keywords::ProximityKeywordsValidationError::{
    EmptyKeyword, InvalidLookAheadCharacterCount, KeywordTooLong, TooManyKeywords,
};
use crate::rule::ProximityKeywordsConfig;
use metrics::{counter, Counter};
use regex_automata::{meta, Input};
use regex_syntax::ast::{
    Alternation, Assertion, AssertionKind, Ast, Class, ClassBracketed, ClassSet, ClassSetItem,
    ClassSetUnion, Concat, Flag, Flags, FlagsItem, FlagsItemKind, Group, GroupKind, Literal,
    LiteralKind, Position, Repetition, RepetitionKind, RepetitionOp, Span,
};

const MAX_KEYWORD_COUNT: usize = 50;
const MAX_LOOK_AHEAD_CHARACTER_COUNT: usize = 50;

pub const TYPE: &str = "type";

/// Internal representation of included keywords after it has been validated / compiled.
#[derive(Default)]
pub struct CompiledProximityKeywords {
    look_ahead_character_count: usize,
    included_keywords_pattern: Option<meta::Regex>,
    excluded_keywords_pattern: Option<meta::Regex>,
    metrics: Metrics,
}

/// Characters we strip inside for excluded keywords in order to remove some noise
/// If this list contains more than a couple chars, some optimizations may be needed below
const EXCLUDED_KEYWORDS_REMOVED_CHARS: &[char] = &['-', '_'];

impl CompiledProximityKeywords {
    pub fn is_false_positive_match(&self, content: &str, match_start: usize) -> bool {
        match (
            &self.included_keywords_pattern,
            &self.excluded_keywords_pattern,
        ) {
            (Some(included_keywords), _) => {
                let is_false_positive = !contains_keyword_match(
                    content,
                    match_start,
                    self.look_ahead_character_count,
                    false,
                    included_keywords,
                );
                if is_false_positive {
                    self.metrics.false_positive_included_keywords.increment(1);
                }
                is_false_positive
            }
            (None, Some(excluded_keywords)) => {
                let is_false_positive = contains_keyword_match(
                    content,
                    match_start,
                    self.look_ahead_character_count,
                    true,
                    excluded_keywords,
                );
                if is_false_positive {
                    self.metrics.false_positive_excluded_keywords.increment(1);
                }
                is_false_positive
            }
            (None, None) => {
                /* no keywords to check */
                false
            }
        }
    }

    pub fn try_new(
        config: ProximityKeywordsConfig,
        labels: &Labels,
    ) -> Result<Self, ProximityKeywordsValidationError> {
        if config.look_ahead_character_count == 0
            || config.look_ahead_character_count > MAX_LOOK_AHEAD_CHARACTER_COUNT
        {
            return Err(InvalidLookAheadCharacterCount);
        }
        if config.included_keywords.is_empty() && config.excluded_keywords.is_empty() {
            return Ok(CompiledProximityKeywords::default());
        }
        if config.included_keywords.len() > MAX_KEYWORD_COUNT
            || config.excluded_keywords.len() > MAX_KEYWORD_COUNT
        {
            return Err(TooManyKeywords);
        }

        // No error is expected during pattern compilation because the regex is build internally in this method
        let included_pattern = compile_keywords(
            config.included_keywords,
            config.look_ahead_character_count,
            &[],
        )?;
        let excluded_pattern = compile_keywords(
            config.excluded_keywords,
            config.look_ahead_character_count,
            EXCLUDED_KEYWORDS_REMOVED_CHARS,
        )?;

        Ok(CompiledProximityKeywords {
            look_ahead_character_count: config.look_ahead_character_count,
            included_keywords_pattern: included_pattern,
            excluded_keywords_pattern: excluded_pattern,
            metrics: Metrics::new(labels),
        })
    }
}

/// Returns the match context which is what is searched for keywords
/// and the range where matches are searched for. The range is needed since the context is
/// expanded to ensure regex assertions (e.g. word boundaries) work correctly.
fn contains_keyword_match(
    content: &str,
    match_start: usize,
    mut look_ahead_char_count: usize,
    strip_chars: bool,
    regex: &meta::Regex,
) -> bool {
    let prefix = &content[0..match_start];

    let prefix_start = if strip_chars {
        let mut prefix_start = match_start;
        // "EXCLUDED_KEYWORDS_REMOVED_CHARS" don't count towards the "look_ahead_char_count"
        let mut char_indices = prefix.char_indices();

        while look_ahead_char_count > 0 {
            match char_indices.next_back() {
                Some((i, c)) => {
                    prefix_start = i;
                    if !EXCLUDED_KEYWORDS_REMOVED_CHARS.contains(&c) {
                        look_ahead_char_count -= 1;
                    }
                }
                None => {
                    prefix_start = 0;
                    break;
                }
            }
        }
        prefix_start
    } else {
        // just get the previous n chars (no chars are skipped)
        prefix
            .char_indices()
            .nth_back(look_ahead_char_count - 1)
            .map(|item| item.0)
            .unwrap_or(0)
    };

    let prefix_end = match_start;

    let input = Input::new(content)
        .earliest(true)
        .span(prefix_start..prefix_end);
    regex.search_half(&input).is_some()
}

struct Metrics {
    pub false_positive_included_keywords: Counter,
    pub false_positive_excluded_keywords: Counter,
}

impl Metrics {
    pub fn new(labels: &Labels) -> Self {
        Metrics {
            false_positive_included_keywords: counter!(
                "false_positive.proximity_keywords",
                labels.clone_with_labels(&[(TYPE, "included_keywords".to_string())])
            ),
            false_positive_excluded_keywords: counter!(
                "false_positive.proximity_keywords",
                labels.clone_with_labels(&[(TYPE, "excluded_keywords".to_string())])
            ),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics::new(&NO_LABEL)
    }
}

fn compile_keywords(
    keywords: Vec<String>,
    look_ahead_character_count: usize,
    remove_chars: &[char],
) -> Result<Option<meta::Regex>, ProximityKeywordsValidationError> {
    if keywords.is_empty() {
        return Ok(None);
    }
    let keyword_patterns: Vec<Ast> = keywords
        .into_iter()
        .map(|keyword| {
            if keyword.chars().count() > look_ahead_character_count {
                return Err(KeywordTooLong);
            }

            let trimmed_keyword = keyword.trim().replace(remove_chars, "");
            if trimmed_keyword.is_empty() {
                return Err(EmptyKeyword);
            }
            Ok(calculate_keyword_pattern(&trimmed_keyword, remove_chars))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let pattern = Ast::Alternation(Alternation {
        span: span(),
        asts: keyword_patterns,
    })
    .to_string();

    Ok(Some(
        meta::Regex::builder()
            .configure(
                meta::Config::new()
                    .nfa_size_limit(None)
                    // This is the default that `Regex` uses
                    .hybrid_cache_capacity(2 * (1 << 20)),
            )
            .syntax(regex_automata::util::syntax::Config::default().case_insensitive(true))
            .build(&pattern)
            .unwrap(),
    ))
}

/// Transform a keyword in an AST, the keyword MUST NOT be empty
fn calculate_keyword_pattern(keyword: &str, remove_chars: &[char]) -> Ast {
    let mut keyword_pattern: Vec<Ast> = vec![];
    if keyword
        .chars()
        .next()
        .map(|char| char.is_ascii_alphabetic() || char.is_ascii_digit())
        .unwrap()
    {
        keyword_pattern.push(word_boundary())
    }

    for (i, c) in keyword.chars().enumerate() {
        if i != 0 {
            if let Some(p) = allowed_chars_pattern(remove_chars) {
                keyword_pattern.push(p);
            };
            // allow any number of the "remove_chars" between characters of the keyword
        }
        keyword_pattern.push(Ast::Literal(literal_ast(c)))
    }

    if keyword
        .chars()
        .next_back()
        .map(|char| char.is_ascii_alphabetic() || char.is_ascii_digit())
        .unwrap()
    {
        keyword_pattern.push(word_boundary())
    }
    Ast::Concat(Concat {
        span: span(),
        asts: keyword_pattern,
    })
}

// This creates a pattern that allows any number of the following chars (including 0)
fn allowed_chars_pattern(allowed_chars: &[char]) -> Option<Ast> {
    if allowed_chars.is_empty() {
        return None;
    }

    let char_literals = allowed_chars
        .iter()
        .map(|c| ClassSetItem::Literal(literal_ast(*c)))
        .collect::<Vec<_>>();

    Some(Ast::Repetition(Repetition {
        span: span(),
        op: RepetitionOp {
            span: span(),
            kind: RepetitionKind::ZeroOrMore,
        },
        greedy: true,
        ast: Box::new(Ast::Class(Class::Bracketed(ClassBracketed {
            span: span(),
            negated: false,
            kind: ClassSet::Item(ClassSetItem::Union(ClassSetUnion {
                span: span(),
                items: char_literals,
            })),
        }))),
    }))
}

fn literal_ast(c: char) -> Literal {
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
fn span() -> Span {
    Span::new(Position::new(0, 0, 0), Position::new(0, 0, 0))
}

fn word_boundary() -> Ast {
    // The "Unicode" flag is disabled to disable the equivalent of Hyperscans UCP flag
    Ast::Group(Group {
        span: span(),
        kind: GroupKind::NonCapturing(Flags {
            span: span(),
            items: vec![
                FlagsItem {
                    span: span(),
                    kind: FlagsItemKind::Negation,
                },
                FlagsItem {
                    span: span(),
                    kind: FlagsItemKind::Flag(Flag::Unicode),
                },
            ],
        }),
        ast: Box::new(Ast::Assertion(Assertion {
            span: span(),
            kind: AssertionKind::WordBoundary,
        })),
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProximityKeywordsValidationError {
    /// No more than [MAX_KEYWORD_COUNT] are allowed.
    TooManyKeywords,

    /// Trim empty keywords are not allowed.
    EmptyKeyword,

    /// keywords cannot be longer than the look_ahead_character_count of the [ProximityKeywordsConfig].
    KeywordTooLong,

    /// Look ahead character count should be bigger than 0 and cannot be longer than [MAX_LOOK_AHEAD_CHARACTER_COUNT].
    InvalidLookAheadCharacterCount,
}

#[cfg(test)]
mod test {
    use crate::proximity_keywords::*;

    fn try_new_compiled_proximity_keyword(
        look_ahead_character_count: usize,
        included_keywords: Vec<String>,
        excluded_keywords: Vec<String>,
    ) -> Result<CompiledProximityKeywords, ProximityKeywordsValidationError> {
        CompiledProximityKeywords::try_new(
            ProximityKeywordsConfig {
                look_ahead_character_count,
                included_keywords,
                excluded_keywords,
            },
            &NO_LABEL,
        )
    }

    #[test]
    fn test_empty_keyword() {
        let proximity_keywords = try_new_compiled_proximity_keyword(30, vec![], vec![]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("hello world", 6));
    }

    #[test]
    fn test_included_keyword() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["hello".to_string()], vec![]).unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(!proximity_keywords.is_false_positive_match("hey, hello world", 11));

        assert!(proximity_keywords.is_false_positive_match("world ", 5));
        assert!(proximity_keywords.is_false_positive_match("world", 0));

        assert!(proximity_keywords.is_false_positive_match("hello world", 3));
    }

    #[test]
    fn test_excluded_keyword() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["hello".to_string()]).unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(proximity_keywords.is_false_positive_match("hey, hello world", 11));

        assert!(!proximity_keywords.is_false_positive_match("world ", 5));
        assert!(!proximity_keywords.is_false_positive_match("world", 0));

        assert!(!proximity_keywords.is_false_positive_match("hello world", 3));
    }

    #[test]
    fn test_included_and_excluded_keyword() {
        let proximity_keywords = try_new_compiled_proximity_keyword(
            30,
            vec!["hey".to_string()],
            vec!["hello".to_string()],
        )
        .unwrap();

        // only the included keyword is present
        assert!(!proximity_keywords.is_false_positive_match("hey world", 6));
        // only the excluded keyword is present
        assert!(proximity_keywords.is_false_positive_match("hello world", 6));
        // no keyword is present
        assert!(proximity_keywords.is_false_positive_match("world", 5));
        // included and excluded keywords are present
        assert!(!proximity_keywords.is_false_positive_match("hey, hello world", 11));
    }

    #[test]
    fn should_detect_on_any_keyword() {
        let proximity_keywords = try_new_compiled_proximity_keyword(
            30,
            vec!["hello".to_string(), "coty".to_string()],
            vec![],
        )
        .unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(!proximity_keywords.is_false_positive_match("hey coty, hello world", 16));

        assert!(proximity_keywords.is_false_positive_match("hey hey hey world", 12));

        let proximity_keywords = try_new_compiled_proximity_keyword(
            30,
            vec![],
            vec!["hello".to_string(), "coty".to_string()],
        )
        .unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(proximity_keywords.is_false_positive_match("hey coty, hello world", 16));

        assert!(!proximity_keywords.is_false_positive_match("hey hey hey world", 12));
    }

    #[test]
    fn should_quote_keyword() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["he.*o".to_string()], vec![]).unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(!proximity_keywords.is_false_positive_match("he.*o world", 6));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["he.*o".to_string()]).unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(proximity_keywords.is_false_positive_match("he.*o world", 6));
    }

    #[test]
    fn keywords_should_be_case_insensitive() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["hello".to_string()], vec![]).unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(!proximity_keywords.is_false_positive_match("HELLO world", 6));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["hello".to_string()]).unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(proximity_keywords.is_false_positive_match("HELLO world", 6));
    }

    #[test]
    fn included_keyword_should_have_word_boundaries() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["host".to_string()], vec![]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("host ping", 5));
        assert!(proximity_keywords.is_false_positive_match("localhost ping", 10));
        assert!(proximity_keywords.is_false_positive_match("hostlocal ping", 10));

        // word boundaries are is added at the beginning (resp. end) only if the first (resp. last) character is a letter or a digit
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["-host".to_string()], vec![]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("-host- ping", 6));
        assert!(!proximity_keywords.is_false_positive_match("local-host ping", 11));
        assert!(proximity_keywords.is_false_positive_match("-hostlocal ping", 11));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["ৎhost".to_string()], vec![]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("ৎhost ping", 7));
        assert!(!proximity_keywords.is_false_positive_match("localৎhost ping", 12));
    }

    #[test]
    fn excluded_keyword_should_have_word_boundaries() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["host".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("host ping", 5));
        assert!(!proximity_keywords.is_false_positive_match("localhost ping", 10));
        assert!(!proximity_keywords.is_false_positive_match("hostlocal ping", 10));

        // word boundaries are is added at the beginning (resp. end) only if the first (resp. last) character is a letter or a digit
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["!host".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("!host- ping", 6));
        assert!(proximity_keywords.is_false_positive_match("local!host ping", 11));
        assert!(!proximity_keywords.is_false_positive_match("!hostlocal ping", 11));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["ৎhost".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("ৎhost ping", 7));
        assert!(proximity_keywords.is_false_positive_match("localৎhost ping", 12));
    }

    #[test]
    fn should_remove_excluded_keywords_removed_chars_in_excluded_keywords_and_prefix() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["span-id".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("span-id ping", 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", 8));
        assert!(!proximity_keywords.is_false_positive_match("span id ping", 8));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["span_id".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("span-id ping", 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", 8));
        assert!(!proximity_keywords.is_false_positive_match("span id ping", 8));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["spanid".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("span-id ping", 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", 8));
        assert!(!proximity_keywords.is_false_positive_match("span id ping", 8));

        // nothing is changed on included keywords
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["span-id".to_string()], vec![]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("span-id ping", 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", 8));
    }

    #[test]
    fn should_look_ahead_too_far() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(10, vec!["host".to_string()], vec![]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("host 56789012345", 15));
        assert!(!proximity_keywords.is_false_positive_match("host 56789012345", 10));
        // prefix `ost 567890` does not contains host
        assert!(proximity_keywords.is_false_positive_match("host 56789012345", 11));
        assert!(!proximity_keywords.is_false_positive_match(" host 6789012345", 11));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(10, vec![], vec!["host".to_string()]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("host 56789012345", 15));
        assert!(proximity_keywords.is_false_positive_match("host 56789012345", 10));
        // prefix `ost 567890` does not contains host
        assert!(!proximity_keywords.is_false_positive_match("host 56789012345", 11));
        assert!(proximity_keywords.is_false_positive_match(" host 6789012345", 11));
    }

    #[test]
    fn should_not_contains_trim_empty_keyword() {
        let proximity_keywords = try_new_compiled_proximity_keyword(
            10,
            vec!["hello".to_string(), " ".to_string()],
            vec![],
        );
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), EmptyKeyword);

        let proximity_keywords = try_new_compiled_proximity_keyword(
            10,
            vec![],
            vec!["hello".to_string(), " ".to_string()],
        );
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), EmptyKeyword);

        // for excluded keywords, the limit should take into account the removed chars (- and _)
        let proximity_keywords =
            try_new_compiled_proximity_keyword(10, vec![], vec!["-".to_string()]);
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), EmptyKeyword);
    }

    #[test]
    fn should_not_have_more_than_keyword_count_limit() {
        let proximity_keywords = try_new_compiled_proximity_keyword(
            30,
            std::iter::repeat(["hello".to_string()])
                .flatten()
                .take(MAX_KEYWORD_COUNT)
                .collect(),
            vec![],
        );
        assert!(proximity_keywords.is_ok());

        let proximity_keywords = try_new_compiled_proximity_keyword(
            30,
            std::iter::repeat(["hello".to_string()])
                .flatten()
                .take(MAX_KEYWORD_COUNT + 1)
                .collect(),
            vec![],
        );
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), TooManyKeywords);

        let proximity_keywords = try_new_compiled_proximity_keyword(
            30,
            vec![],
            std::iter::repeat(["hello".to_string()])
                .flatten()
                .take(MAX_KEYWORD_COUNT)
                .collect(),
        );
        assert!(proximity_keywords.is_ok());

        let proximity_keywords = try_new_compiled_proximity_keyword(
            30,
            vec![],
            std::iter::repeat(["hello".to_string()])
                .flatten()
                .take(MAX_KEYWORD_COUNT + 1)
                .collect(),
        );
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), TooManyKeywords);
    }

    #[test]
    fn should_not_go_over_character_count_limit() {
        let proximity_keywords = try_new_compiled_proximity_keyword(
            MAX_LOOK_AHEAD_CHARACTER_COUNT,
            vec!["hello".to_string()],
            vec![],
        );
        assert!(proximity_keywords.is_ok());

        let proximity_keywords = try_new_compiled_proximity_keyword(
            MAX_LOOK_AHEAD_CHARACTER_COUNT + 1,
            vec!["hello".to_string()],
            vec![],
        );
        assert!(proximity_keywords.is_err());
        assert_eq!(
            proximity_keywords.err().unwrap(),
            InvalidLookAheadCharacterCount
        );

        let proximity_keywords =
            try_new_compiled_proximity_keyword(0, vec!["hello".to_string()], vec![]);
        assert!(proximity_keywords.is_err());
        assert_eq!(
            proximity_keywords.err().unwrap(),
            InvalidLookAheadCharacterCount
        );
    }

    #[test]
    fn keywords_should_be_smaller_than_character_count() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(5, vec!["hello".to_string()], vec![]);
        assert!(proximity_keywords.is_ok());

        let proximity_keywords =
            try_new_compiled_proximity_keyword(5, vec!["hello-".to_string()], vec![]);
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), KeywordTooLong);

        let proximity_keywords =
            try_new_compiled_proximity_keyword(5, vec![], vec!["hello".to_string()]);
        assert!(proximity_keywords.is_ok());

        let proximity_keywords =
            try_new_compiled_proximity_keyword(5, vec![], vec!["hello1".to_string()]);
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), KeywordTooLong);
    }

    #[test]
    fn test_included_keywords_on_start_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec!["id".to_string()], vec![]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("invalid   abc", 10);

        assert_eq!(is_false_positive, true);
    }

    #[test]
    fn test_included_keywords_on_end_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec!["id".to_string()], vec![]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("foo idabc", 6);

        assert_eq!(is_false_positive, true);
    }

    #[test]
    fn test_included_keywords_on_start_boundary_with_space() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec!["id".to_string()], vec![]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("users id   ab", 11);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_excluded_keyword_strip_chars_dont_count_towards_look_ahead_count() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();

        // "id" only fits in the match prefix (5 chars) if the "-" char isn't counted towards the 5 chars
        let is_false_positive = keywords.is_false_positive_match("users i-d   ab", 12);

        assert_eq!(is_false_positive, true);
    }

    #[test]
    fn test_included_keywords_on_start_boundary_with_space_including_word_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(7, vec!["id".to_string()], vec![]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("users id   ab", 11);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_excluded_keywords_on_start_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("invalid   abc", 10);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_excluded_keywords_on_end_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("foo idabc", 6);
        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_compile_keywords() {
        let regex = compile_keywords(vec!["hello".to_string()], 5, &[])
            .unwrap()
            .unwrap();
        assert_eq!(regex.is_match("hello"), true);
        assert_eq!(regex.is_match("he-l_lo"), false);
    }

    #[test]
    fn test_compile_keywords_with_removed_chars() {
        let regex = compile_keywords(vec!["hello".to_string()], 5, &['-', '_'])
            .unwrap()
            .unwrap();
        assert_eq!(regex.is_match("hello"), true);
        assert_eq!(regex.is_match("he-l_lo"), true);
    }

    #[test]
    fn test_allowed_chars_pattern() {
        assert_eq!(
            allowed_chars_pattern(&['a', 'b', 'c']).map(|p| p.to_string()),
            Some("[abc]*".to_string())
        );
        assert_eq!(
            allowed_chars_pattern(&['a']).map(|p| p.to_string()),
            Some("[a]*".to_string())
        );
        assert_eq!(allowed_chars_pattern(&[]).map(|p| p.to_string()), None);
    }

    #[test]
    fn test_calculate_keyword_pattern() {
        assert_eq!(
            calculate_keyword_pattern("test", &['-', '_']).to_string(),
            "(?-u:\\b)t[\\-_]*e[\\-_]*s[\\-_]*t(?-u:\\b)".to_string()
        );
        assert_eq!(
            calculate_keyword_pattern("test", &[]).to_string(),
            "(?-u:\\b)test(?-u:\\b)".to_string()
        );
    }
}
