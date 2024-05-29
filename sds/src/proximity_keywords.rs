use crate::proximity_keywords::ProximityKeywordsValidationError::{
    EmptyKeyword, InvalidLookAheadCharacterCount, KeywordTooLong, TooManyKeywords,
};
use crate::rule::ProximityKeywordsConfig;
use crate::Labels;
use metrics::{counter, Counter};
use regex_automata::{meta, Input};
use regex_syntax::ast::{
    Alternation, Assertion, AssertionKind, Ast, Concat, Flag, Flags, FlagsItem, FlagsItemKind,
    Group, GroupKind, Literal, LiteralKind, Position, Span,
};
use thiserror::Error;

const MAX_KEYWORD_COUNT: usize = 50;
const MAX_LOOK_AHEAD_CHARACTER_COUNT: usize = 50;

pub const TYPE: &str = "type";

/// Internal representation of included keywords after it has been validated / compiled.
#[derive(Default)]
pub struct CompiledProximityKeywords {
    look_ahead_character_count: usize,
    included_keywords_pattern: Option<ProximityKeywordsRegex<false>>,
    excluded_keywords_pattern: Option<ProximityKeywordsRegex<true>>,
    metrics: Metrics,
}

/// Characters we strip inside for excluded keywords in order to remove some noise
/// If this list contains more than a couple chars, some optimizations may be needed below
const EXCLUDED_KEYWORDS_REMOVED_CHARS: &[char] = &['-', '_'];

/// Characters that are considered to be links between keyword words.
/// Example: '-' in "aws-access" is considered to be a link character.
/// Example: '.' in "my.path" is considered to be a link character.
pub const MULTI_WORD_KEYWORDS_LINK_CHARS: &[char] = &['-', '_', '.', ' ', '/'];

pub const UNIFIED_LINK_CHAR: char = '.';

struct ProximityKeywordsRegex<const EXCLUDED_CHARS: bool> {
    content_regex: meta::Regex,
    path_regex: meta::Regex,
}

impl CompiledProximityKeywords {
    pub fn is_false_positive_match(
        &self,
        content: &str,
        sanitized_path: Option<String>,
        match_start: usize,
    ) -> bool {
        match (
            &self.included_keywords_pattern,
            &self.excluded_keywords_pattern,
        ) {
            (Some(included_keywords), _) => {
                if let Some(sanitized_path) = sanitized_path {
                    let is_valid_from_path =
                        self.contains_keyword_in_path(&sanitized_path, included_keywords);

                    if is_valid_from_path {
                        return false;
                    }
                }

                let is_false_positive_from_content = !self.contains_keyword_match(
                    content,
                    match_start,
                    self.look_ahead_character_count,
                    included_keywords,
                );

                if is_false_positive_from_content {
                    self.metrics.false_positive_included_keywords.increment(1);
                }
                is_false_positive_from_content
            }
            (None, Some(excluded_keywords)) => {
                let is_false_positive = self.contains_keyword_match(
                    content,
                    match_start,
                    self.look_ahead_character_count,
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
        let included_patterns = compile_keywords(
            config.included_keywords,
            config.look_ahead_character_count,
            &[],
        )?
        .map(|(content_regex, path_regex)| ProximityKeywordsRegex {
            content_regex,
            path_regex,
        });

        let excluded_patterns = compile_keywords(
            config.excluded_keywords,
            config.look_ahead_character_count,
            EXCLUDED_KEYWORDS_REMOVED_CHARS,
        )?
        .map(|(content_regex, path_regex)| ProximityKeywordsRegex {
            content_regex,
            path_regex,
        });

        Ok(CompiledProximityKeywords {
            look_ahead_character_count: config.look_ahead_character_count,
            included_keywords_pattern: included_patterns,
            excluded_keywords_pattern: excluded_patterns,
            metrics: Metrics::new(labels),
        })
    }

    fn contains_keyword_in_path(&self, path: &str, regex: &ProximityKeywordsRegex<false>) -> bool {
        let input = Input::new(path).earliest(true);

        regex.path_regex.search_half(&input).is_some()
    }

    /// Returns the match context which is what is searched for keywords
    /// and the range where matches are searched for. The range is needed since the context is
    /// expanded to ensure regex assertions (e.g. word boundaries) work correctly.
    fn contains_keyword_match<const EXCLUDED_CHARS: bool>(
        &self,
        content: &str,
        match_start: usize,
        look_ahead_char_count: usize,
        regex: &ProximityKeywordsRegex<EXCLUDED_CHARS>,
    ) -> bool {
        if EXCLUDED_CHARS {
            let prefix_start_info = get_prefix_start(
                match_start,
                // Adding 1 to the start to account for assertion checking
                look_ahead_char_count + 1,
                content,
            );

            // Adding 1 char here to allow correct assertion checking on the last char. There will always be
            // at least 1 more char is always available since empty matches aren't allowed
            let prefix_end = next_char_index(content, match_start).unwrap_or(content.len());

            let stripped_prefix = content[prefix_start_info.start..prefix_end]
                .replace(EXCLUDED_KEYWORDS_REMOVED_CHARS, "");

            // Subtracting one to exclude the last char which was added only for boundary checking
            let span_end = prev_char_index(&stripped_prefix, stripped_prefix.len()).unwrap_or(0);

            let span_start = if prefix_start_info.used_all_chars {
                // an extra char was added for assertion checking, so it needs to be removed here
                next_char_index(&stripped_prefix, 0).unwrap_or(stripped_prefix.len())
            } else {
                0
            };

            let input = Input::new(&stripped_prefix)
                .earliest(true)
                .span(span_start..span_end);
            regex.content_regex.search_half(&input).is_some()
        } else {
            // just get the previous n chars (no chars are skipped)
            let prefix_start_info = get_prefix_start(match_start, look_ahead_char_count, content);

            let prefix_end = match_start;

            let input = Input::new(content)
                .earliest(true)
                .span(prefix_start_info.start..prefix_end);
            regex.content_regex.search_half(&input).is_some()
        }
    }
}

fn next_char_index(content: &str, start: usize) -> Option<usize> {
    content[start..]
        .char_indices()
        .nth(1)
        .map(|(i, _c)| start + i)
}

fn prev_char_index(content: &str, start: usize) -> Option<usize> {
    content[..start].char_indices().next_back().map(|(i, _c)| i)
}

struct PrefixStart {
    start: usize,
    // A boolean indicating if all of the chars requested were available for the prefix
    used_all_chars: bool,
}

fn get_prefix_start(
    match_start: usize,
    look_ahead_char_count: usize,
    content: &str,
) -> PrefixStart {
    let prefix = &content[0..match_start];
    let mut char_indices = prefix.char_indices();

    match char_indices.nth_back(look_ahead_char_count - 1) {
        Some((i, _)) => PrefixStart {
            start: i,
            used_all_chars: true,
        },
        None => PrefixStart {
            start: 0,
            used_all_chars: false,
        },
    }
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
                labels.clone_with_labels(Labels::new(&[(TYPE, "included_keywords".to_string())]))
            ),
            false_positive_excluded_keywords: counter!(
                "false_positive.proximity_keywords",
                labels.clone_with_labels(Labels::new(&[(TYPE, "excluded_keywords".to_string())]))
            ),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics::new(&Labels::empty())
    }
}

fn compile_keywords_to_ast(
    keywords: &[String],
    look_ahead_character_count: usize,
    remove_chars: &[char],
) -> Result<Option<(Ast, Ast)>, ProximityKeywordsValidationError> {
    if keywords.is_empty() {
        return Ok(None);
    }

    let (content_patterns, path_patterns) = keywords
        .iter()
        .map(|keyword| {
            if keyword.chars().count() > look_ahead_character_count {
                return Err(KeywordTooLong(look_ahead_character_count));
            }

            let trimmed_keyword = keyword.trim().replace(remove_chars, "");
            if trimmed_keyword.is_empty() {
                return Err(EmptyKeyword);
            }
            Ok((
                calculate_keyword_content_pattern(&trimmed_keyword),
                calculate_keyword_path_pattern(&trimmed_keyword),
            ))
        })
        .collect::<Result<Vec<_>, _>>()?
        .iter()
        .cloned()
        .unzip();

    let content_pattern = Ast::Alternation(Alternation {
        span: span(),
        asts: content_patterns,
    });

    let path_pattern = Ast::Alternation(Alternation {
        span: span(),
        asts: path_patterns,
    });

    Ok(Some((content_pattern, path_pattern)))
}

fn compile_keywords(
    keywords: Vec<String>,
    look_ahead_character_count: usize,
    remove_chars: &[char],
) -> Result<Option<(meta::Regex, meta::Regex)>, ProximityKeywordsValidationError> {
    let (content_pattern, path_pattern) =
        match compile_keywords_to_ast(&keywords, look_ahead_character_count, remove_chars) {
            Ok(Some((content_ast, path_ast))) => (content_ast.to_string(), path_ast.to_string()),
            Ok(None) => return Ok(None),
            Err(e) => return Err(e),
        };

    let mut builder = meta::Regex::builder();
    let regex_builder = builder
        .configure(
            meta::Config::new()
                .nfa_size_limit(None)
                // This is the default that `Regex` uses
                .hybrid_cache_capacity(2 * (1 << 20)),
        )
        .syntax(regex_automata::util::syntax::Config::default().case_insensitive(true));

    Ok(Some((
        regex_builder.build(&content_pattern).unwrap(),
        regex_builder.build(&path_pattern).unwrap(),
    )))
}

fn should_push_word_boundary(c: char) -> bool {
    c.is_ascii_alphabetic() || c.is_ascii_digit()
}

/// Transform a keyword in an AST, the keyword MUST NOT be empty
fn calculate_keyword_content_pattern(keyword: &str) -> Ast {
    let mut keyword_pattern: Vec<Ast> = vec![];
    if should_push_word_boundary(keyword.chars().next().unwrap()) {
        keyword_pattern.push(word_boundary())
    }

    for c in keyword.chars() {
        keyword_pattern.push(Ast::Literal(literal_ast(c)))
    }

    if should_push_word_boundary(keyword.chars().next_back().unwrap()) {
        keyword_pattern.push(word_boundary())
    }
    Ast::Concat(Concat {
        span: span(),
        asts: keyword_pattern,
    })
}

#[derive(Clone, Copy)]
enum CharType {
    Regular,
    Uppercase,
    Separator,
}

fn get_char_type(c: &char) -> CharType {
    let is_link_symbol = MULTI_WORD_KEYWORDS_LINK_CHARS.contains(c);
    let is_uppercase_char = c.is_ascii_uppercase();

    if is_link_symbol {
        CharType::Separator
    } else if is_uppercase_char {
        CharType::Uppercase
    } else {
        CharType::Regular
    }
}

/// Function that standardizes a list of characters, by pushing characters one by one in a standard way.
/// Takes a closure that will be called when a character is to be pushed
pub fn standardize_path_chars<F>(chars: Vec<char>, mut push_character: F)
where
    F: FnMut(&char),
{
    let kw_length = chars.len();

    if chars.is_empty() {
        return;
    }

    push_character(&chars[0]);

    for (i, chars) in chars.windows(2).enumerate() {
        let current = &chars[1];
        let prev_char = get_char_type(&chars[0]);
        let current_char = get_char_type(current);

        let is_last_char = i == kw_length - 2;

        match (is_last_char, prev_char, current_char) {
            // The last character is simply pushed
            (true, _, _) => {
                push_character(current);
            }
            // Regular character is simply pushed
            (_, _, CharType::Regular) => {
                push_character(current);
            }
            // Character coming after a separator is pushed
            (_, CharType::Separator, _) => {
                push_character(current);
            }
            // Uppercase after an uppercase is pushed
            (_, CharType::Uppercase, CharType::Uppercase) => {
                push_character(current);
            }
            (_, CharType::Regular, CharType::Uppercase) => {
                push_character(&UNIFIED_LINK_CHAR);
                // CamelCase: push a link character and push the current character
                push_character(current);
            }
            // Regular separation in the keyword: push a link character only
            (_, _, CharType::Separator) => {
                push_character(&UNIFIED_LINK_CHAR);
            }
        }
    }
}

/// Transform a keyword in an AST for the path pattern, the keyword MUST NOT be empty
fn calculate_keyword_path_pattern(keyword: &str) -> Ast {
    let mut keyword_pattern: Vec<Ast> = vec![];

    if should_push_word_boundary(keyword.chars().next().unwrap()) {
        keyword_pattern.push(word_boundary())
    }

    let char_list: Vec<char> = keyword.chars().collect();

    standardize_path_chars(char_list, |c| {
        keyword_pattern.push(Ast::Literal(literal_ast(c.to_ascii_lowercase())));
    });

    if should_push_word_boundary(keyword.chars().next_back().unwrap()) {
        keyword_pattern.push(word_boundary())
    }

    Ast::Concat(Concat {
        span: span(),
        asts: keyword_pattern,
    })
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

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ProximityKeywordsValidationError {
    #[error("No more than {} keywords are allowed", MAX_KEYWORD_COUNT)]
    TooManyKeywords,

    #[error("Empty keywords are not allowed")]
    EmptyKeyword,

    #[error("Keywords cannot be longer than the look ahead character count ({0})")]
    KeywordTooLong(usize),

    #[error(
        "Look ahead character count should be bigger than 0 and cannot be longer than {}",
        MAX_LOOK_AHEAD_CHARACTER_COUNT
    )]
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
            &Labels::empty(),
        )
    }

    #[test]
    fn test_empty_keyword() {
        let proximity_keywords = try_new_compiled_proximity_keyword(30, vec![], vec![]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("hello world", None, 6));
    }

    #[test]
    fn test_included_keyword_content() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["hello".to_string()], vec![]).unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", None, 6));
        assert!(!proximity_keywords.is_false_positive_match("hey, hello world", None, 11));

        assert!(proximity_keywords.is_false_positive_match("world ", None, 5));
        assert!(proximity_keywords.is_false_positive_match("world", None, 0));

        assert!(proximity_keywords.is_false_positive_match("hello world", None, 3));
    }

    #[test]
    fn test_included_keyword_path() {
        let proximity_keywords = try_new_compiled_proximity_keyword(
            30,
            vec![
                "aws_access_key_id".to_string(),
                "aws-access".to_string(),
                "accessKey".to_string(),
            ],
            vec![],
        )
        .unwrap();

        // Should match
        assert_eq!(
            proximity_keywords.is_false_positive_match(
                "",
                Some("aws.access.key.id".to_string()),
                0
            ),
            false
        );
        assert_eq!(
            proximity_keywords.is_false_positive_match("", Some("aws.access.key".to_string()), 0),
            false
        );
        assert_eq!(
            proximity_keywords.is_false_positive_match("", Some("aws.access.keys".to_string()), 0),
            false
        );
        assert_eq!(
            proximity_keywords.is_false_positive_match("", Some("aws.access%key".to_string()), 0),
            false
        );
        assert_eq!(
            proximity_keywords.is_false_positive_match(
                "",
                Some("aws.access.key.identity".to_string()),
                0
            ),
            false
        );
        assert_eq!(
            proximity_keywords.is_false_positive_match(
                "",
                Some("access.key.aws.another.long.keyword".to_string()),
                0,
            ),
            false
        );

        // Should not match
        assert_eq!(
            proximity_keywords.is_false_positive_match("", Some("aws.key".to_string()), 0),
            true
        );
        assert_eq!(
            proximity_keywords.is_false_positive_match("", Some("key".to_string()), 0),
            true
        );
        assert_eq!(
            proximity_keywords.is_false_positive_match("", Some("aws.app.key".to_string()), 0),
            true
        );
        assert_eq!(
            proximity_keywords.is_false_positive_match("", Some("aws.accessible".to_string()), 0),
            true
        );
        assert_eq!(
            proximity_keywords.is_false_positive_match("", Some("access#key".to_string()), 0),
            true
        );
        assert_eq!(
            proximity_keywords.is_false_positive_match("", Some("key.access.aws".to_string()), 0),
            true
        );
    }

    #[test]
    fn test_excluded_keyword() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["hello".to_string()]).unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", None, 6));
        assert!(proximity_keywords.is_false_positive_match("hey, hello world", None, 11));

        assert!(!proximity_keywords.is_false_positive_match("world ", None, 5));
        assert!(!proximity_keywords.is_false_positive_match("world", None, 0));

        assert!(!proximity_keywords.is_false_positive_match("hello world", None, 3));
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
        assert!(!proximity_keywords.is_false_positive_match("hey world", None, 6));
        // only the excluded keyword is present
        assert!(proximity_keywords.is_false_positive_match("hello world", None, 6));
        // no keyword is present
        assert!(proximity_keywords.is_false_positive_match("world", None, 5));
        // included and excluded keywords are present
        assert!(!proximity_keywords.is_false_positive_match("hey, hello world", None, 11));
    }

    #[test]
    fn should_detect_on_any_keyword() {
        let proximity_keywords = try_new_compiled_proximity_keyword(
            30,
            vec!["hello".to_string(), "coty".to_string()],
            vec![],
        )
        .unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", None, 6));
        assert!(!proximity_keywords.is_false_positive_match("hey coty, hello world", None, 16));

        assert!(proximity_keywords.is_false_positive_match("hey hey hey world", None, 12));

        let proximity_keywords = try_new_compiled_proximity_keyword(
            30,
            vec![],
            vec!["hello".to_string(), "coty".to_string()],
        )
        .unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", None, 6));
        assert!(proximity_keywords.is_false_positive_match("hey coty, hello world", None, 16));

        assert!(!proximity_keywords.is_false_positive_match("hey hey hey world", None, 12));
    }

    #[test]
    fn should_quote_keyword() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["he.*o".to_string()], vec![]).unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", None, 6));
        assert!(!proximity_keywords.is_false_positive_match("he.*o world", None, 6));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["he.*o".to_string()]).unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", None, 6));
        assert!(proximity_keywords.is_false_positive_match("he.*o world", None, 6));
    }

    #[test]
    fn keywords_should_be_case_insensitive() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["hello".to_string()], vec![]).unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", None, 6));
        assert!(!proximity_keywords.is_false_positive_match("HELLO world", None, 6));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["hello".to_string()]).unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", None, 6));
        assert!(proximity_keywords.is_false_positive_match("HELLO world", None, 6));
    }

    #[test]
    fn included_keyword_should_have_word_boundaries() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["host".to_string()], vec![]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("host ping", None, 5));
        assert!(proximity_keywords.is_false_positive_match("localhost ping", None, 10));
        assert!(proximity_keywords.is_false_positive_match("hostlocal ping", None, 10));

        // word boundaries are is added at the beginning (resp. end) only if the first (resp. last) character is a letter or a digit
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["-host".to_string()], vec![]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("-host- ping", None, 6));
        assert!(!proximity_keywords.is_false_positive_match("local-host ping", None, 11));
        assert!(proximity_keywords.is_false_positive_match("-hostlocal ping", None, 11));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["ৎhost".to_string()], vec![]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("ৎhost ping", None, 7));
        assert!(!proximity_keywords.is_false_positive_match("localৎhost ping", None, 12));
    }

    #[test]
    fn excluded_keyword_should_have_word_boundaries() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["host".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("host ping", None, 5));
        assert!(!proximity_keywords.is_false_positive_match("localhost ping", None, 10));
        assert!(!proximity_keywords.is_false_positive_match("hostlocal ping", None, 10));

        // word boundaries are is added at the beginning (resp. end) only if the first (resp. last) character is a letter or a digit
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["!host".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("!host- ping", None, 6));
        assert!(proximity_keywords.is_false_positive_match("local!host ping", None, 11));
        assert!(!proximity_keywords.is_false_positive_match("!hostlocal ping", None, 11));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["ৎhost".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("ৎhost ping", None, 7));
        assert!(proximity_keywords.is_false_positive_match("localৎhost ping", None, 12));
    }

    #[test]
    fn should_remove_excluded_keywords_removed_chars_in_excluded_keywords_and_prefix() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["span-id".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("span-id ping", None, 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", None, 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", None, 8));
        assert!(!proximity_keywords.is_false_positive_match("span id ping", None, 8));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["span_id".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("span-id ping", None, 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", None, 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", None, 8));
        assert!(!proximity_keywords.is_false_positive_match("span id ping", None, 8));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec![], vec!["spanid".to_string()]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("span-id ping", None, 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", None, 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", None, 8));
        assert!(!proximity_keywords.is_false_positive_match("span id ping", None, 8));

        // nothing is changed on included keywords
        let proximity_keywords =
            try_new_compiled_proximity_keyword(30, vec!["span-id".to_string()], vec![]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("span-id ping", None, 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", None, 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", None, 8));
    }

    #[test]
    fn should_look_ahead_too_far() {
        let proximity_keywords =
            try_new_compiled_proximity_keyword(10, vec!["host".to_string()], vec![]).unwrap();
        assert!(proximity_keywords.is_false_positive_match("host 56789012345", None, 15));
        assert!(!proximity_keywords.is_false_positive_match("host 56789012345", None, 10));
        // prefix `ost 567890` does not contains host
        assert!(proximity_keywords.is_false_positive_match("host 56789012345", None, 11));
        assert!(!proximity_keywords.is_false_positive_match(" host 6789012345", None, 11));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(10, vec![], vec!["host".to_string()]).unwrap();
        assert!(!proximity_keywords.is_false_positive_match("host 56789012345", None, 15));
        assert!(proximity_keywords.is_false_positive_match("host 56789012345", None, 10));
        // prefix `ost 567890` does not contains host
        assert!(!proximity_keywords.is_false_positive_match("host 56789012345", None, 11));
        assert!(proximity_keywords.is_false_positive_match(" host 6789012345", None, 11));
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
        assert_eq!(proximity_keywords.err().unwrap(), KeywordTooLong(5));

        let proximity_keywords =
            try_new_compiled_proximity_keyword(5, vec![], vec!["hello".to_string()]);
        assert!(proximity_keywords.is_ok());

        let proximity_keywords =
            try_new_compiled_proximity_keyword(5, vec![], vec!["hello1".to_string()]);
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), KeywordTooLong(5));
    }

    #[test]
    fn test_included_keywords_on_start_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec!["id".to_string()], vec![]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("invalid   abc", None, 10);

        assert_eq!(is_false_positive, true);
    }

    #[test]
    fn test_included_keywords_on_end_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec!["id".to_string()], vec![]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("foo idabc", None, 6);

        assert_eq!(is_false_positive, true);
    }

    #[test]
    fn test_included_keywords_on_start_boundary_with_space() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec!["id".to_string()], vec![]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("users id   ab", None, 11);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_excluded_keyword_strip_chars_do_count_towards_look_ahead_count() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();

        // "id" only fits in the match prefix (5 chars) if the "-" char isn't counted towards the 5 chars
        let is_false_positive = keywords.is_false_positive_match("users i-d   ab", None, 12);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_excluded_keyword_stripped_chars_in_word_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(8, vec![], vec!["id".to_string()]).unwrap();

        // The entire string is in the prefix, but "-" is stripped, so "userid" don't match "id" due to the word boundary
        let is_false_positive = keywords.is_false_positive_match("user-id ab", None, 8);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_included_keywords_on_start_boundary_with_space_including_word_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(7, vec!["id".to_string()], vec![]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("users id   ab", None, 11);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_excluded_keywords_on_start_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("invalid   abc", None, 10);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_excluded_keywords_on_end_boundary() {
        let keywords =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();

        let is_false_positive = keywords.is_false_positive_match("foo idabc", None, 6);
        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_compile_keywords() {
        let (content_regex, path_regex) =
            compile_keywords(vec!["hello".to_string(), "awsAccess".to_string()], 20, &[])
                .unwrap()
                .unwrap();
        assert_eq!(content_regex.is_match("hello"), true);
        assert_eq!(content_regex.is_match("he-l_lo"), false);
        assert_eq!(
            content_regex.search(&Input::new("I want to say hello to my dear friend")),
            Some(regex_automata::Match::must(0, 14..19))
        );

        assert_eq!(path_regex.is_match("awsAccess"), false);
        assert_eq!(path_regex.is_match("aws.access"), true);
        assert_eq!(path_regex.is_match("aws.accessible"), false);
        assert_eq!(
            path_regex.search(&Input::new("my.path.to.aws.access")),
            Some(regex_automata::Match::must(0, 11..21))
        );
    }

    #[test]
    fn test_compile_keywords_pattern() {
        let (content_pattern, path_pattern) = match compile_keywords_to_ast(
            &&vec![
                "hello".to_string(),
                "world*".to_string(),
                "_aws".to_string(),
                "aws-access".to_string(),
            ],
            10,
            &[],
        ) {
            Ok(Some((content_ast, path_ast))) => (content_ast.to_string(), path_ast.to_string()),
            _ => ("".to_string(), "".to_string()),
        };

        assert_eq!(content_pattern, "(?-u:\\b)hello(?-u:\\b)|(?-u:\\b)world\\*|_aws(?-u:\\b)|(?-u:\\b)aws\\-access(?-u:\\b)");
        assert_eq!(path_pattern, "(?-u:\\b)hello(?-u:\\b)|(?-u:\\b)world\\*|_aws(?-u:\\b)|(?-u:\\b)aws\\.access(?-u:\\b)");
    }

    #[test]
    fn test_calculate_keyword_pattern() {
        assert_eq!(
            calculate_keyword_content_pattern("test").to_string(),
            "(?-u:\\b)test(?-u:\\b)".to_string()
        );
    }

    #[test]
    fn test_calculate_multi_word_keyword_pattern() {
        assert_eq!(
            calculate_keyword_content_pattern("multi word-KEYWORD").to_string(),
            "(?-u:\\b)multi word\\-KEYWORD(?-u:\\b)"
        )
    }

    #[test]
    fn test_calculate_path_pattern_on_simple_keyword() {
        assert_eq!(
            calculate_keyword_path_pattern("test").to_string(),
            "(?-u:\\b)test(?-u:\\b)".to_string()
        )
    }

    #[test]
    fn test_calculate_path_pattern_on_multi_word_keyword() {
        assert_eq!(
            calculate_keyword_path_pattern("test hello world").to_string(),
            "(?-u:\\b)test\\.hello\\.world(?-u:\\b)".to_string()
        );

        assert_eq!(
            calculate_keyword_path_pattern("test helloWorld").to_string(),
            "(?-u:\\b)test\\.hello\\.world(?-u:\\b)".to_string()
        );

        assert_eq!(
            calculate_keyword_path_pattern("awsAccess-key-id").to_string(),
            "(?-u:\\b)aws\\.access\\.key\\.id(?-u:\\b)".to_string()
        );

        assert_eq!(
            calculate_keyword_path_pattern("AWS_KEY_ID").to_string(),
            "(?-u:\\b)aws\\.key\\.id(?-u:\\b)".to_string()
        );

        assert_eq!(
            calculate_keyword_path_pattern("_AWS_KEY_ID_").to_string(),
            "_aws\\.key\\.id_".to_string()
        );

        assert_eq!(
            calculate_keyword_path_pattern("AwsAccessKeyID").to_string(),
            "(?-u:\\b)aws\\.access\\.key\\.id(?-u:\\b)".to_string()
        );

        assert_eq!(
            calculate_keyword_path_pattern("AWSACCESSKEYID").to_string(),
            "(?-u:\\b)awsaccesskeyid(?-u:\\b)".to_string()
        );

        assert_eq!(
            calculate_keyword_path_pattern("aLotOfCamelCaSe").to_string(),
            "(?-u:\\b)a\\.lot\\.of\\.camel\\.ca\\.se(?-u:\\b)".to_string()
        );

        assert_eq!(
            calculate_keyword_path_pattern("testThis-with_different/separators").to_string(),
            "(?-u:\\b)test\\.this\\.with\\.different\\.separators(?-u:\\b)".to_string()
        );

        assert_eq!(
            calculate_keyword_path_pattern("edge--case_/a. bit...annoying").to_string(),
            "(?-u:\\b)edge\\.\\-case\\./a\\. bit\\.\\.\\.annoying(?-u:\\b)".to_string()
        );

        assert_eq!(
            calculate_keyword_path_pattern("lots--of___symbol/s").to_string(),
            "(?-u:\\b)lots\\.\\-of\\.__symbol\\.s(?-u:\\b)".to_string()
        );
    }

    #[test]
    fn test_next_char() {
        assert_eq!(next_char_index("", 0), None);
        assert_eq!(next_char_index("a€b", 0), Some(1));
        assert_eq!(next_char_index("a€b", 1), Some(4));
        assert_eq!(next_char_index("a€b", 4), None);
    }

    #[test]
    fn test_prev_char() {
        assert_eq!(prev_char_index("a€b", 5), Some(4));
        assert_eq!(prev_char_index("a€b", 4), Some(1));
        assert_eq!(prev_char_index("a€b", 1), Some(0));
        assert_eq!(prev_char_index("a€b", 0), None);
        assert_eq!(prev_char_index("", 0), None);
    }
}
