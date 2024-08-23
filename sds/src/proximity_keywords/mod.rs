mod excluded_keywords;
mod included_keywords;

pub use crate::proximity_keywords::excluded_keywords::CompiledExcludedProximityKeywords;
pub use crate::proximity_keywords::included_keywords::*;

use crate::proximity_keywords::ProximityKeywordsValidationError::{
    EmptyKeyword, InvalidLookAheadCharacterCount, KeywordTooLong, TooManyKeywords,
};
use crate::{Labels, ProximityKeywordsConfig};
use metrics::counter;
use regex_automata::{meta, Input};
use regex_syntax::ast::{
    Alternation, Assertion, AssertionKind, Ast, Concat, Flag, Flags, FlagsItem, FlagsItemKind,
    Group, GroupKind, Literal, LiteralKind, Position, Span,
};
use thiserror::Error;

const MAX_KEYWORD_COUNT: usize = 50;
pub const MAX_LOOK_AHEAD_CHARACTER_COUNT: usize = 50;
pub const TYPE: &str = "type";

/// Characters we strip inside for excluded keywords in order to remove some noise
/// If this list contains more than a couple chars, some optimizations may be needed below
const EXCLUDED_KEYWORDS_REMOVED_CHARS: &[char] = &['-', '_'];

#[derive(Debug)]
pub struct ProximityKeywordsRegex {
    pub content_regex: meta::Regex,
    pub path_regex: meta::Regex,
}

/// Characters that are considered to be links between keyword words.
/// Example: '-' in "aws-access" is considered to be a link character.
/// Example: '.' in "my.path" is considered to be a link character.
pub const MULTI_WORD_KEYWORDS_LINK_CHARS: &[char] = &['-', '_', '.', ' ', '/'];

pub const UNIFIED_LINK_CHAR: char = '.';
pub const UNIFIED_LINK_STR: &str = ".";

pub fn compile_keywords_proximity_config(
    config: &ProximityKeywordsConfig,
    labels: &Labels,
) -> Result<
    (
        Option<CompiledIncludedProximityKeywords>,
        Option<CompiledExcludedProximityKeywords>,
    ),
    ProximityKeywordsValidationError,
> {
    if config.look_ahead_character_count == 0
        || config.look_ahead_character_count > MAX_LOOK_AHEAD_CHARACTER_COUNT
    {
        return Err(InvalidLookAheadCharacterCount);
    }

    let mut included_keywords = None;
    let mut excluded_keywords = None;

    if config.included_keywords.len() > MAX_KEYWORD_COUNT
        || config.excluded_keywords.len() > MAX_KEYWORD_COUNT
    {
        return Err(TooManyKeywords);
    }

    if let Some((content_regex, path_regex)) = compile_keywords(
        config.included_keywords.clone(),
        config.look_ahead_character_count,
        &[],
    )? {
        included_keywords = Some(CompiledIncludedProximityKeywords {
            look_ahead_character_count: config.look_ahead_character_count,
            keywords_pattern: ProximityKeywordsRegex {
                content_regex,
                path_regex,
            },
        });
    }

    if let Some((content_regex, path_regex)) = compile_keywords(
        config.excluded_keywords.clone(),
        config.look_ahead_character_count,
        EXCLUDED_KEYWORDS_REMOVED_CHARS,
    )? {
        excluded_keywords = Some(CompiledExcludedProximityKeywords {
            look_ahead_character_count: config.look_ahead_character_count,
            keywords_pattern: ProximityKeywordsRegex {
                content_regex,
                path_regex,
            },
            false_positive_counter: counter!(
                "false_positive.proximity_keywords",
                labels.clone_with_labels(Labels::new(&[(TYPE, "excluded_keywords".to_string())]))
            ),
        });
    }

    Ok((included_keywords, excluded_keywords))
}

pub fn contains_keyword_in_path(path: &str, regex: &ProximityKeywordsRegex) -> bool {
    let input = Input::new(path).earliest(true);
    regex.path_regex.search_half(&input).is_some()
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

pub struct PrefixStart {
    pub start: usize,
    // A boolean indicating if all of the chars requested were available for the prefix
    pub used_all_chars: bool,
}

pub fn is_index_within_prefix(
    content: &str,
    prefix_start: usize,
    target: usize,
    prefix_size: usize,
) -> bool {
    debug_assert!(target > prefix_start);
    debug_assert!(content.is_char_boundary(prefix_start));
    debug_assert!(content.is_char_boundary(target));

    // A unicode char can't be less than 1 byte, so do a quick check assuming 1 byte per char
    if prefix_start + prefix_size > target {
        return true;
    }

    // Slower method that works with unicode chars
    content[prefix_start..]
        .char_indices()
        .nth(prefix_size)
        .map_or(true, |(i, _)| prefix_start + i >= target)
}

pub fn get_prefix_start(
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

#[derive(Debug, PartialEq)]
pub enum BypassStandardizePathResult {
    BypassAndAllLowercase,
    BypassAndAllUppercase,
    NoBypass,
}

pub fn should_bypass_standardize_path(characters: &str) -> BypassStandardizePathResult {
    let mut all_lower = true;
    let mut all_upper = true;
    for char in characters.chars() {
        let is_upper = char.is_ascii_uppercase();
        let is_lower = char.is_ascii_lowercase();
        // If it's neither an uppercase character nor a lowercase character, return false
        if !is_lower && !is_upper {
            return BypassStandardizePathResult::NoBypass;
        }
        all_lower = all_lower && is_lower;
        all_upper = all_upper && is_upper;
        // If we realise that we don't have all uppercase nor all lowercase, return false
        if !all_lower && !all_upper {
            return BypassStandardizePathResult::NoBypass;
        }
    }

    // The characters contain only uppercase characters or only lowercase characters by now
    if all_lower {
        BypassStandardizePathResult::BypassAndAllLowercase
    } else {
        BypassStandardizePathResult::BypassAndAllUppercase
    }
}

/// Function that standardizes a list of characters, by pushing characters one by one in a standard way.
/// Takes a closure that will be called when a character is to be pushed
pub fn standardize_path_chars<F>(characters: &str, mut push_character: F)
where
    F: FnMut(&char),
{
    let mut characters_iter = characters.chars();
    let char = if let Some(char) = characters_iter.next() {
        push_character(&char);
        char
    } else {
        return;
    };

    let kw_length = characters.len();

    let mut previous = char;
    for (i, current) in characters_iter.enumerate() {
        let is_last_char = i == kw_length - 2;

        let prev_char = get_char_type(&previous);
        let current_char = get_char_type(&current);

        match (is_last_char, prev_char, current_char) {
            // The last character is simply pushed
            (true, _, _) => {
                push_character(&current);
            }
            // Regular character is simply pushed
            (_, _, CharType::Regular) => {
                push_character(&current);
            }
            // Character coming after a separator is pushed
            (_, CharType::Separator, _) => {
                push_character(&current);
            }
            // Uppercase after an uppercase is pushed
            (_, CharType::Uppercase, CharType::Uppercase) => {
                push_character(&current);
            }
            (_, CharType::Regular, CharType::Uppercase) => {
                push_character(&UNIFIED_LINK_CHAR);
                // CamelCase: push a link character and push the current character
                push_character(&current);
            }
            // Regular separation in the keyword: push a link character only
            (_, _, CharType::Separator) => {
                push_character(&UNIFIED_LINK_CHAR);
            }
        }

        previous = current;
    }
}

/// Transform a keyword in an AST for the path pattern, the keyword MUST NOT be empty
fn calculate_keyword_path_pattern(keyword: &str) -> Ast {
    let mut keyword_pattern: Vec<Ast> = vec![];

    if should_push_word_boundary(keyword.chars().next().unwrap()) {
        keyword_pattern.push(word_boundary())
    }

    standardize_path_chars(keyword, |c| {
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
    use crate::proximity_keywords::BypassStandardizePathResult::{
        BypassAndAllLowercase, BypassAndAllUppercase, NoBypass,
    };
    use crate::proximity_keywords::*;

    fn try_new_compiled_proximity_keyword(
        look_ahead_character_count: usize,
        included_keywords: Vec<String>,
        excluded_keywords: Vec<String>,
    ) -> Result<
        (
            Option<CompiledIncludedProximityKeywords>,
            Option<CompiledExcludedProximityKeywords>,
        ),
        ProximityKeywordsValidationError,
    > {
        compile_keywords_proximity_config(
            &ProximityKeywordsConfig {
                look_ahead_character_count,
                included_keywords,
                excluded_keywords,
            },
            &Labels::empty(),
        )
    }

    #[test]
    fn test_is_index_within_prefix_ascii() {
        let content = "abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(is_index_within_prefix(content, 0, 1, 10), true);
        assert_eq!(is_index_within_prefix(content, 0, 5, 10), true);
        assert_eq!(is_index_within_prefix(content, 0, 9, 10), true);
        assert_eq!(is_index_within_prefix(content, 0, 10, 10), true);
        assert_eq!(is_index_within_prefix(content, 0, 11, 10), false);

        assert_eq!(is_index_within_prefix(content, 5, 6, 10), true);
        assert_eq!(is_index_within_prefix(content, 5, 10, 10), true);
        assert_eq!(is_index_within_prefix(content, 5, 14, 10), true);
        assert_eq!(is_index_within_prefix(content, 5, 15, 10), true);
        assert_eq!(is_index_within_prefix(content, 5, 16, 10), false);
    }

    #[test]
    fn test_is_index_within_prefix_multi_byte_unicode() {
        // each char is 2 bytes
        let content = "éèéèéèéèéèéèéèéè";
        assert_eq!(is_index_within_prefix(content, 0, 2, 10), true);
        assert_eq!(is_index_within_prefix(content, 2, 6, 3), true);
        assert_eq!(is_index_within_prefix(content, 2, 6, 1), false);
    }

    #[test]
    fn test_empty_keyword() {
        let (included_keywords, excluded_keywords) =
            try_new_compiled_proximity_keyword(30, vec![], vec![]).unwrap();
        assert!(included_keywords.is_none());
        assert!(excluded_keywords.is_none());
    }

    #[test]
    fn test_excluded_keyword() {
        let (_included_keywords, excluded_keywords) =
            try_new_compiled_proximity_keyword(30, vec![], vec!["hello".to_string()]).unwrap();
        let excluded_keywords = excluded_keywords.unwrap();

        assert!(excluded_keywords.is_false_positive_match("hello world", 6));
        assert!(excluded_keywords.is_false_positive_match("hey, hello world", 11));

        assert!(!excluded_keywords.is_false_positive_match("world ", 5));
        assert!(!excluded_keywords.is_false_positive_match("world", 0));

        assert!(!excluded_keywords.is_false_positive_match("hello world", 3));
    }

    #[test]
    fn excluded_keyword_should_have_word_boundaries() {
        let (_included, excluded) =
            try_new_compiled_proximity_keyword(30, vec![], vec!["host".to_string()]).unwrap();
        let excluded = excluded.unwrap();

        assert!(excluded.is_false_positive_match("host ping", 5));
        assert!(!excluded.is_false_positive_match("localhost ping", 10));
        assert!(!excluded.is_false_positive_match("hostlocal ping", 10));

        // word boundaries are is added at the beginning (resp. end) only if the first (resp. last) character is a letter or a digit
        let (_included, excluded) =
            try_new_compiled_proximity_keyword(30, vec![], vec!["!host".to_string()]).unwrap();
        let excluded = excluded.unwrap();
        assert!(excluded.is_false_positive_match("!host- ping", 6));
        assert!(excluded.is_false_positive_match("local!host ping", 11));
        assert!(!excluded.is_false_positive_match("!hostlocal ping", 11));

        let (_included, excluded) =
            try_new_compiled_proximity_keyword(30, vec![], vec!["ৎhost".to_string()]).unwrap();
        let excluded = excluded.unwrap();
        assert!(excluded.is_false_positive_match("ৎhost ping", 7));
        assert!(excluded.is_false_positive_match("localৎhost ping", 12));
    }

    #[test]
    fn should_remove_excluded_keywords_removed_chars_in_excluded_keywords_and_prefix() {
        let (_included, excluded) =
            try_new_compiled_proximity_keyword(30, vec![], vec!["span-id".to_string()]).unwrap();
        let excluded = excluded.unwrap();
        assert!(excluded.is_false_positive_match("span-id ping", 8));
        assert!(excluded.is_false_positive_match("spanid ping", 7));
        assert!(excluded.is_false_positive_match("span_id ping", 8));
        assert!(!excluded.is_false_positive_match("span id ping", 8));

        let (_included, excluded) =
            try_new_compiled_proximity_keyword(30, vec![], vec!["span_id".to_string()]).unwrap();
        let excluded = excluded.unwrap();
        assert!(excluded.is_false_positive_match("span-id ping", 8));
        assert!(excluded.is_false_positive_match("spanid ping", 7));
        assert!(excluded.is_false_positive_match("span_id ping", 8));
        assert!(!excluded.is_false_positive_match("span id ping", 8));

        let (_included, excluded) =
            try_new_compiled_proximity_keyword(30, vec![], vec!["spanid".to_string()]).unwrap();
        let excluded = excluded.unwrap();
        assert!(excluded.is_false_positive_match("span-id ping", 8));
        assert!(excluded.is_false_positive_match("spanid ping", 7));
        assert!(excluded.is_false_positive_match("span_id ping", 8));
        assert!(!excluded.is_false_positive_match("span id ping", 8));
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
    fn test_excluded_keyword_strip_chars_do_count_towards_look_ahead_count() {
        let (_included, excluded) =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();
        let excluded = excluded.unwrap();
        // "id" only fits in the match prefix (5 chars) if the "-" char isn't counted towards the 5 chars
        let is_false_positive = excluded.is_false_positive_match("users i-d   ab", 12);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_excluded_keyword_stripped_chars_in_word_boundary() {
        let (_included, excluded) =
            try_new_compiled_proximity_keyword(8, vec![], vec!["id".to_string()]).unwrap();
        let excluded = excluded.unwrap();
        // The entire string is in the prefix, but "-" is stripped, so "userid" don't match "id" due to the word boundary
        let is_false_positive = excluded.is_false_positive_match("user-id ab", 8);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_excluded_keywords_on_start_boundary() {
        let (_included, excluded) =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();
        let excluded = excluded.unwrap();
        let is_false_positive = excluded.is_false_positive_match("invalid   abc", 10);

        assert_eq!(is_false_positive, false);
    }

    #[test]
    fn test_excluded_keywords_on_end_boundary() {
        let (_included, excluded) =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();

        let excluded = excluded.unwrap();
        let is_false_positive = excluded.is_false_positive_match("foo idabc", 6);
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
        );
        assert_eq!(
            calculate_keyword_path_pattern("t").to_string(),
            "(?-u:\\b)t(?-u:\\b)".to_string()
        );
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

    #[test]
    fn test_should_bypass_standardize() {
        assert_eq!(should_bypass_standardize_path("hello world"), NoBypass);
        assert_eq!(should_bypass_standardize_path("helloWorld"), NoBypass);
        assert_eq!(should_bypass_standardize_path("hello-world"), NoBypass);
        assert_eq!(
            should_bypass_standardize_path("helloworld"),
            BypassAndAllLowercase
        );
        assert_eq!(
            should_bypass_standardize_path("HELLOWORLD"),
            BypassAndAllUppercase
        );
    }

    #[test]
    fn test_included_keyword_path() {
        let (included_keywords, _excluded_keywords) = try_new_compiled_proximity_keyword(
            30,
            vec![
                "aws_access_key_id".to_string(),
                "aws-access".to_string(),
                "accessKey".to_string(),
            ],
            vec![],
        )
        .unwrap();
        let included_keywords = included_keywords.unwrap();

        let should_match = vec![
            "aws.access.key.id",
            "aws.access.key",
            "aws.access.keys",
            "aws.access%key",
            "aws.access.key.identity",
            "access.key.aws.another.long.keyword",
        ];

        // Should match
        for path in should_match {
            assert_eq!(
                contains_keyword_in_path(path, &included_keywords.keywords_pattern),
                true
            );
        }

        let should_not_match = vec![
            "aws.key",
            "key",
            "aws.app.key",
            "aws.accessible",
            "access#key",
            "key.access.aws",
        ];

        for path in should_not_match {
            assert_eq!(
                contains_keyword_in_path(path, &included_keywords.keywords_pattern),
                false
            );
        }
    }
}
