mod excluded_keywords;
mod included_keywords;

pub use crate::proximity_keywords::excluded_keywords::CompiledExcludedProximityKeywords;
pub use crate::proximity_keywords::included_keywords::*;

use crate::ast_utils::should_push_word_boundary;
use crate::proximity_keywords::ProximityKeywordsValidationError::{
    EmptyKeyword, InvalidLookAheadCharacterCount, KeywordTooLong, TooManyKeywords,
};
use crate::scanner::regex_rule::{SharedRegex, get_memoized_regex};
use crate::{Labels, ProximityKeywordsConfig};
use metrics::counter;
use regex_automata::{Input, meta};
use std::borrow::Cow;
use thiserror::Error;

const MAX_KEYWORD_COUNT: usize = 50;
pub const MAX_LOOK_AHEAD_CHARACTER_COUNT: usize = 50;
pub const TYPE: &str = "type";

/// Characters we strip inside for excluded keywords in order to remove some noise
/// If this list contains more than a couple chars, some optimizations may be needed below
const EXCLUDED_KEYWORDS_REMOVED_CHARS: &[char] = &['-', '_'];

#[derive(Debug, Clone)]
pub struct ProximityKeywordsRegex {
    pub content_regex: SharedRegex,
    pub path_regex: SharedRegex,
}

/// Characters that are considered to be links between keyword words.
/// Example: '-' in "aws-access" is considered to be a link character.
/// Example: '.' in "my.path" is considered to be a link character.
pub const MULTI_WORD_KEYWORDS_LINK_CHARS: &[char] = &['-', '_', '.', ' ', '/'];

/// Preformatted regex fragments matching the exact syntax previously generated via `regex_syntax::ast`.
/// Keeping the same strings preserves `REGEX_STORE` cache keys byte-for-byte without allocating ASTs.
const WORD_BOUNDARY_PATTERN: &str = "(?-u:\\b)";
const WORD_BOUNDARY_OR_LINK_CHAR_PATTERN: &str = "(?:(?-u:\\b)|(?:_))";
const LINK_CHAR_SEPARATOR_PATTERN: &str = "(?:\\-|_|\\.| |/)";
const OPTIONAL_LINK_CHAR_SEPARATOR_PATTERN: &str = "(?:\\-|_|\\.| |/)?";

pub const UNIFIED_LINK_CHAR: char = '.';
#[allow(dead_code)]
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
        &config.included_keywords,
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

    if let Some(content_regex) = compile_excluded_keywords(
        &config.excluded_keywords,
        config.look_ahead_character_count,
        EXCLUDED_KEYWORDS_REMOVED_CHARS,
    )? {
        excluded_keywords = Some(CompiledExcludedProximityKeywords {
            look_ahead_character_count: config.look_ahead_character_count,
            content_regex,
            false_positive_counter: counter!(
                "false_positive.proximity_keywords",
                labels.clone_with_labels(Labels::new(&[(TYPE, "excluded_keywords".to_string())]))
            ),
        });
    }

    Ok((included_keywords, excluded_keywords))
}

#[inline]
pub fn contains_keyword_in_path(
    path: &str,
    regex: &ProximityKeywordsRegex,
    cache: &mut meta::Cache,
) -> bool {
    let input = Input::new(path).earliest(true);
    regex.path_regex.search_half_with(cache, &input).is_some()
}

fn next_char_index(content: &str, start: usize) -> Option<usize> {
    content[start..]
        .char_indices()
        .nth(1)
        .map(|(i, _c)| start + i)
}

fn prev_char_with_index(content: &str, start: usize) -> Option<(usize, char)> {
    content[..start].char_indices().next_back()
}

pub struct PrefixStart {
    pub start: usize,
}

pub fn is_index_within_prefix(
    content: &str,
    keyword_start: usize,
    match_start: usize,
    prefix_size: usize,
) -> bool {
    debug_assert!(match_start > keyword_start);
    debug_assert!(content.is_char_boundary(keyword_start));
    debug_assert!(content.is_char_boundary(match_start));

    // A unicode char can't be less than 1 byte, so do a quick check assuming 1 byte per char
    if keyword_start + prefix_size > match_start {
        return true;
    }

    // Slower method that works with unicode chars
    content[keyword_start..]
        .char_indices()
        .nth(prefix_size)
        .is_none_or(|(i, _)| keyword_start + i >= match_start)
}

pub fn get_prefix_start(
    match_start: usize,
    look_ahead_char_count: usize,
    content: &str,
) -> PrefixStart {
    let prefix = &content[0..match_start];
    let mut char_indices = prefix.char_indices();

    match char_indices.nth_back(look_ahead_char_count - 1) {
        Some((i, _)) => PrefixStart { start: i },
        None => PrefixStart { start: 0 },
    }
}

#[inline]
fn push_escaped_literal(out: &mut String, c: char) {
    if regex_syntax::is_meta_character(c) {
        out.push('\\');
    }
    out.push(c);
}

fn trim_and_strip_keyword<'a>(keyword: &'a str, remove_chars: &[char]) -> Cow<'a, str> {
    let trimmed = keyword.trim();
    if remove_chars.is_empty() || !trimmed.contains(remove_chars) {
        Cow::Borrowed(trimmed)
    } else {
        Cow::Owned(trimmed.replace(remove_chars, ""))
    }
}

fn compile_keywords_to_patterns(
    keywords: &[String],
    look_ahead_character_count: usize,
    remove_chars: &[char],
    build_path_pattern: bool,
) -> Result<Option<(String, String)>, ProximityKeywordsValidationError> {
    if keywords.is_empty() {
        return Ok(None);
    }

    let total_kw_len: usize = keywords.iter().map(String::len).sum();
    let mut content_pattern = String::with_capacity(
        total_kw_len + keywords.len() * (WORD_BOUNDARY_OR_LINK_CHAR_PATTERN.len() * 2 + 1),
    );
    let mut path_pattern = if build_path_pattern {
        String::with_capacity(total_kw_len + keywords.len() * (WORD_BOUNDARY_PATTERN.len() * 2 + 1))
    } else {
        String::new()
    };

    for (i, keyword) in keywords.iter().enumerate() {
        if keyword.chars().count() > look_ahead_character_count {
            return Err(KeywordTooLong(look_ahead_character_count));
        }

        let trimmed_keyword = trim_and_strip_keyword(keyword, remove_chars);
        if trimmed_keyword.is_empty() {
            return Err(EmptyKeyword);
        }

        if i > 0 {
            content_pattern.push('|');
            if build_path_pattern {
                path_pattern.push('|');
            }
        }
        push_keyword_content_pattern(&trimmed_keyword, &mut content_pattern);
        if build_path_pattern {
            push_keyword_path_pattern(&trimmed_keyword, &mut path_pattern);
        }
    }

    Ok(Some((content_pattern, path_pattern)))
}

#[allow(clippy::result_large_err)]
fn build_keyword_regex(pattern: &str) -> Result<meta::Regex, meta::BuildError> {
    meta::Regex::builder()
        .configure(
            meta::Config::new()
                .nfa_size_limit(None)
                // This is the default that `Regex` uses
                .hybrid_cache_capacity(2 * (1 << 20)),
        )
        .syntax(regex_automata::util::syntax::Config::default().case_insensitive(true))
        .build(pattern)
}

fn compile_keywords(
    keywords: &[String],
    look_ahead_character_count: usize,
    remove_chars: &[char],
) -> Result<Option<(SharedRegex, SharedRegex)>, ProximityKeywordsValidationError> {
    let Some((content_pattern, path_pattern)) =
        compile_keywords_to_patterns(keywords, look_ahead_character_count, remove_chars, true)?
    else {
        return Ok(None);
    };

    Ok(Some((
        get_memoized_regex(&content_pattern, build_keyword_regex).unwrap(),
        get_memoized_regex(&path_pattern, build_keyword_regex).unwrap(),
    )))
}

fn compile_excluded_keywords(
    keywords: &[String],
    look_ahead_character_count: usize,
    remove_chars: &[char],
) -> Result<Option<SharedRegex>, ProximityKeywordsValidationError> {
    let Some((content_pattern, _)) =
        compile_keywords_to_patterns(keywords, look_ahead_character_count, remove_chars, false)?
    else {
        return Ok(None);
    };

    Ok(Some(
        get_memoized_regex(&content_pattern, build_keyword_regex).unwrap(),
    ))
}

/// Format a keyword directly into a regex pattern string; the keyword MUST NOT be empty.
fn push_keyword_content_pattern(keyword: &str, out: &mut String) {
    let mut chars = keyword.chars().peekable();
    let Some(first) = chars.peek().copied() else {
        return;
    };
    if should_push_word_boundary(first) {
        out.push_str(WORD_BOUNDARY_OR_LINK_CHAR_PATTERN);
    }

    let mut is_first = true;
    let mut last = first;
    while let Some(c) = chars.next() {
        last = c;
        let is_last = chars.peek().is_none();
        if MULTI_WORD_KEYWORDS_LINK_CHARS.contains(&c) {
            if is_first || is_last {
                // A link char at the very start/end of the keyword (e.g. "-host") is part of
                // the keyword's own literal shape, not a separator between two words, so it
                // must stay mandatory.
                out.push_str(LINK_CHAR_SEPARATOR_PATTERN);
            } else {
                // An interior separator is optional so that concatenated words
                // (e.g. "blable" for the keyword "bla ble") are matched as well.
                out.push_str(OPTIONAL_LINK_CHAR_SEPARATOR_PATTERN);
            }
        } else {
            push_escaped_literal(out, c);
        }
        is_first = false;
    }

    if should_push_word_boundary(last) {
        out.push_str(WORD_BOUNDARY_OR_LINK_CHAR_PATTERN);
    }
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
        // If it's neither an uppercase character nor a lowercase character, return NoBypass
        if !is_lower && !is_upper {
            return BypassStandardizePathResult::NoBypass;
        }
        all_lower = all_lower && is_lower;
        all_upper = all_upper && is_upper;
        // If we realise that we don't have all uppercase nor all lowercase, return NoBypass
        if !all_lower && !all_upper {
            return BypassStandardizePathResult::NoBypass;
        }
    }

    // The characters contain only uppercase characters or only lowercase characters by now, so we can bypass
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

    let mut prev_char = get_char_type(&char);
    for (i, current) in characters_iter.enumerate() {
        let is_last_char = i == kw_length - 2;

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

        prev_char = current_char;
    }
}

/// Format a keyword directly into a path regex pattern string; the keyword MUST NOT be empty.
fn push_keyword_path_pattern(keyword: &str, out: &mut String) {
    let Some(first) = keyword.chars().next() else {
        return;
    };
    if should_push_word_boundary(first) {
        out.push_str(WORD_BOUNDARY_PATTERN);
    }

    standardize_path_chars(keyword, |c| {
        push_escaped_literal(out, c.to_ascii_lowercase());
    });

    if should_push_word_boundary(keyword.chars().next_back().unwrap()) {
        out.push_str(WORD_BOUNDARY_PATTERN);
    }
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
    use excluded_keywords::contains_excluded_keyword_match;

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
        assert!(is_index_within_prefix(content, 0, 1, 10));
        assert!(is_index_within_prefix(content, 0, 5, 10));
        assert!(is_index_within_prefix(content, 0, 9, 10));
        assert!(is_index_within_prefix(content, 0, 10, 10));
        assert!(!is_index_within_prefix(content, 0, 11, 10));

        assert!(is_index_within_prefix(content, 5, 6, 10));
        assert!(is_index_within_prefix(content, 5, 10, 10));
        assert!(is_index_within_prefix(content, 5, 14, 10));
        assert!(is_index_within_prefix(content, 5, 15, 10));
        assert!(!is_index_within_prefix(content, 5, 16, 10));
    }

    #[test]
    fn test_is_index_within_prefix_multi_byte_unicode() {
        // each char is 2 bytes
        let content = "éèéèéèéèéèéèéèéè";
        assert!(is_index_within_prefix(content, 0, 2, 10));
        assert!(is_index_within_prefix(content, 2, 6, 3));
        assert!(!is_index_within_prefix(content, 2, 6, 1));
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
            try_new_compiled_proximity_keyword(30, vec![], vec![String::from("host")]).unwrap();
        let excluded = excluded.unwrap();
        let my_other_str = "¬------------------------------";
        let contains =
            contains_excluded_keyword_match(my_other_str, 32, 30, &excluded.content_regex);
        assert!(!contains);
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

        assert!(!is_false_positive);
    }

    #[test]
    fn test_excluded_keyword_stripped_chars_in_word_boundary() {
        let (_included, excluded) =
            try_new_compiled_proximity_keyword(8, vec![], vec!["id".to_string()]).unwrap();
        let excluded = excluded.unwrap();
        // The entire string is in the prefix, but "-" is stripped, so "userid" don't match "id" due to the word boundary
        let is_false_positive = excluded.is_false_positive_match("user-id ab", 8);

        assert!(!is_false_positive);
    }

    #[test]
    fn test_excluded_keywords_on_start_boundary() {
        let (_included, excluded) =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();
        let excluded = excluded.unwrap();
        let is_false_positive = excluded.is_false_positive_match("invalid   abc", 10);

        assert!(!is_false_positive);
    }

    #[test]
    fn test_excluded_keywords_on_end_boundary() {
        let (_included, excluded) =
            try_new_compiled_proximity_keyword(5, vec![], vec!["id".to_string()]).unwrap();

        let excluded = excluded.unwrap();
        let is_false_positive = excluded.is_false_positive_match("foo idabc", 6);
        assert!(!is_false_positive);
    }

    fn format_keyword_content_pattern(keyword: &str) -> String {
        let mut out = String::new();
        push_keyword_content_pattern(keyword, &mut out);
        out
    }

    fn format_keyword_path_pattern(keyword: &str) -> String {
        let mut out = String::new();
        push_keyword_path_pattern(keyword, &mut out);
        out
    }

    #[test]
    fn test_compile_keywords() {
        let (content_regex, path_regex) =
            compile_keywords(&["hello".to_string(), "awsAccess".to_string()], 20, &[])
                .unwrap()
                .unwrap();
        assert!(content_regex.is_match("hello"));
        assert!(!content_regex.is_match("he-l_lo"));
        assert_eq!(
            content_regex.search(&Input::new("I want to say hello to my dear friend")),
            Some(regex_automata::Match::must(0, 14..19))
        );

        assert!(!path_regex.is_match("awsAccess"));
        assert!(path_regex.is_match("aws.access"));
        assert!(!path_regex.is_match("aws.accessible"));
        assert_eq!(
            path_regex.search(&Input::new("my.path.to.aws.access")),
            Some(regex_automata::Match::must(0, 11..21))
        );
    }

    #[test]
    fn test_compile_keywords_pattern() {
        let (content_pattern, path_pattern) = compile_keywords_to_patterns(
            &[
                "hello".to_string(),
                "world*".to_string(),
                "_aws".to_string(),
                "aws-access".to_string(),
            ],
            10,
            &[],
            true,
        )
        .unwrap()
        .unwrap();

        assert_eq!(
            content_pattern,
            "(?:(?-u:\\b)|(?:_))hello(?:(?-u:\\b)|(?:_))|(?:(?-u:\\b)|(?:_))world\\*|(?:\\-|_|\\.| |/)aws(?:(?-u:\\b)|(?:_))|(?:(?-u:\\b)|(?:_))aws(?:\\-|_|\\.| |/)?access(?:(?-u:\\b)|(?:_))"
        );
        assert_eq!(
            path_pattern,
            "(?-u:\\b)hello(?-u:\\b)|(?-u:\\b)world\\*|_aws(?-u:\\b)|(?-u:\\b)aws\\.access(?-u:\\b)"
        );
    }

    #[test]
    fn test_calculate_keyword_pattern() {
        assert_eq!(
            format_keyword_content_pattern("test"),
            "(?:(?-u:\\b)|(?:_))test(?:(?-u:\\b)|(?:_))".to_string()
        );
    }

    #[test]
    fn test_calculate_multi_word_keyword_pattern() {
        assert_eq!(
            format_keyword_content_pattern("multi word-KEYWORD"),
            "(?:(?-u:\\b)|(?:_))multi(?:\\-|_|\\.| |/)?word(?:\\-|_|\\.| |/)?KEYWORD(?:(?-u:\\b)|(?:_))"
        )
    }

    #[test]
    fn test_calculate_path_pattern_on_simple_keyword() {
        assert_eq!(
            format_keyword_path_pattern("test"),
            "(?-u:\\b)test(?-u:\\b)".to_string()
        );
        assert_eq!(
            format_keyword_path_pattern("t"),
            "(?-u:\\b)t(?-u:\\b)".to_string()
        );
    }

    #[test]
    fn test_calculate_path_pattern_on_multi_word_keyword() {
        assert_eq!(
            format_keyword_path_pattern("test hello world"),
            "(?-u:\\b)test\\.hello\\.world(?-u:\\b)".to_string()
        );

        assert_eq!(
            format_keyword_path_pattern("test helloWorld"),
            "(?-u:\\b)test\\.hello\\.world(?-u:\\b)".to_string()
        );

        assert_eq!(
            format_keyword_path_pattern("awsAccess-key-id"),
            "(?-u:\\b)aws\\.access\\.key\\.id(?-u:\\b)".to_string()
        );

        assert_eq!(
            format_keyword_path_pattern("AWS_KEY_ID"),
            "(?-u:\\b)aws\\.key\\.id(?-u:\\b)".to_string()
        );

        assert_eq!(
            format_keyword_path_pattern("_AWS_KEY_ID_"),
            "_aws\\.key\\.id_".to_string()
        );

        assert_eq!(
            format_keyword_path_pattern("AwsAccessKeyID"),
            "(?-u:\\b)aws\\.access\\.key\\.id(?-u:\\b)".to_string()
        );

        assert_eq!(
            format_keyword_path_pattern("AWSACCESSKEYID"),
            "(?-u:\\b)awsaccesskeyid(?-u:\\b)".to_string()
        );

        assert_eq!(
            format_keyword_path_pattern("aLotOfCamelCaSe"),
            "(?-u:\\b)a\\.lot\\.of\\.camel\\.ca\\.se(?-u:\\b)".to_string()
        );

        assert_eq!(
            format_keyword_path_pattern("testThis-with_different/separators"),
            "(?-u:\\b)test\\.this\\.with\\.different\\.separators(?-u:\\b)".to_string()
        );

        assert_eq!(
            format_keyword_path_pattern("edge--case_/a. bit...annoying"),
            "(?-u:\\b)edge\\.\\-case\\./a\\. bit\\.\\.\\.annoying(?-u:\\b)".to_string()
        );

        assert_eq!(
            format_keyword_path_pattern("lots--of___symbol/s"),
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
        assert_eq!(prev_char_with_index("a€b", 5), Some((4, 'b')));
        assert_eq!(prev_char_with_index("a€b", 4), Some((1, '€')));
        assert_eq!(prev_char_with_index("a€b", 1), Some((0, 'a')));
        assert_eq!(prev_char_with_index("a€b", 0), None);
        assert_eq!(prev_char_with_index("", 0), None);
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
                "phone".to_string(),
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
            "aws.access.phone",
            "aws.access.phoneNumber",
            "access.key.aws.another.long.keyword",
        ];

        let mut cache = included_keywords.keywords_pattern.path_regex.create_cache();

        // Should match
        for path in should_match {
            assert!(contains_keyword_in_path(
                path,
                &included_keywords.keywords_pattern,
                &mut cache,
            ));
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
            assert!(!contains_keyword_in_path(
                path,
                &included_keywords.keywords_pattern,
                &mut cache,
            ));
        }
    }

    #[test]
    fn test_direct_pattern_formatting_matches_ast_reference() {
        use crate::ast_utils::{literal_ast, span};
        use regex_syntax::ast::{
            Alternation, Assertion, AssertionKind, Ast, Concat, Flag, Flags, FlagsItem,
            FlagsItemKind, Group, GroupKind, Repetition, RepetitionKind, RepetitionOp,
        };

        fn ast_any_char(chars: &[char]) -> Ast {
            let asts = chars
                .iter()
                .map(|c| Ast::Literal(literal_ast(*c)))
                .collect();
            Ast::Group(Group {
                span: span(),
                kind: GroupKind::NonCapturing(Flags {
                    span: span(),
                    items: vec![],
                }),
                ast: Box::new(Ast::Alternation(Alternation { span: span(), asts })),
            })
        }

        fn ast_word_boundary() -> Ast {
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

        fn ast_word_boundary_or_link_char() -> Ast {
            Ast::Group(Group {
                span: span(),
                kind: GroupKind::NonCapturing(Flags {
                    span: span(),
                    items: vec![],
                }),
                ast: Box::new(Ast::Alternation(Alternation {
                    span: span(),
                    asts: vec![ast_word_boundary(), ast_any_char(&['_'])],
                })),
            })
        }

        fn ast_content_pattern(keyword: &str) -> String {
            let mut asts = vec![];
            if should_push_word_boundary(keyword.chars().next().unwrap()) {
                asts.push(ast_word_boundary_or_link_char());
            }
            let char_count = keyword.chars().count();
            for (i, c) in keyword.chars().enumerate() {
                if MULTI_WORD_KEYWORDS_LINK_CHARS.contains(&c) {
                    let sep = ast_any_char(MULTI_WORD_KEYWORDS_LINK_CHARS);
                    if i == 0 || i == char_count - 1 {
                        asts.push(sep);
                    } else {
                        asts.push(Ast::Repetition(Repetition {
                            span: span(),
                            op: RepetitionOp {
                                span: span(),
                                kind: RepetitionKind::ZeroOrOne,
                            },
                            greedy: true,
                            ast: Box::new(sep),
                        }));
                    }
                } else {
                    asts.push(Ast::Literal(literal_ast(c)));
                }
            }
            if should_push_word_boundary(keyword.chars().next_back().unwrap()) {
                asts.push(ast_word_boundary_or_link_char());
            }
            Ast::Concat(Concat { span: span(), asts }).to_string()
        }

        fn ast_path_pattern(keyword: &str) -> String {
            let mut asts = vec![];
            if should_push_word_boundary(keyword.chars().next().unwrap()) {
                asts.push(ast_word_boundary());
            }
            standardize_path_chars(keyword, |c| {
                asts.push(Ast::Literal(literal_ast(c.to_ascii_lowercase())));
            });
            if should_push_word_boundary(keyword.chars().next_back().unwrap()) {
                asts.push(ast_word_boundary());
            }
            Ast::Concat(Concat { span: span(), asts }).to_string()
        }

        // Verify constant fragments stay in sync with AST printer and link char lists.
        assert_eq!(WORD_BOUNDARY_PATTERN, ast_word_boundary().to_string());
        assert_eq!(
            WORD_BOUNDARY_OR_LINK_CHAR_PATTERN,
            ast_word_boundary_or_link_char().to_string()
        );
        assert_eq!(
            LINK_CHAR_SEPARATOR_PATTERN,
            ast_any_char(MULTI_WORD_KEYWORDS_LINK_CHARS).to_string()
        );
        assert_eq!(
            OPTIONAL_LINK_CHAR_SEPARATOR_PATTERN,
            format!("{}?", ast_any_char(MULTI_WORD_KEYWORDS_LINK_CHARS))
        );

        let mut test_keywords: Vec<String> = vec![
            "a".into(),
            "-".into(),
            "_".into(),
            ".".into(),
            "/".into(),
            "hello".into(),
            "-host".into(),
            "host-".into(),
            "_aws_key_".into(),
            "awsAccess-key-id".into(),
            "AWS_KEY_ID".into(),
            "aLotOfCamelCaSe".into(),
            "edge--case_/a. bit...annoying".into(),
            r"meta.*+?()|[]{}^$\".into(),
            "ৎhost".into(),
            "café-token".into(),
            "😀key".into(),
        ];
        // Also cover every single printable ASCII character as a 1-char keyword and embedded.
        for b in 0x21u8..=0x7eu8 {
            let c = b as char;
            test_keywords.push(c.to_string());
            test_keywords.push(format!("a{c}b"));
        }

        for kw in &test_keywords {
            assert_eq!(
                format_keyword_content_pattern(kw),
                ast_content_pattern(kw),
                "content pattern mismatch for {kw:?}"
            );
            assert_eq!(
                format_keyword_path_pattern(kw),
                ast_path_pattern(kw),
                "path pattern mismatch for {kw:?}"
            );
        }

        let batch = vec![
            "hello".to_string(),
            "  aws-access ".to_string(),
            "world*".to_string(),
        ];
        let (direct_content, direct_path) = compile_keywords_to_patterns(&batch, 30, &[], true)
            .unwrap()
            .unwrap();
        let expected_content = batch
            .iter()
            .map(|k| ast_content_pattern(k.trim()))
            .collect::<Vec<_>>()
            .join("|");
        let expected_path = batch
            .iter()
            .map(|k| ast_path_pattern(k.trim()))
            .collect::<Vec<_>>()
            .join("|");
        assert_eq!(direct_content, expected_content);
        assert_eq!(direct_path, expected_path);
    }
}
