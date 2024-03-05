use crate::proximity_keywords::ProximityKeywordsValidationError::{
    EmptyKeyword, InvalidLookAheadCharacterCount, KeywordTooLong, TooManyKeywords,
};

use crate::rule::ProximityKeywordsConfig;
use regex::{Regex, RegexBuilder};
use regex_syntax::ast::{
    Alternation, Assertion, AssertionKind, Ast, Concat, Flag, Flags, FlagsItem, FlagsItemKind,
    Group, GroupKind, Literal, LiteralKind, Position, Span,
};

const MAX_KEYWORD_COUNT: usize = 50;
const MAX_LOOK_AHEAD_CHARACTER_COUNT: usize = 50;

/// Internal representation of included keywords after it has been validated / compiled.
#[derive(Default)]
pub struct CompiledProximityKeywords {
    look_ahead_character_count: usize,
    included_keywords_pattern: Option<Regex>,
    excluded_keywords_pattern: Option<Regex>,
}

/// Characters we strip inside for excluded keywords in order to remove some noise
const EXCLUDED_KEYWORDS_REMOVED_CHARS: &[char] = &['-', '_'];

impl CompiledProximityKeywords {
    pub fn is_false_positive_match(&self, value: &str, match_start: usize) -> bool {
        if self.included_keywords_pattern.is_none() && self.excluded_keywords_pattern.is_none() {
            return false;
        }

        let before_match_value = &value[0..match_start];
        let start_included_keyword_byte = before_match_value
            .char_indices()
            .nth_back(self.look_ahead_character_count - 1)
            .map(|item| item.0)
            .unwrap_or(0);
        let match_prefix = &value[start_included_keyword_byte..match_start];

        if let Some(included_keywords_pattern) = self.included_keywords_pattern.as_ref() {
            return !included_keywords_pattern.is_match(match_prefix);
        };

        self.excluded_keywords_pattern
            .as_ref()
            // excluded_keywords_pattern is necessarily not none if included_keywords_pattern is none due to the first condition of the function.
            .unwrap()
            .is_match(&match_prefix.replace(EXCLUDED_KEYWORDS_REMOVED_CHARS, ""))
    }
}

impl TryFrom<ProximityKeywordsConfig> for CompiledProximityKeywords {
    type Error = ProximityKeywordsValidationError;

    fn try_from(config: ProximityKeywordsConfig) -> Result<Self, Self::Error> {
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
        })
    }
}

fn compile_keywords(
    keywords: Vec<String>,
    look_ahead_character_count: usize,
    remove_chars: &[char],
) -> Result<Option<Regex>, ProximityKeywordsValidationError> {
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
            Ok(calculate_keyword_pattern(&trimmed_keyword))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let pattern = Ast::Alternation(Alternation {
        span: span(),
        asts: keyword_patterns,
    })
    .to_string();

    Ok(Option::from(
        RegexBuilder::new(&pattern)
            // Never limit the complexity the keywords patterns to make sure it always compile.
            // The complexity of the regex should be bounded by:
            //  - the max number of keywords
            //  - the max length of keywords
            // If this limit is reached, the code will panic
            .size_limit(usize::MAX)
            .case_insensitive(true)
            .build()
            .unwrap(),
    ))
}

/// Transform a keyword in an AST, the keyword MUST NOT be empty
fn calculate_keyword_pattern(keyword: &str) -> Ast {
    let mut keyword_pattern: Vec<Ast> = vec![];
    if keyword
        .chars()
        .next()
        .map(|char| char.is_ascii_alphabetic() || char.is_ascii_digit())
        .unwrap()
    {
        keyword_pattern.push(word_boundary())
    }

    for character in keyword.chars() {
        let kind = if regex_syntax::is_meta_character(character) {
            LiteralKind::Meta
        } else {
            LiteralKind::Verbatim
        };
        keyword_pattern.push(Ast::Literal(Literal {
            span: span(),
            kind,
            c: character,
        }))
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

    #[test]
    fn test_empty_keyword() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec![],
        })
        .unwrap();
        assert!(!proximity_keywords.is_false_positive_match("hello world", 6));
    }

    #[test]
    fn test_included_keyword() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["hello".to_string()],
            excluded_keywords: vec![],
        })
        .unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(!proximity_keywords.is_false_positive_match("hey, hello world", 11));

        assert!(proximity_keywords.is_false_positive_match("world", 5));
        assert!(proximity_keywords.is_false_positive_match("world", 0));

        assert!(proximity_keywords.is_false_positive_match("hello world", 3));
    }

    #[test]
    fn test_excluded_keyword() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec!["hello".to_string()],
        })
        .unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(proximity_keywords.is_false_positive_match("hey, hello world", 11));

        assert!(!proximity_keywords.is_false_positive_match("world", 5));
        assert!(!proximity_keywords.is_false_positive_match("world", 0));

        assert!(!proximity_keywords.is_false_positive_match("hello world", 3));
    }

    #[test]
    fn test_included_and_excluded_keyword() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["hey".to_string()],
            excluded_keywords: vec!["hello".to_string()],
        })
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
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["hello".to_string(), "coty".to_string()],
            excluded_keywords: vec![],
        })
        .unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(!proximity_keywords.is_false_positive_match("hey coty, hello world", 16));

        assert!(proximity_keywords.is_false_positive_match("hey hey hey world", 12));

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec!["hello".to_string(), "coty".to_string()],
        })
        .unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(proximity_keywords.is_false_positive_match("hey coty, hello world", 16));

        assert!(!proximity_keywords.is_false_positive_match("hey hey hey world", 12));
    }

    #[test]
    fn should_quote_keyword() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["he.*o".to_string()],
            excluded_keywords: vec![],
        })
        .unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(!proximity_keywords.is_false_positive_match("he.*o world", 6));

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec!["he.*o".to_string()],
        })
        .unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(proximity_keywords.is_false_positive_match("he.*o world", 6));
    }

    #[test]
    fn keywords_should_be_case_insensitive() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["hello".to_string()],
            excluded_keywords: vec![],
        })
        .unwrap();

        assert!(!proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(!proximity_keywords.is_false_positive_match("HELLO world", 6));

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec!["hello".to_string()],
        })
        .unwrap();

        assert!(proximity_keywords.is_false_positive_match("hello world", 6));
        assert!(proximity_keywords.is_false_positive_match("HELLO world", 6));
    }

    #[test]
    fn included_keyword_should_have_word_boundaries() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["host".to_string()],
            excluded_keywords: vec![],
        })
        .unwrap();
        assert!(!proximity_keywords.is_false_positive_match("host ping", 5));
        assert!(proximity_keywords.is_false_positive_match("localhost ping", 10));
        assert!(proximity_keywords.is_false_positive_match("hostlocal ping", 10));

        // word boundaries are is added at the beginning (resp. end) only if the first (resp. last) character is a letter or a digit
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["-host".to_string()],
            excluded_keywords: vec![],
        })
        .unwrap();
        assert!(!proximity_keywords.is_false_positive_match("-host- ping", 6));
        assert!(!proximity_keywords.is_false_positive_match("local-host ping", 11));
        assert!(proximity_keywords.is_false_positive_match("-hostlocal ping", 11));

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["ৎhost".to_string()],
            excluded_keywords: vec![],
        })
        .unwrap();
        assert!(!proximity_keywords.is_false_positive_match("ৎhost ping", 7));
        assert!(!proximity_keywords.is_false_positive_match("localৎhost ping", 12));
    }

    #[test]
    fn excluded_keyword_should_have_word_boundaries() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec!["host".to_string()],
        })
        .unwrap();
        assert!(proximity_keywords.is_false_positive_match("host ping", 5));
        assert!(!proximity_keywords.is_false_positive_match("localhost ping", 10));
        assert!(!proximity_keywords.is_false_positive_match("hostlocal ping", 10));

        // word boundaries are is added at the beginning (resp. end) only if the first (resp. last) character is a letter or a digit
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec!["!host".to_string()],
        })
        .unwrap();
        assert!(proximity_keywords.is_false_positive_match("!host- ping", 6));
        assert!(proximity_keywords.is_false_positive_match("local!host ping", 11));
        assert!(!proximity_keywords.is_false_positive_match("!hostlocal ping", 11));

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec!["ৎhost".to_string()],
        })
        .unwrap();
        assert!(proximity_keywords.is_false_positive_match("ৎhost ping", 7));
        assert!(proximity_keywords.is_false_positive_match("localৎhost ping", 12));
    }

    #[test]
    fn should_remove_excluded_keywords_removed_chars_in_excluded_keywords_and_prefix() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec!["span-id".to_string()],
        })
        .unwrap();
        assert!(proximity_keywords.is_false_positive_match("span-id ping", 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", 8));
        assert!(!proximity_keywords.is_false_positive_match("span id ping", 8));

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec!["span_id".to_string()],
        })
        .unwrap();
        assert!(proximity_keywords.is_false_positive_match("span-id ping", 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", 8));
        assert!(!proximity_keywords.is_false_positive_match("span id ping", 8));

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: vec!["spanid".to_string()],
        })
        .unwrap();
        assert!(proximity_keywords.is_false_positive_match("span-id ping", 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", 8));
        assert!(!proximity_keywords.is_false_positive_match("span id ping", 8));

        // nothing is changed on included keywords
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec!["span-id".to_string()],
            excluded_keywords: vec![],
        })
        .unwrap();
        assert!(!proximity_keywords.is_false_positive_match("span-id ping", 8));
        assert!(proximity_keywords.is_false_positive_match("spanid ping", 7));
        assert!(proximity_keywords.is_false_positive_match("span_id ping", 8));
    }

    #[test]
    fn should_look_ahead_too_far() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 10,
            included_keywords: vec!["host".to_string()],
            excluded_keywords: vec![],
        })
        .unwrap();
        assert!(proximity_keywords.is_false_positive_match("host 56789012345", 15));
        assert!(!proximity_keywords.is_false_positive_match("host 56789012345", 10));
        // prefix `ost 567890` does not contains host
        assert!(proximity_keywords.is_false_positive_match("host 56789012345", 11));
        assert!(!proximity_keywords.is_false_positive_match(" host 6789012345", 11));

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 10,
            included_keywords: vec![],
            excluded_keywords: vec!["host".to_string()],
        })
        .unwrap();
        assert!(!proximity_keywords.is_false_positive_match("host 56789012345", 15));
        assert!(proximity_keywords.is_false_positive_match("host 56789012345", 10));
        // prefix `ost 567890` does not contains host
        assert!(!proximity_keywords.is_false_positive_match("host 56789012345", 11));
        assert!(proximity_keywords.is_false_positive_match(" host 6789012345", 11));
    }

    #[test]
    fn should_not_contains_trim_empty_keyword() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 10,
            included_keywords: vec!["hello".to_string(), " ".to_string()],
            excluded_keywords: vec![],
        });
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), EmptyKeyword);

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 10,
            included_keywords: vec![],
            excluded_keywords: vec!["hello".to_string(), " ".to_string()],
        });
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), EmptyKeyword);

        // for excluded keywords, the limit should take into account the removed chars (- and _)
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 10,
            included_keywords: vec![],
            excluded_keywords: vec!["-".to_string()],
        });
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), EmptyKeyword);
    }

    #[test]
    fn should_not_have_more_than_keyword_count_limit() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: std::iter::repeat(["hello".to_string()])
                .flatten()
                .take(MAX_KEYWORD_COUNT)
                .collect(),
            excluded_keywords: vec![],
        });
        assert!(proximity_keywords.is_ok());

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: std::iter::repeat(["hello".to_string()])
                .flatten()
                .take(MAX_KEYWORD_COUNT + 1)
                .collect(),
            excluded_keywords: vec![],
        });
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), TooManyKeywords);

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: std::iter::repeat(["hello".to_string()])
                .flatten()
                .take(MAX_KEYWORD_COUNT)
                .collect(),
        });
        assert!(proximity_keywords.is_ok());

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 30,
            included_keywords: vec![],
            excluded_keywords: std::iter::repeat(["hello".to_string()])
                .flatten()
                .take(MAX_KEYWORD_COUNT + 1)
                .collect(),
        });
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), TooManyKeywords);
    }

    #[test]
    fn should_not_go_over_character_count_limit() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: MAX_LOOK_AHEAD_CHARACTER_COUNT,
            included_keywords: vec!["hello".to_string()],
            excluded_keywords: vec![],
        });
        assert!(proximity_keywords.is_ok());

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: MAX_LOOK_AHEAD_CHARACTER_COUNT + 1,
            included_keywords: vec!["hello".to_string()],
            excluded_keywords: vec![],
        });
        assert!(proximity_keywords.is_err());
        assert_eq!(
            proximity_keywords.err().unwrap(),
            InvalidLookAheadCharacterCount
        );

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 0,
            included_keywords: vec!["hello".to_string()],
            excluded_keywords: vec![],
        });
        assert!(proximity_keywords.is_err());
        assert_eq!(
            proximity_keywords.err().unwrap(),
            InvalidLookAheadCharacterCount
        );
    }

    #[test]
    fn keywords_should_be_smaller_than_character_count() {
        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 5,
            included_keywords: vec!["hello".to_string()],
            excluded_keywords: vec![],
        });
        assert!(proximity_keywords.is_ok());

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 5,
            included_keywords: vec!["hello-".to_string()],
            excluded_keywords: vec![],
        });
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), KeywordTooLong);

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 5,
            included_keywords: vec![],
            excluded_keywords: vec!["hello".to_string()],
        });
        assert!(proximity_keywords.is_ok());

        let proximity_keywords = CompiledProximityKeywords::try_from(ProximityKeywordsConfig {
            look_ahead_character_count: 5,
            included_keywords: vec![],
            excluded_keywords: vec!["hello1".to_string()],
        });
        assert!(proximity_keywords.is_err());
        assert_eq!(proximity_keywords.err().unwrap(), KeywordTooLong);
    }
}
