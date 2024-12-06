use std::{fmt::Display, fs::OpenOptions};

use crate::proximity_keywords::{
    get_prefix_start, next_char_index, prev_char_index, ProximityKeywordsRegex,
    EXCLUDED_KEYWORDS_REMOVED_CHARS,
};
use metrics::Counter;
use regex_automata::Input;
use std::io::Write;

pub struct CompiledExcludedProximityKeywords {
    pub look_ahead_character_count: usize,
    pub keywords_pattern: ProximityKeywordsRegex,
    pub false_positive_counter: Counter,
}

#[derive(Debug, PartialEq)]
struct SpanBoundsWithStrippedPrefix {
    start: usize,
    end: usize,
    stripped_prefix: String,
}

impl CompiledExcludedProximityKeywords {
    pub fn is_false_positive_match(&self, content: &str, match_start: usize) -> bool {
        let is_false_positive = contains_excluded_keyword_match(
            content,
            match_start,
            self.look_ahead_character_count,
            &self.keywords_pattern,
        );
        if is_false_positive {
            self.false_positive_counter.increment(1);
        }
        is_false_positive
    }
}

fn get_span_bounds_orig(
    content: &str,
    match_start: usize,
    look_ahead_char_count: usize,
) -> SpanBoundsWithStrippedPrefix {
    let prefix_start_info = get_prefix_start(
        match_start,
        // Adding 1 to the start to account for assertion checking
        look_ahead_char_count + 1,
        content,
    );

    // Adding 1 char here to allow correct assertion checking on the last char. There will always be
    // at least 1 more char is always available since empty matches aren't allowed
    let prefix_end = next_char_index(content, match_start).unwrap_or(content.len());

    let stripped_prefix =
        content[prefix_start_info.start..prefix_end].replace(EXCLUDED_KEYWORDS_REMOVED_CHARS, "");

    // Subtracting one to exclude the last char which was added only for boundary checking
    let span_end = prev_char_index(&stripped_prefix, stripped_prefix.len()).unwrap_or(0);

    let span_start = if prefix_start_info.used_all_chars {
        // an extra char was added for assertion checking, so it needs to be removed here
        next_char_index(&stripped_prefix, 0).unwrap_or(stripped_prefix.len())
    } else {
        0
    };
    SpanBoundsWithStrippedPrefix {
        start: span_start,
        end: span_end,
        stripped_prefix,
    }
}

fn get_span_bounds(
    content: &str,
    match_start: usize,
    look_ahead_char_count: usize,
) -> SpanBoundsWithStrippedPrefix {
    let prefix_start_info = get_prefix_start(
        match_start,
        // Adding 1 to the start to account for assertion checking
        look_ahead_char_count + 1,
        content,
    );

    // Adding 1 char here to allow correct assertion checking on the last char. There will always be
    // at least 1 more char is always available since empty matches aren't allowed
    let (prefix_end, unable_to_grow) =
        if let Some(prefix_end) = next_char_index(content, match_start) {
            (prefix_end, false)
        } else {
            (content.len(), true)
        };

    let stripped_prefix =
        content[prefix_start_info.start..prefix_end].replace(EXCLUDED_KEYWORDS_REMOVED_CHARS, "");

    // Subtracting one to exclude the last char which was added only for boundary checking
    let span_end = if unable_to_grow {
        stripped_prefix.len()
    } else {
        prev_char_index(&stripped_prefix, stripped_prefix.len()).unwrap_or(0)
    };
    let span_start = if prefix_start_info.used_all_chars {
        // an extra char was added for assertion checking, so it needs to be removed here
        next_char_index(&stripped_prefix, 0).unwrap_or(stripped_prefix.len())
    } else {
        0
    };

    println!(
        "({}, {}), with prefix start and end ({}, {})",
        span_start, span_end, prefix_start_info.start, prefix_end
    );

    SpanBoundsWithStrippedPrefix {
        start: span_start,
        end: span_end,
        stripped_prefix,
    }
}

/// Returns the match context which is what is searched for keywords
/// and the range where matches are searched for. The range is needed since the context is
/// expanded to ensure regex assertions (e.g. word boundaries) work correctly.
pub fn contains_excluded_keyword_match(
    content: &str,
    match_start: usize,
    look_ahead_char_count: usize,
    regex: &ProximityKeywordsRegex,
) -> bool {
    let span_bounds = get_span_bounds(content, match_start, look_ahead_char_count);
    // println!(
    //     "({}, {}, {}) -> ({}, {}, {})",
    //     content,
    //     match_start,
    //     look_ahead_char_count,
    //     span_bounds.start,
    //     span_bounds.end,
    //     span_bounds.stripped_prefix
    // );
    // let mut file = OpenOptions::new()
    //     .write(true)
    //     .append(true)
    //     .open("excluded_keywords.txt")
    //     .unwrap();

    // writeln!(
    //     file,
    //     "TestGetSpanBoundsData {{content: \"{}\".to_string(),match_start: {},look_ahead_char_count: {},expected_start: {},expected_end: {},expected_stripped_prefix: \"{}\".to_string()}},",
    //     content,
    //     match_start,
    //     look_ahead_char_count,
    //     span_bounds.start,
    //     span_bounds.end,
    //     span_bounds.stripped_prefix
    // )
    // .unwrap();
    let input = Input::new(&span_bounds.stripped_prefix)
        .earliest(true)
        .span(span_bounds.start..span_bounds.end);
    regex.content_regex.search_half(&input).is_some()
}

#[cfg(test)]
mod tests {
    use std::ops::Sub;

    use crate::proximity_keywords::span;

    use super::*;

    struct TestGetSpanBoundsData {
        content: String,
        match_start: usize,
        look_ahead_char_count: usize,
        expected_start: usize,
        expected_end: usize,
        expected_stripped_prefix: String,
    }

    #[test]
    fn test_my_get_span_bounds() {
        let my_data = TestGetSpanBoundsData {
            content: "¬------------------------------".to_string(),
            match_start: 32,
            look_ahead_char_count: 30,
            expected_start: 0,
            expected_end: 2,
            expected_stripped_prefix: "¬".to_string(),
        };

        let span_bounds = get_span_bounds(
            &my_data.content,
            my_data.match_start,
            my_data.look_ahead_char_count,
        );
        println!("{:?}", span_bounds);
        println!("'{}'", span_bounds.stripped_prefix);
        println!(
            " {}{}{}{}",
            " ".repeat(span_bounds.start),
            "^",
            " ".repeat(std::cmp::min(
                span_bounds
                    .end
                    .wrapping_sub(span_bounds.start)
                    .wrapping_sub(1),
                0
            )),
            "^",
        );
        println!(
            "Span will scan '{}', exclusion will make use of '{}'",
            span_bounds.stripped_prefix[span_bounds.start..span_bounds.end].to_string(),
            span_bounds.stripped_prefix
        );
        assert_eq!(
            span_bounds.start, my_data.expected_start,
            "span start bounds do not match, expected {}, got {}",
            my_data.expected_start, span_bounds.start
        );
        assert_eq!(
            span_bounds.end, my_data.expected_end,
            "span end bounds do not match, expected {}, got {}",
            my_data.expected_end, span_bounds.end
        );
        assert_eq!(
            span_bounds.stripped_prefix, my_data.expected_stripped_prefix,
            "stripped prefix does not match"
        );
    }

    #[test]
    fn test_get_span_bounds() {
        let data = vec![
            TestGetSpanBoundsData {
                content: "¬------------------------------".to_string(),
                match_start: 32,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 2,
                expected_stripped_prefix: "¬".to_string(),
            },
            TestGetSpanBoundsData {
                content: "span-id ping".to_string(),
                match_start: 8,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 7,
                expected_stripped_prefix: "spanid p".to_string(),
            },
            TestGetSpanBoundsData {
                content: "span id ping".to_string(),
                match_start: 8,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 8,
                expected_stripped_prefix: "span id p".to_string(),
            },
            // This one tests the case where the match_start is at the end of the content
            // and it should not shrink the span
            TestGetSpanBoundsData {
                content: "this is some content".to_string(),
                match_start: 20,
                look_ahead_char_count: 7,
                expected_start: 14,
                expected_end: 20,
                expected_stripped_prefix: "content".to_string(),
            },
            TestGetSpanBoundsData {
                content: "span-id ping".to_string(),
                match_start: 8,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 7,
                expected_stripped_prefix: "spanid p".to_string(),
            },
            TestGetSpanBoundsData {
                content: "spanid ping".to_string(),
                match_start: 7,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 7,
                expected_stripped_prefix: "spanid p".to_string(),
            },
            TestGetSpanBoundsData {
                content: "span_id ping".to_string(),
                match_start: 8,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 7,
                expected_stripped_prefix: "spanid p".to_string(),
            },
            TestGetSpanBoundsData {
                content: "span id ping".to_string(),
                match_start: 8,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 8,
                expected_stripped_prefix: "span id p".to_string(),
            },
            TestGetSpanBoundsData {
                content: "hello world".to_string(),
                match_start: 6,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 6,
                expected_stripped_prefix: "hello w".to_string(),
            },
            TestGetSpanBoundsData {
                content: "hey, hello world".to_string(),
                match_start: 11,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 11,
                expected_stripped_prefix: "hey, hello w".to_string(),
            },
            TestGetSpanBoundsData {
                content: "world ".to_string(),
                match_start: 5,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 5,
                expected_stripped_prefix: "world ".to_string(),
            },
            TestGetSpanBoundsData {
                content: "world".to_string(),
                match_start: 0,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 0,
                expected_stripped_prefix: "w".to_string(),
            },
            TestGetSpanBoundsData {
                content: "hello world".to_string(),
                match_start: 3,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 3,
                expected_stripped_prefix: "hell".to_string(),
            },
            TestGetSpanBoundsData {
                content: "users i-d   ab".to_string(),
                match_start: 12,
                look_ahead_char_count: 5,
                expected_start: 1,
                expected_end: 5,
                expected_stripped_prefix: "id   a".to_string(),
            },
            TestGetSpanBoundsData {
                content: "user-id ab".to_string(),
                match_start: 8,
                look_ahead_char_count: 8,
                expected_start: 0,
                expected_end: 7,
                expected_stripped_prefix: "userid a".to_string(),
            },
            TestGetSpanBoundsData {
                content: "foo idabc".to_string(),
                match_start: 6,
                look_ahead_char_count: 5,
                expected_start: 1,
                expected_end: 6,
                expected_stripped_prefix: "foo ida".to_string(),
            },
            TestGetSpanBoundsData {
                content: "invalid   abc".to_string(),
                match_start: 10,
                look_ahead_char_count: 5,
                expected_start: 1,
                expected_end: 6,
                expected_stripped_prefix: "lid   a".to_string(),
            },
            TestGetSpanBoundsData {
                content: "hello world".to_string(),
                match_start: 6,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 6,
                expected_stripped_prefix: "hello w".to_string(),
            },
            TestGetSpanBoundsData {
                content: "x-test=value".to_string(),
                match_start: 7,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 6,
                expected_stripped_prefix: "xtest=v".to_string(),
            },
            TestGetSpanBoundsData {
                content: "he**o world".to_string(),
                match_start: 6,
                look_ahead_char_count: 30,
                expected_start: 0,
                expected_end: 6,
                expected_stripped_prefix: "he**o w".to_string(),
            },
        ];

        for d in data {
            let span_bounds = get_span_bounds(&d.content, d.match_start, d.look_ahead_char_count);
            let span_bounds_2 =
                get_span_bounds_orig(&d.content, d.match_start, d.look_ahead_char_count);
            assert_eq!(
                span_bounds, span_bounds_2,
                "span bounds do not match, orig was {:?}, new was {:?}",
                span_bounds_2, span_bounds
            );
            assert_eq!(
                span_bounds.start, d.expected_start,
                "span start bounds do not match, expected {}, got {}",
                d.expected_start, span_bounds.start
            );
            assert_eq!(
                span_bounds.end, d.expected_end,
                "span end bounds do not match, expected {}, got {}",
                d.expected_end, span_bounds.end
            );
            assert_eq!(
                span_bounds.stripped_prefix, d.expected_stripped_prefix,
                "stripped prefix does not match"
            );
        }
    }
}
