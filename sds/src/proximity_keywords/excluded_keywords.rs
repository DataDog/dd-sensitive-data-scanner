use crate::proximity_keywords::{
    prev_char_with_index, ProximityKeywordsRegex, EXCLUDED_KEYWORDS_REMOVED_CHARS,
};
use metrics::Counter;
use nom::AsChar;
use regex_automata::Input;

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

fn get_span_bounds_scan(
    content: &str,
    match_start: usize,
    look_ahead_char_count: usize,
) -> SpanBoundsWithStrippedPrefix {
    let mut i = match_start;

    // the number of chars consumed, even if they were excluded
    let mut span_char_len = 0;

    let mut prefix = String::with_capacity(look_ahead_char_count + 2);

    // Try to take 1 char from the match first (for boundary checking)
    let mut bytes_added_to_end = 0;
    if let Some(c) = content[i..].chars().next() {
        if !EXCLUDED_KEYWORDS_REMOVED_CHARS.contains(&c) {
            bytes_added_to_end = c.len();
            prefix.push(c);
        }
    }

    // collect `look_ahead_char_count` chars without the excluded chars
    loop {
        if i == 0 {
            break;
        }
        if span_char_len == look_ahead_char_count {
            break;
        }
        if let Some((prev_i, c)) = prev_char_with_index(content, i) {
            i = prev_i;
            span_char_len += 1;
            if !EXCLUDED_KEYWORDS_REMOVED_CHARS.contains(&c) {
                prefix.push(c);
            }
        }
    }

    let mut span_start = 0;

    // Try to append another char to the front for boundary checking
    if let Some(c) = content[..i].chars().next_back() {
        span_start = c.len();
        prefix.push(c);
    }
    let prefix = prefix.chars().rev().collect::<String>();
    SpanBoundsWithStrippedPrefix {
        start: span_start,
        end: prefix.len() - bytes_added_to_end,
        stripped_prefix: prefix,
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
    let span_bounds = get_span_bounds_scan(content, match_start, look_ahead_char_count);
    let input = Input::new(&span_bounds.stripped_prefix)
        .earliest(true)
        .span(span_bounds.start..span_bounds.end);
    regex.content_regex.search_half(&input).is_some()
}

#[cfg(test)]
mod tests {

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
    fn test_get_span_bounds() {
        let data = vec![
            TestGetSpanBoundsData {
                content: "¬------------------------------".to_string(),
                match_start: 32,
                look_ahead_char_count: 30,
                expected_start: 2,
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
                expected_start: 1,
                expected_end: 8,
                expected_stripped_prefix: " content".to_string(),
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
            let span_bounds =
                get_span_bounds_scan(&d.content, d.match_start, d.look_ahead_char_count);
            assert_eq!(
                span_bounds.start, d.expected_start,
                "span start bounds do not match, expected {}, got {}",
                d.expected_start, span_bounds.start
            );
            assert_eq!(
                span_bounds.end, d.expected_end,
                "span end bounds do not match, expected {}, got {} [this is test with content {}]",
                d.expected_end, span_bounds.end, &d.content
            );
            assert_eq!(
                span_bounds.stripped_prefix, d.expected_stripped_prefix,
                "stripped prefix does not match"
            );
        }
    }
}
