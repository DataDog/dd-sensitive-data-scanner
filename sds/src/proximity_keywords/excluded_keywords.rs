use crate::proximity_keywords::{
    get_prefix_start, next_char_index, prev_char_index, ProximityKeywordsRegex,
    EXCLUDED_KEYWORDS_REMOVED_CHARS,
};
use metrics::Counter;
use regex_automata_fork::Input;

pub struct CompiledExcludedProximityKeywords {
    pub look_ahead_character_count: usize,
    pub keywords_pattern: ProximityKeywordsRegex,
    pub false_positive_counter: Counter,
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

/// Returns the match context which is what is searched for keywords
/// and the range where matches are searched for. The range is needed since the context is
/// expanded to ensure regex assertions (e.g. word boundaries) work correctly.
fn contains_excluded_keyword_match(
    content: &str,
    match_start: usize,
    look_ahead_char_count: usize,
    regex: &ProximityKeywordsRegex,
) -> bool {
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

    let input = Input::new(&stripped_prefix)
        .earliest(true)
        .span(span_start..span_end);
    regex.content_regex.search_half(&input).is_some()
}
