use metrics::Counter;

pub struct CompiledExcludedProximityKeywords {
    pub look_ahead_character_count: usize,
    pub keywords_pattern: super::ProximityKeywordsRegex,
    pub false_positive_counter: Counter,
}

impl CompiledExcludedProximityKeywords {
    pub fn is_false_positive_match(&self, content: &str, match_start: usize) -> bool {
        let is_false_positive = super::contains_keyword_match(
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
