use metrics::Counter;

pub struct CompiledIncludedProximityKeywords {
    pub look_ahead_character_count: usize,
    pub keywords_pattern: super::ProximityKeywordsRegex<false>,
}

impl CompiledIncludedProximityKeywords {
    pub fn is_false_positive_match(
        &self,
        content: &str,
        sanitized_path: Option<String>,
        match_start: usize,
    ) -> bool {
        if let Some(sanitized_path) = sanitized_path {
            let is_valid_from_path =
                super::contains_keyword_in_path(&sanitized_path, &self.keywords_pattern);

            if is_valid_from_path {
                return false;
            }
        }

        let is_false_positive_from_content = !super::contains_keyword_match(
            content,
            match_start,
            self.look_ahead_character_count,
            &self.keywords_pattern,
        );

        is_false_positive_from_content
    }
}
