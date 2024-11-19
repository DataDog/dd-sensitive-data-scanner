use crate::proximity_keywords::next_char_index;
use crate::scanner::regex_rule::RegexCaches;
use regex_automata::Input;

pub struct CompiledIncludedProximityKeywords {
    pub look_ahead_character_count: usize,
    pub keywords_pattern: super::ProximityKeywordsRegex,
}

impl CompiledIncludedProximityKeywords {
    pub fn keyword_matches<'a>(&'a self, content: &'a str) -> IncludedKeywordSearch<'a> {
        IncludedKeywordSearch {
            keywords: self,
            content,
            start: 0,
        }
    }
}

pub struct IncludedKeywordSearch<'a> {
    keywords: &'a CompiledIncludedProximityKeywords,
    content: &'a str,
    start: usize,
}

impl<'a> IncludedKeywordSearch<'a> {
    pub fn skip_to(&mut self, start: usize) {
        if start > self.start {
            self.start = start;
        }
    }

    pub fn next(&mut self, regex_caches: &mut RegexCaches) -> Option<usize> {
        let input = Input::new(self.content).range(self.start..).earliest(true);

        if let Some(included_keyword_match) =
            self.keywords.keywords_pattern.content_regex.search_with(
                regex_caches.get(&self.keywords.keywords_pattern.content_regex),
                &input,
            )
        {
            // The next scan starts at the next character after the start of the keyword since
            // multi-word keywords can overlap
            self.start = next_char_index(self.content, included_keyword_match.start())
                .unwrap_or(included_keyword_match.end());
            Some(included_keyword_match.start())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use crate::proximity_keywords::{
        compile_keywords_proximity_config, CompiledIncludedProximityKeywords, IncludedKeywordSearch,
    };
    use crate::scanner::regex_rule::config::ProximityKeywordsConfig;
    use crate::scanner::regex_rule::RegexCaches;
    use crate::Labels;

    fn collect_keyword_matches(mut search: IncludedKeywordSearch) -> Vec<usize> {
        let mut caches = RegexCaches::new();
        let mut output = vec![];
        while let Some(x) = search.next(&mut caches) {
            output.push(x);
        }
        output
    }

    fn compile_keywords(lookahead: usize, keywords: &[&str]) -> CompiledIncludedProximityKeywords {
        let (included, _) = compile_keywords_proximity_config(
            &ProximityKeywordsConfig {
                look_ahead_character_count: lookahead,
                included_keywords: keywords.iter().map(|s| s.to_string()).collect(),
                excluded_keywords: vec![],
            },
            &Labels::empty(),
        )
        .unwrap();
        included.unwrap()
    }

    #[test]
    fn test_included_keywords_on_start_boundary() {
        let keywords = compile_keywords(5, &["id"]);

        let keyword_matches = collect_keyword_matches(keywords.keyword_matches("invalid   abc"));

        // There should be no matches since keywords have a word boundary
        assert!(keyword_matches.is_empty());
    }

    #[test]
    fn test_overlapping_keywords() {
        let keywords = compile_keywords(5, &["a b", "b c"]);

        let keyword_matches = collect_keyword_matches(keywords.keyword_matches("a b c"));

        assert_eq!(keyword_matches, vec![0, 2]);
    }

    #[test]
    fn should_detect_on_any_keyword() {
        let keywords = compile_keywords(30, &["hello", "coty"]);

        assert_eq!(
            collect_keyword_matches(keywords.keyword_matches("hello world")),
            vec![0]
        );

        assert_eq!(
            collect_keyword_matches(keywords.keyword_matches("hey coty, hello world")),
            vec![4, 10]
        );

        assert!(collect_keyword_matches(keywords.keyword_matches("hey hey hey world")).is_empty());
    }

    #[test]
    fn should_quote_keyword() {
        let keywords = compile_keywords(30, &["he.*o"]);

        assert!(collect_keyword_matches(keywords.keyword_matches("hello world")).is_empty(),);

        assert_eq!(
            collect_keyword_matches(keywords.keyword_matches("he.*o world")),
            vec![0]
        );
    }

    #[test]
    fn keywords_should_be_case_insensitive() {
        let keywords = compile_keywords(30, &["hello"]);

        assert_eq!(
            collect_keyword_matches(keywords.keyword_matches("HELLO world")),
            vec![0]
        );
        assert_eq!(
            collect_keyword_matches(keywords.keyword_matches("hello world")),
            vec![0]
        );
    }

    #[test]
    fn included_keyword_should_have_word_boundaries() {
        let keywords = compile_keywords(30, &["host"]);

        assert_eq!(
            collect_keyword_matches(keywords.keyword_matches("host ping")),
            vec![0]
        );
        assert!(collect_keyword_matches(keywords.keyword_matches("localhost ping")).is_empty());
        assert!(collect_keyword_matches(keywords.keyword_matches("hostlocal ping")).is_empty());

        // word boundaries are is added at the beginning (resp. end) only if the first (resp. last) character is a letter or a digit
        let keywords = compile_keywords(30, &["-host"]);

        assert_eq!(
            collect_keyword_matches(keywords.keyword_matches("-host ping")),
            vec![0]
        );
        assert_eq!(
            collect_keyword_matches(keywords.keyword_matches("local-host ping")),
            vec![5]
        );
        assert!(collect_keyword_matches(keywords.keyword_matches("-hostlocal ping")).is_empty());

        let keywords = compile_keywords(30, &["ৎhost"]);
        assert_eq!(
            collect_keyword_matches(keywords.keyword_matches("ৎhost ping")),
            vec![0]
        );
        assert_eq!(
            collect_keyword_matches(keywords.keyword_matches("localৎhost ping")),
            vec![5]
        );
    }
}
