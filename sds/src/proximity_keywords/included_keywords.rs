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
        debug_assert!(start >= self.start);
        self.start = start;
    }
}

impl<'a> Iterator for IncludedKeywordSearch<'a> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        // TODO: use a custom cache for this regex too
        let input = Input::new(self.content).range(self.start..).earliest(true);

        if let Some(included_keyword_match) =
            self.keywords.keywords_pattern.content_regex.search(&input)
        {
            self.start = included_keyword_match.end();
            Some(included_keyword_match.start())
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use crate::proximity_keywords::ProximityKeywordsRegex;
    use regex_automata::meta;

    #[test]
    pub fn test_included_keyword_search() {
        let keywords = super::CompiledIncludedProximityKeywords {
            look_ahead_character_count: 0,
            keywords_pattern: ProximityKeywordsRegex {
                content_regex: meta::Regex::new(r"\b(foo|bar)\b").unwrap(),
                path_regex: meta::Regex::new(r"unused").unwrap(),
            },
        };

        let content = "foo bar duck";
        let mut search = keywords.keyword_matches(content);

        assert_eq!(search.next(), Some(0));
        assert_eq!(search.next(), Some(4));
        assert_eq!(search.next(), None);
    }

    //
    // #[test]
    // fn test_included_keywords_on_start_boundary_with_space_including_word_boundary() {
    //     let keywords =
    //         try_new_compiled_proximity_keyword(7, vec!["id".to_string()], vec![]).unwrap();
    //
    //     let is_false_positive = keywords.is_false_positive_match("users id   ab", None, 11);
    //
    //     assert_eq!(is_false_positive, false);
    // }
    //

    // #[test]
    // fn test_included_keywords_on_start_boundary_with_space() {
    //     let keywords =
    //         try_new_compiled_proximity_keyword(5, vec!["id".to_string()], vec![]).unwrap();
    //
    //     let is_false_positive = keywords.is_false_positive_match("users id   ab", None, 11);
    //
    //     assert_eq!(is_false_positive, false);
    // }

    // #[test]
    // fn test_included_keywords_on_end_boundary() {
    //     let keywords =
    //         try_new_compiled_proximity_keyword(5, vec!["id".to_string()], vec![]).unwrap();
    //
    //     let is_false_positive = keywords.is_false_positive_match("foo idabc", None, 6);
    //
    //     assert_eq!(is_false_positive, true);
    // }

    // #[test]
    // fn test_included_keywords_on_start_boundary() {
    //     let keywords =
    //         try_new_compiled_proximity_keyword(5, vec!["id".to_string()], vec![]).unwrap();
    //
    //     let is_false_positive = keywords.is_false_positive_match("invalid   abc", None, 10);
    //
    //     assert_eq!(is_false_positive, true);
    // }

    // #[test]
    // fn should_look_ahead_too_far() {
    //     let proximity_keywords =
    //         try_new_compiled_proximity_keyword(10, vec!["host".to_string()], vec![]).unwrap();
    //     assert!(proximity_keywords.is_false_positive_match("host 56789012345", None, 15));
    //     assert!(!proximity_keywords.is_false_positive_match("host 56789012345", None, 10));
    //     // prefix `ost 567890` does not contains host
    //     assert!(proximity_keywords.is_false_positive_match("host 56789012345", None, 11));
    //     assert!(!proximity_keywords.is_false_positive_match(" host 6789012345", None, 11));
    //
    //     let proximity_keywords =
    //         try_new_compiled_proximity_keyword(10, vec![], vec!["host".to_string()]).unwrap();
    //     assert!(!proximity_keywords.is_false_positive_match("host 56789012345", None, 15));
    //     assert!(proximity_keywords.is_false_positive_match("host 56789012345", None, 10));
    //     // prefix `ost 567890` does not contains host
    //     assert!(!proximity_keywords.is_false_positive_match("host 56789012345", None, 11));
    //     assert!(proximity_keywords.is_false_positive_match(" host 6789012345", None, 11));
    // }

    // #[test]
    // fn test_included_and_excluded_keyword() {
    //     let (included_keywords, excluded_keywords) =
    //         try_new_compiled_proximity_keyword(
    //         30,
    //         vec!["hey".to_string()],
    //         vec!["hello".to_string()],
    //     )
    //     .unwrap();
    //
    //     // only the included keyword is present
    //     assert!(!proximity_keywords.is_false_positive_match("hey world", None, 6));
    //     // only the excluded keyword is present
    //     assert!(proximity_keywords.is_false_positive_match("hello world", None, 6));
    //     // no keyword is present
    //     assert!(proximity_keywords.is_false_positive_match("world", None, 5));
    //     // included and excluded keywords are present
    //     assert!(!proximity_keywords.is_false_positive_match("hey, hello world", None, 11));
    // }
    //
    // #[test]
    // fn should_detect_on_any_keyword() {
    //     let (included_keywords, excluded_keywords) =
    //         try_new_compiled_proximity_keyword(
    //         30,
    //         vec!["hello".to_string(), "coty".to_string()],
    //         vec![],
    //     )
    //     .unwrap();
    //
    //     assert!(!proximity_keywords.is_false_positive_match("hello world", None, 6));
    //     assert!(!proximity_keywords.is_false_positive_match("hey coty, hello world", None, 16));
    //
    //     assert!(proximity_keywords.is_false_positive_match("hey hey hey world", None, 12));
    //
    //     let (included_keywords, excluded_keywords) =
    //         try_new_compiled_proximity_keyword(
    //         30,
    //         vec![],
    //         vec!["hello".to_string(), "coty".to_string()],
    //     )
    //     .unwrap();
    //
    //     assert!(proximity_keywords.is_false_positive_match("hello world", None, 6));
    //     assert!(proximity_keywords.is_false_positive_match("hey coty, hello world", None, 16));
    //
    //     assert!(!proximity_keywords.is_false_positive_match("hey hey hey world", None, 12));
    // }
    //
    // #[test]
    // fn should_quote_keyword() {
    //     let proximity_keywords =
    //         try_new_compiled_proximity_keyword(30, vec!["he.*o".to_string()], vec![]).unwrap();
    //
    //     assert!(proximity_keywords.is_false_positive_match("hello world", None, 6));
    //     assert!(!proximity_keywords.is_false_positive_match("he.*o world", None, 6));
    //
    //     let proximity_keywords =
    //         try_new_compiled_proximity_keyword(30, vec![], vec!["he.*o".to_string()]).unwrap();
    //
    //     assert!(!proximity_keywords.is_false_positive_match("hello world", None, 6));
    //     assert!(proximity_keywords.is_false_positive_match("he.*o world", None, 6));
    // }
    //
    // #[test]
    // fn keywords_should_be_case_insensitive() {
    //     let proximity_keywords =
    //         try_new_compiled_proximity_keyword(30, vec!["hello".to_string()], vec![]).unwrap();
    //
    //     assert!(!proximity_keywords.is_false_positive_match("hello world", None, 6));
    //     assert!(!proximity_keywords.is_false_positive_match("HELLO world", None, 6));
    //
    //     let proximity_keywords =
    //         try_new_compiled_proximity_keyword(30, vec![], vec!["hello".to_string()]).unwrap();
    //
    //     assert!(proximity_keywords.is_false_positive_match("hello world", None, 6));
    //     assert!(proximity_keywords.is_false_positive_match("HELLO world", None, 6));
    // }
    //
    // #[test]
    // fn included_keyword_should_have_word_boundaries() {
    //     let proximity_keywords =
    //         try_new_compiled_proximity_keyword(30, vec!["host".to_string()], vec![]).unwrap();
    //     assert!(!proximity_keywords.is_false_positive_match("host ping", None, 5));
    //     assert!(proximity_keywords.is_false_positive_match("localhost ping", None, 10));
    //     assert!(proximity_keywords.is_false_positive_match("hostlocal ping", None, 10));
    //
    //     // word boundaries are is added at the beginning (resp. end) only if the first (resp. last) character is a letter or a digit
    //     let proximity_keywords =
    //         try_new_compiled_proximity_keyword(30, vec!["-host".to_string()], vec![]).unwrap();
    //     assert!(!proximity_keywords.is_false_positive_match("-host- ping", None, 6));
    //     assert!(!proximity_keywords.is_false_positive_match("local-host ping", None, 11));
    //     assert!(proximity_keywords.is_false_positive_match("-hostlocal ping", None, 11));
    //
    //     let proximity_keywords =
    //         try_new_compiled_proximity_keyword(30, vec!["ৎhost".to_string()], vec![]).unwrap();
    //     assert!(!proximity_keywords.is_false_positive_match("ৎhost ping", None, 7));
    //     assert!(!proximity_keywords.is_false_positive_match("localৎhost ping", None, 12));
    // }

    // #[test]
    // fn test_included_keyword_content() {
    //     let (included_keywords, excluded_keywords) =
    //         try_new_compiled_proximity_keyword(30, vec!["hello".to_string()], vec![]).unwrap();
    //
    //     let included_keywords = included_keywords.unwrap();
    //
    //     assert!(!included_keywords.is_false_positive_match("hello world", None, 6));
    //     assert!(!included_keywords.is_false_positive_match("hey, hello world", None, 11));
    //     assert!(included_keywords.is_false_positive_match("world ", None, 5));
    //     assert!(included_keywords.is_false_positive_match("world", None, 0));
    //     assert!(included_keywords.is_false_positive_match("hello world", None, 3));
    // }

    // #[test]
    // fn test_included_keyword_path() {
    //     let (included_keywords, excluded_keywords) =
    //         try_new_compiled_proximity_keyword(
    //         30,
    //         vec![
    //             "aws_access_key_id".to_string(),
    //             "aws-access".to_string(),
    //             "accessKey".to_string(),
    //         ],
    //         vec![],
    //     )
    //     .unwrap();
    //
    //     // Should match
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match(
    //             "",
    //             Some("aws.access.key.id".to_string()),
    //             0,
    //         ),
    //         false
    //     );
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match("", Some("aws.access.key".to_string()), 0),
    //         false
    //     );
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match("", Some("aws.access.keys".to_string()), 0),
    //         false
    //     );
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match("", Some("aws.access%key".to_string()), 0),
    //         false
    //     );
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match(
    //             "",
    //             Some("aws.access.key.identity".to_string()),
    //             0,
    //         ),
    //         false
    //     );
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match(
    //             "",
    //             Some("access.key.aws.another.long.keyword".to_string()),
    //             0,
    //         ),
    //         false
    //     );
    //
    //     // Should not match
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match("", Some("aws.key".to_string()), 0),
    //         true
    //     );
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match("", Some("key".to_string()), 0),
    //         true
    //     );
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match("", Some("aws.app.key".to_string()), 0),
    //         true
    //     );
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match("", Some("aws.accessible".to_string()), 0),
    //         true
    //     );
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match("", Some("access#key".to_string()), 0),
    //         true
    //     );
    //     assert_eq!(
    //         proximity_keywords.is_false_positive_match("", Some("key.access.aws".to_string()), 0),
    //         true
    //     );
    // }
}
