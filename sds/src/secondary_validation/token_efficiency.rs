use crate::secondary_validation::Validator;
use tiktoken_rs::cl100k_base_singleton;

// Prose and identifiers merge into long BPE tokens; random secrets do not. Below this many
// characters per token, the value is too incompressible to be natural language.
const MAX_CHARS_PER_TOKEN: f64 = 2.5;

pub struct TokenEfficiencyCheck;

impl TokenEfficiencyCheck {
    pub fn new() -> Self {
        // Build the ~100k-entry cl100k vocabulary now, during scanner construction, so that the
        // first scanned event does not absorb the ~40ms of table building. Rules that do not use
        // this validator never construct one, and so never pay for the vocabulary at all.
        let _ = cl100k_base_singleton();
        Self
    }
}

impl Default for TokenEfficiencyCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for TokenEfficiencyCheck {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let value = regex_match.trim();
        let token_count = cl100k_base_singleton().encode_ordinary(value).len();
        if token_count == 0 {
            return false;
        }
        (value.chars().count() as f64 / token_count as f64) < MAX_CHARS_PER_TOKEN
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::Validator;
    use crate::secondary_validation::token_efficiency::TokenEfficiencyCheck;

    /// Both strings are 32 mixed-case alphanumerics, so a character-frequency measure such as
    /// `EntropyCheck` barely separates them. The BPE vocabulary does: the identifier splits into
    /// a handful of English word pieces, while the random token shatters into many short ones.
    /// This pair is the reason this validator exists - keep it as an explicit test.
    #[test]
    fn separates_random_token_from_camel_case_identifier() {
        assert!(TokenEfficiencyCheck.is_valid_match("SOKXxs00k30PUuH4KLoDPNmwlQ4EwXKw"));
        assert!(!TokenEfficiencyCheck.is_valid_match("LibraryWebpageUploadUr1RowStatus"));
    }

    #[test]
    fn accepts_secret_shaped_values() {
        let valid_inputs = vec![
            "k9V@x2L#q7R!m3T$w8Z%h4N^p1D&y6",
            "d41d8cd98f00b204e9800998ecf8427e",
        ];

        for input in valid_inputs {
            assert!(
                TokenEfficiencyCheck.is_valid_match(input),
                "expected a match for {input}"
            );
        }
    }

    #[test]
    fn rejects_natural_language_and_placeholders() {
        let invalid_inputs = vec![
            "this is a normal sentence with common words",
            "YOUR_API_KEY_GOES_HERE",
            // Short natural input stays rejected without a minimum-length guard, because it is a
            // single token: 3 chars / 1 token is well above the threshold.
            "abc",
        ];

        for input in invalid_inputs {
            assert!(
                !TokenEfficiencyCheck.is_valid_match(input),
                "expected no match for {input}"
            );
        }
    }

    #[test]
    fn ignores_surrounding_whitespace() {
        assert_eq!(
            TokenEfficiencyCheck.is_valid_match("  SOKXxs00k30PUuH4KLoDPNmwlQ4EwXKw  "),
            TokenEfficiencyCheck.is_valid_match("SOKXxs00k30PUuH4KLoDPNmwlQ4EwXKw")
        );
    }

    #[test]
    fn rejects_input_without_tokens() {
        assert!(!TokenEfficiencyCheck.is_valid_match(""));
        assert!(!TokenEfficiencyCheck.is_valid_match("   "));
    }
}
