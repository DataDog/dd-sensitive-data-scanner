use crate::secondary_validation::Validator;
use crate::secondary_validation::non_hex_checker::NonHexChecker;
use crate::secondary_validation::token_efficiency::TokenEfficiencyCheck;

/// Combines `NonHexChecker` and `TokenEfficiencyCheck`: a match must contain a non-hex
/// character AND be token-inefficient to be considered a valid secret.
///
/// Running both checks together lets a single rule drop pure-hex substrings and natural
/// language/identifiers without declaring two separate secondary validators.
pub struct NonHexPlusTokenEfficiencyChecker {
    token_efficiency_check: TokenEfficiencyCheck,
}

impl NonHexPlusTokenEfficiencyChecker {
    pub fn new() -> Self {
        Self {
            token_efficiency_check: TokenEfficiencyCheck::new(),
        }
    }
}

impl Default for NonHexPlusTokenEfficiencyChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl Validator for NonHexPlusTokenEfficiencyChecker {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        NonHexChecker.is_valid_match(regex_match)
            && self.token_efficiency_check.is_valid_match(regex_match)
    }
}

#[cfg(test)]
mod tests {
    use crate::secondary_validation::Validator;
    use crate::secondary_validation::non_hex_plus_token_efficiency_checker::NonHexPlusTokenEfficiencyChecker;

    #[test]
    fn rejects_pure_hex_even_if_token_inefficient() {
        // A random-looking hex string is token-inefficient, but pure hex must still be rejected.
        assert!(
            !NonHexPlusTokenEfficiencyChecker::new()
                .is_valid_match("0123456789abcdef0123456789abcdef")
        );
    }

    #[test]
    fn rejects_non_hex_natural_language() {
        // Contains non-hex characters (spaces), but reads as natural language.
        assert!(
            !NonHexPlusTokenEfficiencyChecker::new()
                .is_valid_match("this is a normal sentence with common words")
        );
    }

    #[test]
    fn accepts_non_hex_token_inefficient_secret() {
        assert!(
            NonHexPlusTokenEfficiencyChecker::new()
                .is_valid_match("sk_live_SOKXxs00k30PUuH4KLoDPNmwlQ4EwXKw")
        );
    }

    #[test]
    fn rejects_non_hex_camel_case_identifier() {
        assert!(
            !NonHexPlusTokenEfficiencyChecker::new()
                .is_valid_match("LibraryWebpageUploadUr1RowStatus")
        );
    }
}
