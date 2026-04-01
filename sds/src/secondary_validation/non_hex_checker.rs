use crate::secondary_validation::Validator;

/// Accepts matches that contain at least one character outside `[0-9a-fA-F]`.
///
/// Useful to drop pure hexadecimal substrings (for example hashes or UUIDs without separators)
/// while keeping tokens that use a wider alphabet (base64, prefixes, punctuation, etc.).
pub struct NonHexChecker;

impl Validator for NonHexChecker {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        regex_match.chars().any(|c| !c.is_ascii_hexdigit())
    }
}

#[cfg(test)]
mod tests {
    use crate::secondary_validation::Validator;
    use crate::secondary_validation::non_hex_checker::NonHexChecker;

    #[test]
    fn rejects_pure_hex() {
        for input in [
            "",
            "a",
            "deadbeef",
            "DEADBEEF0123456789",
            "0123456789abcdef",
            "AbCdEf0123456789",
        ] {
            assert!(
                !NonHexChecker.is_valid_match(input),
                "expected pure hex or empty to be rejected: {input:?}"
            );
        }
    }

    #[test]
    fn accepts_when_any_non_hex_present() {
        for input in [
            "g",
            "0g",
            "sk_live_abc",
            "abc-def",
            "ff_FF", // underscore is not hex
            "日本",
        ] {
            assert!(
                NonHexChecker.is_valid_match(input),
                "expected non-hex character to accept: {input:?}"
            );
        }
    }
}
