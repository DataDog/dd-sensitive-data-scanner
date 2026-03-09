use crate::secondary_validation::Validator;

pub struct UkNinoFormatCheck;

const INVALID_FIRST: &[char] = &['D', 'F', 'I', 'Q', 'U', 'V'];
const INVALID_SECOND: &[char] = &['D', 'F', 'I', 'O', 'Q', 'U', 'V'];
const INVALID_PREFIXES: &[&str] = &["BG", "GB", "NK", "KN", "NT", "TN", "ZZ"];

const PATTERN_LENGTH: usize = 9;
const PREFIX_LENGTH: usize = 2;
const SUFFIX_INDEX: usize = PATTERN_LENGTH - 1;

impl Validator for UkNinoFormatCheck {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let chars: Vec<char> = regex_match
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .map(|c| c.to_ascii_uppercase())
            .collect();

        if chars.len() != PATTERN_LENGTH {
            return false;
        }

        let c1 = chars[0];
        let c2 = chars[1];

        if !c1.is_ascii_alphabetic() || !c2.is_ascii_alphabetic() {
            return false;
        }

        let prefix: String = chars[..PREFIX_LENGTH].iter().collect();
        let suffix = chars[SUFFIX_INDEX];

        if INVALID_FIRST.contains(&c1)
            || INVALID_SECOND.contains(&c2)
            || INVALID_PREFIXES.contains(&prefix.as_str())
        {
            return false;
        }

        matches!(suffix, 'A'..='D')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_ni_numbers() {
        let validator = UkNinoFormatCheck;

        let valid_numbers = vec!["AB123456C", "AB 12 34 56 C", "ab123456c", "ZY999999D"];
        for number in valid_numbers {
            assert!(
                validator.is_valid_match(number),
                "Expected no error for number {}",
                number
            );
        }
    }

    #[test]
    fn invalid_format() {
        let validator = UkNinoFormatCheck;

        let invalid_numbers = vec!["AB12345C", "AB1234567C", "1B123456C"];
        for number in invalid_numbers {
            assert!(
                !validator.is_valid_match(number),
                "Expected error for number {}",
                number
            );
        }
    }

    #[test]
    fn invalid_prefix_first_letter() {
        let validator = UkNinoFormatCheck;

        for c in INVALID_FIRST {
            let ni = format!("{}B123456A", c);
            assert!(
                !validator.is_valid_match(&ni),
                "Expected error for first letter {}",
                c
            );
        }
    }

    #[test]
    fn invalid_prefix_second_letter() {
        let validator = UkNinoFormatCheck;

        for c in INVALID_SECOND {
            let ni = format!("A{}123456A", c);
            assert!(
                !validator.is_valid_match(&ni),
                "Expected error for second letter {}",
                c
            );
        }
    }

    #[test]
    fn invalid_prefix_combinations() {
        let validator = UkNinoFormatCheck;

        for prefix in INVALID_PREFIXES {
            let ni = format!("{}123456A", prefix);
            assert!(
                !validator.is_valid_match(&ni),
                "Expected error for prefix {}",
                prefix
            );
        }
    }

    #[test]
    fn invalid_suffix() {
        let validator = UkNinoFormatCheck;

        for c in ['E', 'F', 'Z', '1'] {
            let ni = format!("AB123456{}", c);
            assert!(
                !validator.is_valid_match(&ni),
                "Expected error for suffix {}",
                c
            );
        }
    }
}
