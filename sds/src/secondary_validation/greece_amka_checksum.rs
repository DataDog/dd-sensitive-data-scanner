use crate::secondary_validation::{Validator, get_next_digit};

pub struct GreeceAmkaChecksum;

impl Validator for GreeceAmkaChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut chars = regex_match.chars();

        let mut sum: u32 = 0;
        let mut is_even_position = true;

        // process first 10 digits (YYMMDDXXXXX)
        for _ in 0..10 {
            let digit = match get_next_digit(&mut chars) {
                Some(d) => d,
                None => return false,
            };

            if is_even_position {
                // double even positions (0, 2, 4, 6, 8 - 0-indexed)
                let doubled = digit * 2;
                sum += if doubled > 9 { doubled - 9 } else { doubled };
            } else {
                sum += digit;
            }
            is_even_position = !is_even_position;
        }

        // extract check digit
        let checksum = match get_next_digit(&mut chars) {
            Some(d) => d,
            None => return false,
        };

        if get_next_digit(&mut chars).is_some() {
            return false; // too many digits
        }

        (10 - (sum % 10)) % 10 == checksum
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_amka() {
        let validator = GreeceAmkaChecksum;
        assert!(validator.is_valid_match("91031298765"));
        assert!(validator.is_valid_match("85073003360"));
        assert!(validator.is_valid_match("93050507920"));
        assert!(validator.is_valid_match("00010100017"));
    }

    #[test]
    fn test_invalid_amka_wrong_checksum() {
        let validator = GreeceAmkaChecksum;
        assert!(!validator.is_valid_match("91031298766"));
        assert!(!validator.is_valid_match("82070612345"));
        assert!(!validator.is_valid_match("85073003361"));
    }

    #[test]
    fn test_invalid_amka_too_short() {
        let validator = GreeceAmkaChecksum;
        assert!(!validator.is_valid_match("9103129876"));
        assert!(!validator.is_valid_match("123456789"));
    }
}
