use crate::secondary_validation::{Validator, get_next_digit};

pub struct UsDeaChecksum;

impl Validator for UsDeaChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // checksum: (d1 + d3 + d5) + 2 * (d2 + d4 + d6) = sum, check digit = sum % 10
        let mut chars = regex_match.chars();

        let mut odd_sum = 0u32;
        let mut even_sum = 0u32;

        for i in 0..6 {
            let digit = match get_next_digit(&mut chars) {
                Some(d) => d,
                None => return false,
            };
            if i % 2 == 0 {
                odd_sum += digit;
            } else {
                even_sum += digit;
            }
        }

        let actual_check = match get_next_digit(&mut chars) {
            Some(d) => d,
            None => return false,
        };

        if get_next_digit(&mut chars).is_some() {
            return false; // too many digits
        }

        let expected_check = (odd_sum + 2 * even_sum) % 10;
        expected_check == actual_check
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_dea() {
        let validator = UsDeaChecksum;
        assert!(validator.is_valid_match("AB1234563"));
        assert!(validator.is_valid_match("AB0000000"));
        assert!(validator.is_valid_match("AB9999991"));
        assert!(validator.is_valid_match("FA1111119"));
        assert!(validator.is_valid_match("FS1234563"));
        assert!(validator.is_valid_match("MJ1234563"));
    }

    #[test]
    fn test_invalid_dea_wrong_checksum() {
        let validator = UsDeaChecksum;
        assert!(!validator.is_valid_match("AB1234560"));
        assert!(!validator.is_valid_match("AB1234561"));
        assert!(!validator.is_valid_match("AB1234562"));
    }

    #[test]
    fn test_invalid_dea_wrong_length() {
        let validator = UsDeaChecksum;
        assert!(!validator.is_valid_match("AB123456")); // too short
        assert!(!validator.is_valid_match("AB12345678")); // too long
    }
}
