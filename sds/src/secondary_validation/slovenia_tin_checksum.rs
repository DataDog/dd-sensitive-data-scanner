use crate::secondary_validation::{Validator, validate_mod11_weighted_checksum};

const WEIGHTS: &[u32; 7] = &[7, 6, 5, 4, 3, 2, 1];

pub struct SloveniaTinChecksum;

impl Validator for SloveniaTinChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        validate_mod11_weighted_checksum(regex_match, WEIGHTS, |remainder| match remainder {
            0 => Some(0),
            1 => None, // remainder 1 means invalid TIN
            _ => Some(11 - remainder),
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_slovenia_tin() {
        let validator = SloveniaTinChecksum;
        assert!(validator.is_valid_match("95985352"));
        assert!(validator.is_valid_match("15012554"));
        assert!(validator.is_valid_match("12345674"));
        assert!(validator.is_valid_match("98765432"));
    }

    #[test]
    fn test_invalid_slovenia_tin_wrong_checksum() {
        let validator = SloveniaTinChecksum;
        assert!(!validator.is_valid_match("95985353"));
        assert!(!validator.is_valid_match("15012555"));
        assert!(!validator.is_valid_match("12345675"));
    }

    #[test]
    fn test_invalid_slovenia_tin_remainder_one() {
        let validator = SloveniaTinChecksum;
        // TINs with remainder 1 are invalid
        assert!(!validator.is_valid_match("10000009"));
    }

    #[test]
    fn test_invalid_slovenia_tin_too_short() {
        let validator = SloveniaTinChecksum;
        assert!(!validator.is_valid_match("9598535"));
        assert!(!validator.is_valid_match("123456"));
    }

    #[test]
    fn test_invalid_slovenia_tin_too_long() {
        let validator = SloveniaTinChecksum;
        assert!(!validator.is_valid_match("959853520"));
    }
}
