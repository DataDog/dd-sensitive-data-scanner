use crate::secondary_validation::{get_next_digit, Validator};

pub struct UsNpiChecksum;

impl Validator for UsNpiChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // uses Luhn formula with a 80840 health industry prefix
        let mut chars = regex_match.chars();

        let mut sum = 24u32; // constant for 80840 prefix
        let mut is_doubled = true;

        for _ in 0..9 {
            let digit = match get_next_digit(&mut chars) {
                Some(d) => d,
                None => return false,
            };

            if is_doubled {
                sum += if digit > 4 { digit * 2 - 9 } else { digit * 2 };
            } else {
                sum += digit;
            }
            is_doubled = !is_doubled;
        }

        let actual_check = match get_next_digit(&mut chars) {
            Some(d) => d,
            None => return false,
        };

        if get_next_digit(&mut chars).is_some() {
            return false; // too many digits
        }

        let expected_check = (10 - (sum % 10)) % 10;
        expected_check == actual_check
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_npi() {
        let validator = UsNpiChecksum;
        assert!(validator.is_valid_match("1234567893"));
        assert!(validator.is_valid_match("1111111112"));
        assert!(validator.is_valid_match("0000000006"));
        assert!(validator.is_valid_match("9999999995"));
    }

    #[test]
    fn test_invalid_npi_wrong_checksum() {
        let validator = UsNpiChecksum;
        assert!(!validator.is_valid_match("1234567890"));
        assert!(!validator.is_valid_match("1234567891"));
        assert!(!validator.is_valid_match("1234567892"));
    }

    #[test]
    fn test_invalid_npi_wrong_length() {
        let validator = UsNpiChecksum;
        assert!(!validator.is_valid_match("123456789")); // too short
        assert!(!validator.is_valid_match("12345678901")); // too long
    }
}
