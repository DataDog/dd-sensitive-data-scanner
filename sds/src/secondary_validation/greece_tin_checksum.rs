use crate::secondary_validation::Validator;

pub struct GreekTinChecksum;

const GREEK_TIN_LENGTH: usize = 9;

impl Validator for GreekTinChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        if regex_match.len() != GREEK_TIN_LENGTH {
            return false;
        }

        // Check if the string contains only allowed characters
        if !regex_match.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        // Split into front digits and check digit
        let front = &regex_match[..regex_match.len() - 1];
        let check = regex_match.chars().last().unwrap().to_digit(10).unwrap();

        // Calculate sum by iterating through front digits
        let sum = front
            .chars()
            .map(|c| c.to_digit(10).unwrap())
            .fold(0, |acc, digit| acc * 2 + digit);

        // Calculate expected check digit
        let expected_check = ((sum * 2) % 11) % 10;

        expected_check == check
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_greek_tin() {
        let validator = GreekTinChecksum;

        assert!(validator.is_valid_match("982603151"));
        assert!(validator.is_valid_match("833329082"));
        assert!(validator.is_valid_match("094259216"));
    }

    #[test]
    fn test_invalid_greek_tin() {
        let validator = GreekTinChecksum;

        assert!(!validator.is_valid_match("982603152"));
        assert!(!validator.is_valid_match("833329083"));
        assert!(!validator.is_valid_match("094259217"));
    }
}
