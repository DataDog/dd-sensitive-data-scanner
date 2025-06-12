use crate::secondary_validation::Validator;

pub struct GreekTinChecksum;

const GREEK_TIN_LENGTH: usize = 9;

impl Validator for GreekTinChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut digits = regex_match.chars().filter_map(|c| c.to_digit(10));

        let sum = digits
            .by_ref()
            .take(GREEK_TIN_LENGTH - 1)
            .fold(0, |acc, digit| acc * 2 + digit);

        if let Some(actual_checksum) = digits.next() {
            return ((sum * 2) % 11) % 10 == actual_checksum;
        }
        false
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
        assert!(validator.is_valid_match("982-603-151"));
        assert!(validator.is_valid_match("982.603.151"));
        assert!(validator.is_valid_match("982🙏603151"));
    }

    #[test]
    fn test_invalid_greek_tin() {
        let validator = GreekTinChecksum;

        assert!(!validator.is_valid_match("982603152"));
        assert!(!validator.is_valid_match("833329083"));
        assert!(!validator.is_valid_match("094259217"));
        // too short
        assert!(!validator.is_valid_match("9826031"));
    }
}
