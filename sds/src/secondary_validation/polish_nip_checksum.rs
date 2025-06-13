use crate::secondary_validation::Validator;

pub struct PolishNipChecksum;

const CHECKSUM_WEIGHTS: &[u32] = &[6, 5, 7, 2, 3, 4, 5, 6, 7];

impl Validator for PolishNipChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut digits = regex_match.chars().filter_map(|c| c.to_digit(10));

        let mut sum = 0;
        for (i, digit) in digits.by_ref().take(CHECKSUM_WEIGHTS.len()).enumerate() {
            sum += CHECKSUM_WEIGHTS[i] * digit;
        }

        if let Some(actual_checksum) = digits.next() {
            return sum % 11 == actual_checksum;
        }
        false
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_polish_nip() {
        let validator = PolishNipChecksum;
        assert!(validator.is_valid_match("8333290827"));
        assert!(validator.is_valid_match("3928621931"));
        assert!(validator.is_valid_match("392-862-19-31"));
        assert!(validator.is_valid_match("392-86-21-931"));
        assert!(validator.is_valid_match("PL3928621931"));
        assert!(validator.is_valid_match("PL🙏3928621931"));
    }

    #[test]
    fn test_invalid_polish_nip() {
        let validator = PolishNipChecksum;
        assert!(!validator.is_valid_match("3928621933"));
        assert!(!validator.is_valid_match("8333290829"));
        assert!(!validator.is_valid_match("833329082"));
    }
}
