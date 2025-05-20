use crate::secondary_validation::Validator;

pub struct PolishNipChecksum;

const POLISH_NIP_LENGTH: usize = 10;

const POLISH_NIP_MULTIPLIERS: &[u32] = &[6, 5, 7, 2, 3, 4, 5, 6, 7];

impl Validator for PolishNipChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        if regex_match.len() != POLISH_NIP_LENGTH {
            return false;
        }

        // Check if the string contains only allowed characters
        if !regex_match.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        // Split into front digits and check digit
        let front = &regex_match[..regex_match.len() - 1];
        let check = regex_match.chars().last().unwrap().to_digit(10).unwrap();

        let mut sum = 0;
        // Calculate expected check digit
        for (i, c) in front.chars().enumerate() {
            if let Some(digit) = c.to_digit(10) {
                sum += digit * POLISH_NIP_MULTIPLIERS[i];
            }
        }
        let expected_check = sum % 11;

        expected_check == check
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_polish_nip() {
        let validator = PolishNipChecksum;

        assert!(validator.is_valid_match("3928621931"));
        assert!(validator.is_valid_match("8333290827"));
    }

    #[test]
    fn test_invalid_polish_nip() {
        let validator = PolishNipChecksum;

        assert!(!validator.is_valid_match("3928621933"));
        assert!(!validator.is_valid_match("8333290829"));
    }
}
