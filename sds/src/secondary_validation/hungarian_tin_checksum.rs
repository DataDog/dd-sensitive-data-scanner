use crate::secondary_validation::Validator;

pub struct HungarianTinChecksum;
const WEIGHTS: &[u32] = &[1, 2, 3, 4, 5, 6, 7, 8, 9];

impl Validator for HungarianTinChecksum {
    // https://ec.europa.eu/taxation_customs/tin/#/check-tin
    // 10 digits, last digit is a checksum
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut numbers = regex_match.chars().filter_map(|c| c.to_digit(10));

        let sum: u32 = numbers
            .by_ref()
            .take(WEIGHTS.len())
            .zip(WEIGHTS.iter())
            .map(|(number, weight)| number * weight)
            .sum();

        if let Some(actual_checksum) = numbers.next() {
            let computed_checksum = sum % 11;
            computed_checksum == actual_checksum
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_match() {
        let validator = HungarianTinChecksum;
        assert!(validator.is_valid_match("8234567896"));
        assert!(validator.is_valid_match("2234567890"));
        assert!(validator.is_valid_match("223-456-789-0"));
    }

    #[test]
    fn test_invalid_match() {
        let validator = HungarianTinChecksum;
        assert!(!validator.is_valid_match("1234567891"));
        assert!(!validator.is_valid_match("223456789"));
    }
}
