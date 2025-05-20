use crate::secondary_validation::Validator;

pub struct HungarianTinChecksum;

impl Validator for HungarianTinChecksum {
    // https://ec.europa.eu/taxation_customs/tin/#/check-tin
    // 10 digits, last digit is a checksum
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let numbers: Vec<u32> = regex_match
            .chars()
            .filter(|c| c.is_ascii_digit())
            .map(|c| c.to_digit(10).unwrap())
            .collect();
        if numbers.len() != 10 {
            return false;
        }
        let sum: u32 = numbers
            .iter()
            .enumerate()
            .filter(|(i, _)| *i < 9)
            .map(|(i, n)| n * (i as u32 + 1))
            .sum();
        let checksum = sum % 11;
        return checksum == numbers[numbers.len() - 1];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_match() {
        let validator = HungarianTinChecksum;
        assert!(validator.is_valid_match("8234567896"));
        assert!(!validator.is_valid_match("1234567891"));
    }
}
