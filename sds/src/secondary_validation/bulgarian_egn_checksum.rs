use crate::secondary_validation::Validator;

pub struct BulgarianEGNChecksum;

const BULGARIAN_EGN_MULTIPLIERS: [u32; 9] = [2, 4, 8, 5, 10, 9, 7, 3, 6];

impl Validator for BulgarianEGNChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let digits: Vec<u32> = regex_match.chars().filter_map(|c| c.to_digit(10)).collect();

        // calculate sum(chars[i] * BULGARIAN_EGN_MULTIPLIERS[i]) for i in [0,9)
        let sum: u32 = digits
            .iter()
            .take(9)
            .zip(BULGARIAN_EGN_MULTIPLIERS.iter())
            .map(|(d, w)| d * w)
            .sum();

        // The check digit is the last digit of the sum modulo 11, with a special case for 10
        let mut check_digit = sum % 11;
        if check_digit == 10 {
            check_digit = 0;
        }
        digits[9] == check_digit
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_egn() {
        // Ex. valid EGNs taken from https://docs.dataprep.ai/user_guide/clean/clean_bg_egn.html
        let valid_egns = [
            "7523169263", // 1975-23-16, valid
            "8032056031", // 1980-32-05, valid
            "6101057509", // 1961-01-05, valid
            "8001010008", // 1980-01-01, valid
        ];
        let validator = BulgarianEGNChecksum;
        for egn in &valid_egns {
            assert!(
                validator.is_valid_match(egn),
                "EGN should be valid: {}",
                egn
            );
        }
    }

    #[test]
    fn test_invalid_egn() {
        let invalid_egns = [
            "7523169264", // wrong check digit
            "8032056032", // wrong check digit
            "6101057500", // wrong check digit
            "8001010000", // wrong check digit
        ];
        let validator = BulgarianEGNChecksum;
        for egn in &invalid_egns {
            assert!(
                !validator.is_valid_match(egn),
                "EGN should be invalid: {}",
                egn
            );
        }
    }
}
