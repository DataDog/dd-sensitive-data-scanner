use crate::secondary_validation::{get_next_digit, Validator};

pub struct PolishNationalIdChecksum;

const MULTIPLIERS: &[u32] = &[1, 3, 7, 9];

impl Validator for PolishNationalIdChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        if regex_match.len() != 11 {
            return false;
        }

        // calculate A×1 + B×3 + C×7 + D×9 + E×1 + F×3 + G×7 + H×9 + I×1 + J×3
        let mut chars = regex_match.chars();
        let mut sum = 0;

        // accumulate the first 10 digits with their respective multipliers
        for i in 0..10 {
            let digit = match get_next_digit(&mut chars) {
                Some(d) => d,
                None => return false,
            };
            sum += digit * MULTIPLIERS[i % 4];
        }

        // the checksum is the last digit of (10 − last digit of the sum)
        let expected_check_digit = (10 - (sum % 10)) % 10;

        // the PESEL number is valid if the checksum matches the last digit of the PESEL
        let actual_check_digit = match get_next_digit(&mut chars) {
            Some(d) => d,
            None => return false,
        };

        if actual_check_digit != expected_check_digit {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_aba_rtn() {
        let valid_ids = vec![
            "12345678903",
            // final digit == 0
            "12345678910",
        ];
        for id in valid_ids {
            assert!(PolishNationalIdChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_aba_rtn() {
        let invalid_ids = vec![
            // wrong checksum
            "12345678901",
            "00000000001",
            "99999999999",
        ];
        for id in invalid_ids {
            assert!(!PolishNationalIdChecksum.is_valid_match(id));
        }
    }
}
