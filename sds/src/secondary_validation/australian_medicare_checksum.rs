use crate::secondary_validation::{Validator, get_next_digit};

pub struct AustralianMedicareChecksum;

// https://curmi.com/australian-health-identifiers/
const WEIGHTS: &[u32; 8] = &[1, 3, 7, 9, 1, 3, 7, 9];

impl Validator for AustralianMedicareChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut chars = regex_match.chars();
        let mut sum: u32 = 0;

        for &weight in WEIGHTS {
            let digit = match get_next_digit(&mut chars) {
                Some(d) => d,
                None => return false,
            };
            sum += digit * weight;
        }

        let checksum_digit = match get_next_digit(&mut chars) {
            Some(d) => d,
            None => return false,
        };

        (sum % 10) == checksum_digit
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_checksum() {
        let validator = AustralianMedicareChecksum;
        let valid = [
            "48867988020",
            "6216795759",
            "437425050",
            "491 937 766 6 5",
            "5826 74635 7/1",
        ];
        for number in valid {
            assert!(validator.is_valid_match(number), "expected valid: {number}");
        }
    }

    #[test]
    fn test_invalid_checksum() {
        let validator = AustralianMedicareChecksum;
        let invalid = [
            "",
            "1",
            "48867988",
            "6216795722",
            "4374 2505 2",
            "6392 2203 A",
        ];
        for number in invalid {
            assert!(
                !validator.is_valid_match(number),
                "expected invalid: {number}"
            );
        }
    }
}
