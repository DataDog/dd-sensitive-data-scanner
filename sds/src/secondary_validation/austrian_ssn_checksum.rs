use crate::secondary_validation::Validator;

pub struct AustrianSSNChecksum;

const AUSTRIAN_SSN_MULTIPLIERS: [u32; 10] = [3, 7, 9, 0, 5, 8, 4, 2, 1, 6];

impl Validator for AustrianSSNChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut chars = regex_match
            .chars()
            .filter_map(|c| c.to_digit(10))
            .enumerate();

        let mut sum = 0;
        let mut actual_check_digit: u32 = 11;
        for w in AUSTRIAN_SSN_MULTIPLIERS.iter() {
            match chars.next() {
                Some((i, digit)) => {
                    if i == 0 && digit == 0 {
                        return false;
                    } else if i == 3 {
                        actual_check_digit = digit; // Extract checksum: Fourth number
                    }

                    sum += digit * w
                }
                None => return false,
            }
        }

        // Check if there is more than 10 characters
        if let Some((_, _)) = chars.next() {
            return false;
        }

        let expected_check_digit = sum % 11;

        if actual_check_digit == expected_check_digit {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_ssn() {
        let valid_ssns = [
            "1237010180",  // valid January 01, 1980
            "1237-010180", // valid January 01, 1980
        ];
        let validator = AustrianSSNChecksum;
        for ssn in &valid_ssns {
            assert!(validator.is_valid_match(ssn), "SSN should be valid: {ssn}");
        }
    }

    #[test]
    fn test_invalid_ssn() {
        let invalid_ssns = [
            "a236010180",  // wrong char a
            "1236010180",  // wrong check digit 6
            "12370101801", // wrong length (11 != 10)
            "",            // wrong length (0 != 10)
            "1623",        // wrong length (4 != 10)
            "2230010180",  // impossible serial number since check digit is 10
            "0234010180",  // invalid January 01, 1980 since the first character could never be 0
        ];
        let validator = AustrianSSNChecksum;
        for ssn in &invalid_ssns {
            assert!(
                !validator.is_valid_match(ssn),
                "SSN should be invalid: {ssn}"
            );
        }
    }
}
