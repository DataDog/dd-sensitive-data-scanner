use crate::secondary_validation::Validator;
pub struct SlovakPersonalIdentificationNumberChecksum;

impl Validator for SlovakPersonalIdentificationNumberChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Convert string to vector of digits
        let digits: Vec<u32> = regex_match.chars().filter_map(|c| c.to_digit(10)).collect();

        // For numbers before year 1954, the length can be 9 digits
        if digits.len() == 9 {
            let year = digits
                .iter()
                .take(2)
                .fold(0, |acc, &digit| acc * 10 + digit);

            if year < 54 {
                return true;
            }
        }

        if digits.len() != 10 {
            return false;
        }

        // Take the first 9 digits and convert them to a single integer
        let first_nine_digits: u32 = digits
            .iter()
            .take(9)
            .fold(0, |acc, &digit| acc * 10 + digit);

        let check = digits[9];
        let modulo = 11;

        // Calculate the remainder when divided by 11
        let remainder = first_nine_digits % modulo;

        if remainder == 0 {
            // Standard case - modulo 11 equals 0
            check == 0
        } else if remainder == 10 {
            // Special case - remainder is 10 and check digit is 0
            check == 0
        } else {
            // Check digit should equal the remainder
            check == remainder
        }
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::slovakia_pin_checksum::SlovakPersonalIdentificationNumberChecksum;
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_pps() {
        let valid = vec!["6809115566", "9811150570", "9811150570", "320911556"];
        for example in valid {
            assert!(SlovakPersonalIdentificationNumberChecksum.is_valid_match(example));
        }
    }

    #[test]
    fn test_invalid_pps() {
        let invalid = vec![
            // wrong checksum
            "9909116450",
            // wrong length
            "12345678",
            "12345678901",
        ];
        for example in invalid {
            assert!(!SlovakPersonalIdentificationNumberChecksum.is_valid_match(example));
        }
    }
}
