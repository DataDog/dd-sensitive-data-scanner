use crate::secondary_validation::Validator;
pub struct RomanianPersonalNumericCode;

const CHECKSUM_WEIGHTS: &[u32] = &[2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9];

impl Validator for RomanianPersonalNumericCode {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        if !regex_match.is_ascii() {
            return false;
        }
        for c in regex_match.chars() {
            if !c.is_digit(10) {
                return false;
            }
        }

        let mut calculated_checksum = 0;
        for (i, c) in regex_match.chars().take(12).enumerate() {
            let digit = if let Some(digit) = c.to_digit(10) {
                digit
            } else {
                return false;
            };
            calculated_checksum += CHECKSUM_WEIGHTS[i] * digit;
        }

        calculated_checksum %= 11;
        if calculated_checksum == 10 {
            calculated_checksum = 1;
        }

        let actual_checksum = if let Some(c) = regex_match.chars().last().unwrap().to_digit(10) {
            c
        } else {
            return false;
        };

        println!("Calculated checksum: {}", calculated_checksum);
        calculated_checksum == actual_checksum
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::romanian_personal_numeric_code::RomanianPersonalNumericCode;
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_matches() {
        let valid_matches = vec![
            "1800101221144",
            "1860524161520",
            "1860524161231",
            "1860524162995",
            "1980917400019",
            "5031226529994",
            "6120131011233",
        ];
        for x in valid_matches {
            assert!(RomanianPersonalNumericCode.is_valid_match(x));
        }
    }

    #[test]
    fn test_invalid_matches() {
        let invalid_matches = vec![
            // invalid checksum
            "1960523456789",
            // too short
            "196052345678",
            // too long
            "19605234567890",
            // not digits
            "ABC0523456789",
        ];
        for x in invalid_matches {
            assert!(!RomanianPersonalNumericCode.is_valid_match(x));
        }
    }
}
