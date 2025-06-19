use crate::secondary_validation::Validator;
pub struct RodneCisloNumberChecksum;

const MODULO: u32 = 11;
impl Validator for RodneCisloNumberChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Convert string to vector of digits
        let digits = regex_match
            .chars()
            .filter_map(|c| c.to_digit(10))
            .collect::<Vec<_>>();

        // For numbers before year 1954, the length can be 9 digits & there is no checksum
        if digits.len() == 9 {
            let year = digits.iter().take(2).fold(0, |acc, digit| acc * 10 + digit);
            return year < 54;
        }

        let mut digits = digits.iter();
        // Take the first 9 digits and convert them to a single integer
        let first_nine_digits: u32 = digits
            .by_ref()
            .take(9)
            .fold(0, |acc, digit| acc * 10 + digit);

        if let Some(checksum) = digits.next() {
            let remainder = first_nine_digits % MODULO % 10;
            return *checksum == remainder;
        }
        false
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::rodne_cislo_checksum::RodneCisloNumberChecksum;
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_pps() {
        let valid = vec![
            "6809115566",
            "9811150570",
            "9811150570",
            // // old format
            // "320911556",
            // "123456789",
        ];
        for example in valid {
            assert!(RodneCisloNumberChecksum.is_valid_match(example));
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
            assert!(!RodneCisloNumberChecksum.is_valid_match(example));
        }
    }
}
