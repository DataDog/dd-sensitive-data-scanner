use crate::secondary_validation::Validator;

pub struct FranceNifChecksum;

// Regex should filter input without 13 digits, assuming input has 13 digits.
impl Validator for FranceNifChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut valid_chars = regex_match.chars().filter_map(|c| c.to_digit(10)).rev();

        let check = valid_chars
            .by_ref()
            .take(3)
            .enumerate()
            .fold(0, |sum, (idx, digit)| sum + 10_u32.pow(idx as u32) * digit);
        let value = valid_chars
            .by_ref()
            .take(10)
            .enumerate()
            .fold(0, |sum, (idx, digit)| sum + 10_u32.pow(idx as u32) * digit);

        value % 511 == check
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_numbers() {
        let valid_ids = vec![
            "30 23 217 600 053",
            "07 01 987 765 493",
            "07-01😇987.765C493", // Allow any non-digit character
        ];
        for id in valid_ids {
            println!("testing for input {id}");
            assert!(FranceNifChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_numbers() {
        let invalid_ids = vec![
            // wrong check digit
            "30 23 217 600 054",
            // wrong length
            "11111111111111111111111",
            "1",
        ];
        for id in invalid_ids {
            println!("testing for input {id}");
            assert!(!FranceNifChecksum.is_valid_match(id));
        }
    }
}
