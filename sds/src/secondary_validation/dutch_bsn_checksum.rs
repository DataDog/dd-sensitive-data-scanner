use crate::secondary_validation::Validator;

pub struct DutchDsnChecksum;
const MULTIPLIERS: &[i32] = &[-1, 2, 3, 4, 5, 6, 7, 8, 9];
const MODULO: i32 = 11;

// https://nl.wikipedia.org/wiki/Burgerservicenummer
impl Validator for DutchDsnChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let valid_chars = regex_match.chars().filter(|c| c.is_ascii_alphanumeric());

        let mut sum = 0;
        for (idx, digit) in valid_chars.rev().enumerate() {
            if let Some(digit) = digit.to_digit(10) {
                if let Some(weight) = MULTIPLIERS.get(idx) {
                    sum = (sum + weight * digit as i32) % MODULO;
                    continue;
                }
            }
            return false;
        }

        sum == 0
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_numbers() {
        let valid_ids = vec![
            "001855013",   // RSIN
            "1855013",     // RSIN without leading zeros.
            "1112.22.333", // BSN
            "1112 22 333", // BSN
        ];
        for id in valid_ids {
            println!("testing for input {}", id);
            assert!(DutchDsnChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_numbers() {
        let invalid_ids = vec![
            // wrong checksum
            "001855014",
            // wrong character
            "C001855013",
            // wrong length
            "11111111111111111111111",
            "1",
        ];
        for id in invalid_ids {
            println!("testing for input {}", id);
            assert!(!DutchDsnChecksum.is_valid_match(id));
        }
    }
}
