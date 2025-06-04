pub struct SwedenPINChecksum;
use crate::secondary_validation::{sum_all_digits, Validator};

const MULTIPLIERS: [u32; 9] = [2, 1, 2, 1, 2, 1, 2, 1, 2];


impl Validator for SwedenPINChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        /*
         * Swedish Persional Identification Number uses a 13-digit identification code.
         * The first 9 digits are multiplied by a multiplier from the MULTIPLIERS array.
         * Each product has its digits summed up and added to a total.
         * The total is used to compute a checksum, which is compared to the last digit of the input.
         */
        let valid_chars = regex_match.chars().filter(|c| c.is_ascii_digit());

        let mut total = 0;
        let mut checksum_digit = 0;

        for (index, char) in valid_chars.enumerate() {
            if let Some(digit) = char.to_digit(10) {
                if index == MULTIPLIERS.len() {
                    // We have all the digits we need
                    checksum_digit = digit;
                    break;
                }
                let product = digit * MULTIPLIERS[index];
                total += sum_all_digits(product);
            }
        }

        let checksum = (10 - (total % 10)) % 10;
        checksum == checksum_digit
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_swedish_pins() {
        let swedish_pins = vec!["670919-9530", "811228-9874"];
        for pin in swedish_pins {
            assert!(SwedenPINChecksum.is_valid_match(pin));
        }
    }

    #[test]
    fn test_invalid_swedish_pins() {
        let invalid_swedish_pins = vec!["811228-9873", "670919-9539"];
        for pin in invalid_swedish_pins {
            assert!(!SwedenPINChecksum.is_valid_match(pin));
        }
    }
}
