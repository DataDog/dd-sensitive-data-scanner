pub struct SlovenianPINChecksum;
use crate::secondary_validation::Validator;

const SLOVENIAN_PIN_LENGTH: usize = 13;

impl Validator for SlovenianPINChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        /*
         * Slovenian Persional Identification Number uses a 13-digit identification code,
         * consisting of the birth date formatted as YYYYMMDD followed by a number XXX
         * ensuring persons born on the same date have a unique national ID,
         * then a first check on YYYYMMDDXXX using the Luhn10 algorithm,
         * and finally a check on YYYYMMDDXXX using the Verhoeff algorithm.
         */
        if regex_match.len() != SLOVENIAN_PIN_LENGTH {
            return false;
        }

        let mut digits = [0; 13];

        for (i, char) in regex_match.chars().enumerate() {
            match char.to_digit(10) {
                Some(digit) => {
                    digits[i] = digit;
                }
                None => return false,
            }
        }

        let m = 11
            - (7 * (digits[0] + digits[6])
                + 6 * (digits[1] + digits[7])
                + 5 * (digits[2] + digits[8])
                + 4 * (digits[3] + digits[9])
                + 3 * (digits[4] + digits[10])
                + 2 * (digits[5] + digits[11]))
                % 11;

        let mut k = m;
        if k == 10 || k == 1 {
            k = 0;
        }

        k == digits[12]
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_slovenian_pins() {
        let slovenian_pins = vec!["0101006500006"];
        for pin in slovenian_pins {
            assert!(SlovenianPINChecksum.is_valid_match(pin));
        }
    }

    #[test]
    fn test_invalid_slovenian_pins() {
        let invalid_slovenian_pins = vec!["0101006500007"];
        for pin in invalid_slovenian_pins {
            assert!(!SlovenianPINChecksum.is_valid_match(pin));
        }
    }
}
