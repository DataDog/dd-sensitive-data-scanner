use crate::secondary_validation::Validator;

pub struct FranceSsnChecksum;

const FRANCE_SSN_LENGTH: usize = 15;
const FRANCE_SSN_CONTROL_KEY_LENGTH: usize = 2;
const FRANCE_SSN_FIRST_VALUE_LENGTH: usize = FRANCE_SSN_LENGTH - FRANCE_SSN_CONTROL_KEY_LENGTH;

const FRANCE_SSN_CHECKSUM_MODULUS: i64 = 97;

impl Validator for FranceSsnChecksum {
    // https://en.wikipedia.org/wiki/INSEE_code
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Remove possible whitespace or '-' from SSN
        let mut valid_chars = regex_match
            .chars()
            .filter(|c| c.is_ascii_digit() || matches!(c, 'a' | 'A' | 'b' | 'B'));

        if valid_chars.clone().count() != FRANCE_SSN_LENGTH {
            return false;
        }

        // Calculate the value of the first 13 alphanumeric characters
        let mut first_value: i64 = 0;
        let mut penalties: i64 = 0;
        for c in valid_chars.by_ref().take(FRANCE_SSN_FIRST_VALUE_LENGTH) {
            if let Some(digit) = c.to_digit(10) {
                first_value = first_value * 10 + digit as i64;
            } else {
                // Some department codes contain an 'A' or 'B'.
                // In that case, replace 'A' or 'B' with '0' and, based on if it was
                // the letter 'A' or 'B', subtract 1000000 or 2000000, respectively.
                // ref: https://xml.insee.fr/schema/nir.html
                first_value *= 10; // push a '0'
                penalties += 1000000;
                if matches!(c, 'b' | 'B') {
                    penalties += 1000000;
                }
            }
        }

        // Calculate the control key from the remaining numerical characters
        let mut control_key: i64 = 0;
        for c in valid_chars.by_ref().take(FRANCE_SSN_CONTROL_KEY_LENGTH) {
            // Control key cannot contain alphabetic characters
            if let Some(digit) = c.to_digit(10) {
                control_key = control_key * 10 + digit as i64;
            } else {
                return false;
            }
        }

        // Calculate checksum
        let final_value = first_value - penalties;

        (FRANCE_SSN_CHECKSUM_MODULUS - final_value % FRANCE_SSN_CHECKSUM_MODULUS) == control_key
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_france_ssn() {
        let valid_ids = vec![
            "2-89-04-78342-163-49",
            "289047834221297",
            "2 89 04 78342 211 01",
            // works with A or B in first number
            "289042A34216390",
            "289042B34216320",
        ];
        for id in valid_ids {
            assert!(FranceSsnChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_france_ssn() {
        let invalid_ids = vec![
            // wrong checksum
            "278056933908923",
            "278056933908997",
            // invalid placement for alphabetic character
            "289042A3421639A",
            // too long
            "2780569339089977",
            // too short
            "27805693390899",
        ];
        for id in invalid_ids {
            assert!(!FranceSsnChecksum.is_valid_match(id));
        }
    }
}
