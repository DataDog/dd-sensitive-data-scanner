use crate::secondary_validation::Validator;

pub struct FranceSsnChecksum;

const FRANCE_SSN_LENGTH: u8 = 15;
const FRANCE_SSN_CONTROL_KEY_LENGTH: u8 = 2;
const FRANCE_SSN_FIRST_VALUE_LENGTH: u8 = FRANCE_SSN_LENGTH - FRANCE_SSN_CONTROL_KEY_LENGTH;

impl Validator for FranceSsnChecksum {
    // https://en.wikipedia.org/wiki/INSEE_code
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut first_value: i64 = 0;
        let mut control_key: i64 = 0;
        let mut count: u8 = 0;
        let mut penalties: i64 = 0;

        for c in regex_match.chars() {
            if c.is_ascii_digit() || matches!(c, 'a' | 'A' | 'b' | 'B') {
                // Calculate the value of the first 13 alphanumeric characters
                if count < FRANCE_SSN_FIRST_VALUE_LENGTH {
                    count += 1;
                    if let Some(digit) = c.to_digit(10) {
                        first_value = first_value * 10 + digit as i64;
                    } else {
                        // Some department codes contain an 'A' or 'B'.
                        // In that case, replace 'A' or 'B' with '0' and, based on if it was the letter 'A' or 'B',
                        // subtract 1000000 or 2000000, respectively.
                        // ref: https://xml.insee.fr/schema/nir.html
                        first_value *= 10; // push a '0'
                        penalties += 1000000;
                        if matches!(c, 'b' | 'B') {
                            penalties += 1000000;
                        }
                    }
                // Calculate the control key from the remaining numerical characters
                } else if count < FRANCE_SSN_LENGTH {
                    if let Some(digit) = c.to_digit(10) {
                        count += 1;
                        control_key = control_key * 10 + digit as i64;
                    }
                // Incorrect length for French SSN
                } else {
                    return false;
                }
            }
        }
        if count != FRANCE_SSN_LENGTH {
            return false;
        }

        let final_value = first_value - penalties;

        (97 - final_value % 97) == control_key
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
