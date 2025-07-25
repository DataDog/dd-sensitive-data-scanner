use crate::secondary_validation::{LuhnChecksum, Validator};

pub struct CoordinationNumberChecksum;

const COORDINATION_NUMBER_LENGTH: usize = 10;

impl Validator for CoordinationNumberChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // https://docs.swedenconnect.se/technical-framework/mirror/skv/skv707-2.pdf
        let mut valid_chars: Vec<char> =
            regex_match.chars().filter(|c| c.is_ascii_digit()).collect();

        if valid_chars.len() > COORDINATION_NUMBER_LENGTH {
            // take the last 10 digits
            valid_chars = valid_chars[valid_chars.len() - COORDINATION_NUMBER_LENGTH..].to_vec();
        }

        LuhnChecksum.is_valid_match(valid_chars.iter().collect::<String>().as_str())
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_coordination_number_checksum() {
        let validator = CoordinationNumberChecksum;
        let valid_list = vec!["7010632391", "150882+2390", "210268+2396", "220090+2399"];
        for valid in valid_list {
            assert!(validator.is_valid_match(valid));
        }
        let invalid_list = vec![
            "1234567891",
            "150882+2392",
            "210268-2395",
            "1234567894",
            "1234567895",
        ];
        for invalid in invalid_list {
            assert!(!validator.is_valid_match(invalid));
        }
    }
}
