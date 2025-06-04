use crate::secondary_validation::Validator;
use std::collections::HashMap;

pub struct ItalianNationalIdChecksum;

const ITALIAN_NATIONAL_ID_LENGTH: usize = 16;

use lazy_static::lazy_static;

lazy_static! {
    static ref ODD_CHARACTERS_MAPPING: HashMap<char, u32> = HashMap::from([
        ('0', 1),
        ('1', 0),
        ('2', 5),
        ('3', 7),
        ('4', 9),
        ('5', 13),
        ('6', 15),
        ('7', 17),
        ('8', 19),
        ('9', 21),
        ('A', 1),
        ('B', 0),
        ('C', 5),
        ('D', 7),
        ('E', 9),
        ('F', 13),
        ('G', 15),
        ('H', 17),
        ('I', 19),
        ('J', 21),
        ('K', 2),
        ('L', 4),
        ('M', 18),
        ('N', 20),
        ('O', 11),
        ('P', 3),
        ('Q', 6),
        ('R', 8),
        ('S', 12),
        ('T', 14),
        ('U', 16),
        ('V', 10),
        ('W', 22),
        ('X', 25),
        ('Y', 24),
        ('Z', 23),
    ]);
}

impl Validator for ItalianNationalIdChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let valid_chars = regex_match
            .chars()
            .filter(|c| ODD_CHARACTERS_MAPPING.contains_key(c));

        let mut checksum_char = '0';
        let mut checksum_value = 0;

        for (idx, c) in valid_chars.enumerate() {
            let position = idx + 1;
            if position == ITALIAN_NATIONAL_ID_LENGTH {
                // Skip the last character which is the checksum character
                checksum_char = c;
                break;
            }

            if position % 2 == 1 {
                // In case of odd position, we need to use the mapping to get the checksum value
                checksum_value += ODD_CHARACTERS_MAPPING[&c];
            } else {
                // In case of even position, we need to handle the character differently
                if let Some(digit) = c.to_digit(10) {
                    checksum_value += digit
                } else {
                    // If the character is a letter, add the position of the letter in the alphabet to the checksum value
                    checksum_value += (c as u8 - b'A') as u32;
                }
            }
        }

        let computed_checksum_value = (b'A' + (checksum_value % 26) as u8) as char;

        // Check if the checksum character is correct
        checksum_char == computed_checksum_value
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_italian_national_id() {
        let validator = ItalianNationalIdChecksum;

        assert!(validator.is_valid_match("MRTMTT91D08 F205J"));
        assert!(validator.is_valid_match("MLLSNT82P65-Z404U"));
        assert!(validator.is_valid_match("LKJLDJ/00E20/D635F"));
    }

    #[test]
    fn test_invalid_italian_national_id() {
        let validator = ItalianNationalIdChecksum;

        assert!(!validator.is_valid_match("MRTMTT91D08F205V"));
        assert!(!validator.is_valid_match("MLLSNT82P65Z404T"));
        assert!(!validator.is_valid_match("LKJLDJ00E20D635P"));
    }
}
