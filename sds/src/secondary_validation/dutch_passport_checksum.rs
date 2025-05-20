use crate::secondary_validation::{Validator};

pub struct DutchPassportChecksum;

const DUTCH_PASSPORT_LENGTH: usize = 9;

impl Validator for DutchPassportChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        /*
         * Dutch passport numbers are 9 characters long:
         * - First two characters are letters from A-N or P-Z (excluding O)
         * - Next 6 characters can be either digits or letters from A-N or P-Z (excluding O)
         * - Last character is a checksum digit calculated using the ICAO 9303 algorithm
         */
        if regex_match.len() != DUTCH_PASSPORT_LENGTH {
            return false;
        }

        // Check first two characters are valid letters (A-N or P-Z)
        if !regex_match[..2].chars().all(|c| {
            let upper = c.to_ascii_uppercase();
            upper.is_ascii_alphabetic() && upper != 'O'
        }) {
            return false;
        }

        // Check next 6 characters are valid (digits or A-N or P-Z)
        if !regex_match[2..8].chars().all(|c| {
            if c.is_ascii_digit() {
                true
            } else {
                let upper = c.to_ascii_uppercase();
                upper.is_ascii_alphabetic() && upper != 'O'
            }
        }) {
            return false;
        }

        // Last character must be a digit (checksum)
        if !regex_match.chars().last().unwrap().is_ascii_digit() {
            return false;
        }

        // Convert characters to their numeric values for checksum calculation
        // A-N = 10-23, P-Z = 24-35
        let mut numeric_values = Vec::with_capacity(8);
        for c in regex_match[..8].chars() {
            let upper = c.to_ascii_uppercase();
            let value = if upper.is_ascii_digit() {
                upper.to_digit(10).unwrap()
            } else {
                let ascii = upper as u32;
                if ascii <= 'N' as u32 {
                    ascii - 'A' as u32 + 10
                } else {
                    ascii - 'A' as u32 + 11
                }
            };
            numeric_values.push(value);
        }

        let checksum = regex_match.chars().last().unwrap().to_digit(10).unwrap();

        // ICAO 9303 algorithm weights
        let weights = [7, 3, 1, 7, 3, 1, 7, 3];

        // Calculate weighted sum
        let sum: u32 = numeric_values.iter()
            .zip(weights.iter())
            .map(|(&value, &weight)| value * weight)
            .sum();

        // Calculate expected checksum
        let expected_checksum = (10 - (sum % 10)) % 10;

        checksum == expected_checksum
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_dutch_passport_numbers() {
        let valid_passports = vec![
            "XR1001R58", // Example valid passport number
            "NP9876543", // Example valid passport number
            "CD12AB456", // Example valid passport number with mixed letters and numbers
        ];

        for passport in valid_passports {
            println!("Dutch passport number: {}", passport);
            assert!(DutchPassportChecksum.is_valid_match(passport));

            // Test with invalid checksum
            let mut invalid_passport = passport[..8].to_string();
            invalid_passport.push_str(&((passport.chars().last().unwrap().to_digit(10).unwrap() + 1) % 10).to_string());
            println!("Dutch passport number with invalid checksum: {}", invalid_passport);
            assert!(!DutchPassportChecksum.is_valid_match(&invalid_passport));
        }

        // Test invalid formats
        let invalid_formats = vec![
            "XR1001R57", // Invalid checksum
            "A12345678", // Second character is a digit
            "AB12345O8", // Contains 'O' in middle positions
            "AB123456O", // Last character is not a digit
        ];

        for passport in invalid_formats {
            println!("Invalid format passport number: {}", passport);
            assert!(!DutchPassportChecksum.is_valid_match(passport));
        }
    }

    #[test]
    fn test_xr1001r58() {
        let passport = "XR1001R58";
        assert!(DutchPassportChecksum.is_valid_match(passport));
    }
}
