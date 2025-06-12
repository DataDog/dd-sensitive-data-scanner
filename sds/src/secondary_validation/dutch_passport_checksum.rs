use crate::secondary_validation::Validator;

pub struct DutchPassportChecksum;

const DUTCH_PASSPORT_LENGTH: usize = 9;
// ICAO 9303 algorithm weights
const WEIGHTS: &[u32] = &[7, 3, 1, 7, 3, 1, 7, 3];

impl Validator for DutchPassportChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut chars = regex_match.chars().filter(|c| c.is_ascii_alphanumeric());

        /*
         * Dutch passport numbers are 9 characters long:
         * - First two characters are letters from A-N or P-Z (excluding O)
         * - Next 6 characters can be either digits or letters from A-N or P-Z (excluding O)
         * - Last character is a checksum digit calculated using the ICAO 9303 algorithm
         */
        if chars.clone().count() != DUTCH_PASSPORT_LENGTH {
            return false;
        }

        let checksum = chars.next_back().unwrap().to_digit(10).unwrap();

        // Calculate weighted sum
        // A-N = 10-23, P-Z = 24-35
        let mut sum = 0;
        for (c, weight) in chars.take(WEIGHTS.len()).zip(WEIGHTS.iter()) {
            let upper = c.to_ascii_uppercase();
            let value = if upper.is_ascii_digit() {
                upper.to_digit(10).unwrap()
            } else {
                upper as u32 - 'A' as u32 + 10
            };
            sum += value * weight;
        }

        checksum == sum % 10
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_dutch_passport_numbers() {
        let valid_passports = vec![
            "XR1001R58", // Example valid passport number
        ];

        for passport in valid_passports {
            println!("Dutch passport number: {}", passport);
            assert!(DutchPassportChecksum.is_valid_match(passport));
        }

        // Test invalid formats
        let invalid_formats = vec![
            "XR1001R57", // Invalid checksum
        ];

        for passport in invalid_formats {
            println!("Invalid format passport number: {}", passport);
            assert!(!DutchPassportChecksum.is_valid_match(passport));
        }
    }
}
