use crate::secondary_validation::Validator;

pub struct DutchPassportChecksum;

// ICAO 9303 algorithm weights
const WEIGHTS: &[u32] = &[7, 3, 1, 7, 3, 1, 7, 3];

impl Validator for DutchPassportChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut chars = regex_match.chars().filter(|c| c.is_ascii_alphanumeric());

        // Calculate weighted sum
        // A-N = 10-23, P-Z = 24-35
        let mut sum = 0;
        for (c, weight) in chars.by_ref().take(WEIGHTS.len()).zip(WEIGHTS.iter()) {
            let upper = c.to_ascii_uppercase();
            let value = match upper.to_digit(10) {
                Some(value) => value,
                None => upper as u32 - 'A' as u32 + 10,
            };
            sum += value * weight;
        }

        if let Some(checksum) = chars.next().map(|c| c.to_digit(10)).flatten() {
            return checksum == sum % 10;
        }
        false
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
