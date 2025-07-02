use crate::secondary_validation::Validator;

pub struct SpanishNussChecksum;

const NUMBER_LENGTH: usize = 10;
const CHECKSUM_LENGTH: usize = 2;

impl Validator for SpanishNussChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        /*
         * Spanish Social Security number (NUSS) format:
         * 12 digits total:
         * - First 10 digits are the number
         * - Last 2 digits are the checksum
         * The checksum is calculated using a specific algorithm:
         * 1. Take the first 10 digits as a number
         * 2. Calculate the remainder when divided by 97
         * 3. The checksum is the remainder (2 digits)
         */

        // Check if all characters are digits
        if !regex_match.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        let mut digits_stream = regex_match.chars().filter(|c| c.is_ascii_digit());

        // Parse the number and checksum
        // A 10-digit number does not fit in a u32, u64 is used.
        let number: u64 = if let Ok(x) = digits_stream
            .by_ref()
            .take(NUMBER_LENGTH)
            .collect::<String>()
            .parse()
        {
            x
        } else {
            return false;
        };

        let checksum: u32 = if let Ok(x) = digits_stream
            .take(CHECKSUM_LENGTH)
            .collect::<String>()
            .parse()
        {
            x
        } else {
            return false;
        };

        // Calculate expected checksum
        let expected_checksum = number % 97;
        checksum == (expected_checksum as u32)
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_spanish_nuss() {
        let valid_nuss = vec![
            "281234567840", // Example valid NUSS
            "281294567895", // Example valid NUSS
            "281234577843", // Example valid NUSS
            "981234577887", // Large value that will overflow a u32
        ];

        for nuss in valid_nuss {
            println!("Spanish NUSS: {nuss}");
            assert!(SpanishNussChecksum.is_valid_match(nuss));

            // Test with invalid checksum
            let mut invalid_nuss = nuss[..10].to_string();
            let new_checksum = ((nuss[10..].parse::<u32>().unwrap() + 1) % 100).to_string();
            invalid_nuss.push_str(&format!("{new_checksum:0>2}"));
            println!("Spanish NUSS with invalid checksum: {invalid_nuss}");
            assert!(!SpanishNussChecksum.is_valid_match(&invalid_nuss));
        }

        // Test invalid formats
        let invalid_formats = vec![
            "28123456789",   // Too short
            "2812345678901", // Too long
            "28123456789A",  // Non-digit character
            "281234567890",  // Invalid checksum
        ];

        for nuss in invalid_formats {
            println!("Invalid format NUSS: {nuss}");
            assert!(!SpanishNussChecksum.is_valid_match(nuss));
        }
    }
}
