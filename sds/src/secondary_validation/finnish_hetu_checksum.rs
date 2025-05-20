use crate::secondary_validation::Validator;

pub struct FinnishHetuChecksum;

const HETU_LENGTH: usize = 11;
const CONTROL_CHARS: &str = "0123456789ABCDEFHJKLMNPRSTUVWXY";

impl Validator for FinnishHetuChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        /*
         * Finnish personal identification numbers (HETU) format:
         * DDMMYYCZZZQ where:
         * - DDMMYY is the date of birth
         * - C is the century marker (-, +, A-F, U-Y)
         * - ZZZ is the individual number (002-899 for regular, 900-999 for temporary)
         * - Q is the control character
         */
        if regex_match.len() != HETU_LENGTH {
            return false;
        }

        // Remove the optional spaces for processing
        let processed_match = regex_match.replace(' ', "");
        if processed_match.len() != HETU_LENGTH {
            return false;
        }

        // Split the components
        let date_part = &processed_match[..6];
        let century_marker = processed_match.chars().nth(6).unwrap();
        let individual_number = &processed_match[7..10];
        let control_char = processed_match.chars().last().unwrap();

        // Validate date part (DDMMYY)
        if !date_part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        // Validate century marker, the law (https://vm.fi/paatos?decisionId=0900908f807c5f3c) mention the following syntax
        // For those born on January 1, 2000, or later, the separator used is the letter A, B, C, D, E, or F; for those born in the 1900s, a hyphen (-) or the letter Y, X, W, V, or U is used; and for those born in the 1800s, a plus sign (+) is used.
        if !matches!(century_marker, '-' | '+' | 'A'..='F' | 'U'..='Y') {
            return false;
        }

        // Validate individual number
        if !individual_number.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        // Validate control character
        if !CONTROL_CHARS.contains(control_char.to_ascii_uppercase()) {
            return false;
        }

        // Calculate the numeric value for checksum
        let numeric_value = format!("{}{}", date_part, individual_number);
        let numeric_value: u32 = numeric_value.parse().unwrap();

        // Calculate the expected control character
        let remainder = numeric_value % 31;
        let expected_control = CONTROL_CHARS.chars().nth(remainder as usize).unwrap();

        control_char.to_ascii_uppercase() == expected_control
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_finnish_hetu() {
        let valid_hetus = vec![
            "010101-0101", // Example from documentation
            "111111-111C", // Example from documentation
            "010101Y0101", // Century marker Y
        ];

        for hetu in valid_hetus {
            println!("Finnish HETU: {}", hetu);
            assert!(FinnishHetuChecksum.is_valid_match(hetu));

            // Test with invalid control character
            let mut invalid_hetu = hetu[..10].to_string();
            invalid_hetu.push('X'); // Invalid control character
            println!(
                "Finnish HETU with invalid control character: {}",
                invalid_hetu
            );
            assert!(!FinnishHetuChecksum.is_valid_match(&invalid_hetu));
        }

        // Test invalid formats
        let invalid_formats = vec![
            "111111-111X",  // Invalid control character
            "111111G111C",  // Invalid century marker
            "010101-0102",  // Invalid individual number checksum
            "111311-111C",  // Invalid individual number checksum
            "010101-1010",  // Invalid individual number checksum
            "111111-111",   // Too short
            "111111-11111", // Too long
            "111111--111C", // Double hyphen
        ];

        for hetu in invalid_formats {
            println!("Invalid format HETU: {}", hetu);
            assert!(!FinnishHetuChecksum.is_valid_match(hetu));
        }
    }
}
