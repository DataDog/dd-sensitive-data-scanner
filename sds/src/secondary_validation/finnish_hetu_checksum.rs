use crate::secondary_validation::Validator;

pub struct FinnishHetuChecksum;

const CONTROL_CHARS: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'H', 'J', 'K',
    'L', 'M', 'N', 'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
];

impl Validator for FinnishHetuChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // https://en.wikipedia.org/wiki/National_identification_number#Finland
        let mut processed_match = regex_match
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '+');
        // Split the components
        let date_part = processed_match.by_ref().take(6).collect::<String>();
        let individual_number = processed_match.by_ref().skip(1).take(3).collect::<String>();
        let control_char = match processed_match.next() {
            Some(c) => c,
            None => return false,
        };

        let numeric_value = format!("{date_part}{individual_number}");
        let numeric_value = match numeric_value.parse::<usize>() {
            Ok(value) => value,
            Err(_) => return false,
        };

        // Calculate the expected control character
        let remainder = numeric_value % 31;
        if let Some(expected_control) = CONTROL_CHARS.get(remainder) {
            return control_char == expected_control.to_ascii_uppercase();
        }
        false
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
            println!("Finnish HETU: {hetu}");
            assert!(FinnishHetuChecksum.is_valid_match(hetu));

            // Test with invalid control character
            let mut invalid_hetu = hetu[..10].to_string();
            invalid_hetu.push('X'); // Invalid control character
            println!(
                "Finnish HETU with invalid control character: {invalid_hetu}"
            );
            assert!(!FinnishHetuChecksum.is_valid_match(&invalid_hetu));
        }

        // Test invalid formats
        let invalid_formats = vec![
            "111111-111X",  // Invalid control character
            "010101-0102",  // Invalid individual number checksum
            "111311-111C",  // Invalid individual number checksum
            "010101-1010",  // Invalid individual number checksum
            "111111-111",   // Too short
            "111111-11111", // Too long
            "111111--111C", // Double hyphen
        ];

        for hetu in invalid_formats {
            println!("Invalid format HETU: {hetu}");
            assert!(!FinnishHetuChecksum.is_valid_match(hetu));
        }
    }
}
