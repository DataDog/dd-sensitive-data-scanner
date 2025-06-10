use crate::secondary_validation::Validator;
pub struct IrishPpsChecksum;

const WEIGHTS: [u32; 7] = [8, 7, 6, 5, 4, 3, 2];
const MODULUS: u32 = 23;

impl Validator for IrishPpsChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut chars = regex_match.chars().filter(|c| c.is_alphanumeric());

        let mut checksum = 0;

        for (i, c) in chars.by_ref().take(WEIGHTS.len()).enumerate() {
            if let Some(digit) = c.to_digit(10) {
                checksum += digit * WEIGHTS[i];
            } else {
                return false;
            }
        }

        let expected_checksum = match chars.next() {
            Some(c) => convert_to_digit(c),
            None => return false,
        };

        // optional 9th char
        if let Some(c) = chars.next() {
            checksum += 9 * convert_to_digit(c);
        }

        checksum % MODULUS == expected_checksum
    }
}

fn convert_to_digit(c: char) -> u32 {
    if c.eq_ignore_ascii_case(&'W') {
        return 0;
    }
    c.to_ascii_uppercase() as u32 - (b'A' as u32) + 1
}
#[cfg(test)]
mod test {
    use crate::secondary_validation::irish_pps_checksum::IrishPpsChecksum;
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_pps() {
        let valid = vec![
            "1234567FA",
            "1084633RB",
            "6433435FW",
            "1084633WW",
            // Additional character is ignored
            "1084633WWX",
            // Ignore non-alphanumeric characters
            "1234567F/A",
        ];
        for example in valid {
            assert!(IrishPpsChecksum.is_valid_match(example));
        }
    }

    #[test]
    fn test_invalid_pps() {
        let invalid = vec![
            // too short
            "1084633",
            "1234567😊A",
        ];
        for example in invalid {
            assert!(!IrishPpsChecksum.is_valid_match(example));
        }
    }
}
