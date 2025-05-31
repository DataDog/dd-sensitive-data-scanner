use crate::secondary_validation::Validator;
pub struct IrishPpsChecksum;

impl Validator for IrishPpsChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut chars = regex_match.chars();
        if chars.clone().any(|c| !c.is_alphanumeric()) {
            return false;
        }

        // all chars are ASCII so byte len is valid here
        if regex_match.len() < 8 {
            return false;
        }

        let mut checksum = 0;

        let weights = [8, 7, 6, 5, 4, 3, 2];
        for (i, c) in chars.by_ref().take(7).enumerate() {
            checksum += checksum_value(c) * weights[i];
        }

        let checksum_char = chars.next().unwrap();
        let expected_checksum = checksum_char.to_ascii_uppercase() as u32 - b'A' as u32 + 1;

        // optional 9th char
        if let Some(c) = chars.next() {
            checksum += 9 * checksum_value(c);
        }

        checksum % 23 == expected_checksum
    }
}

fn checksum_value(c: char) -> u32 {
    if let Some(x) = c.to_digit(10) {
        x
    } else {
        if c.to_ascii_uppercase() == 'W' || c == ' ' {
            0
        } else {
            c.to_ascii_uppercase() as u32 - (b'A' as u32) + 1
        }
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::irish_pps_checksum::IrishPpsChecksum;
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_pps() {
        let valid = vec!["1234567FA", "1084633RB"];
        for example in valid {
            assert!(IrishPpsChecksum.is_valid_match(example));
        }
    }

    #[test]
    fn test_invalid_pps() {
        let invalid = vec![
            // wrong checksum
            "1084633WW",
            // too long
            "1084633WWX",
            // too short
            "1084633",
            "1234567😊A",
        ];
        for example in invalid {
            assert!(!IrishPpsChecksum.is_valid_match(example));
        }
    }
}
