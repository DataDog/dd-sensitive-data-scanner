use crate::secondary_validation::Validator;

pub struct ChineseIdChecksum;

const CHINESE_ID_LENGTH: usize = 18;
const CHINESE_ID_COEFFICIENTS: &[i32] = &[7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];

impl Validator for ChineseIdChecksum {
    // https://en.wikipedia.org/wiki/Resident_Identity_Card
    //  Last digit checksum cf ISO 7064:1983, MOD 11-2.
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Check if the length of the ID is correct
        if regex_match.len() != CHINESE_ID_LENGTH {
            return false;
        }

        // Check if all characters are digits except the last one
        // Compute the sum to compute checksum later on
        let mut sum = 0;
        for (idx, c) in regex_match.chars().take(CHINESE_ID_LENGTH - 1).enumerate() {
            if let Some(x) = c.to_digit(10) {
                sum += CHINESE_ID_COEFFICIENTS[idx] * x as i32;
            } else {
                return false;
            }
        }

        // Compute the checksum
        let checksum = match sum % 11 {
            0 => '1',
            1 => '0',
            2 => 'X',
            // Convert the remainder to ascii value then to char
            _ => (12 - sum % 11 + '0' as i32) as u8 as char,
        };

        // Compare the computed checksum with the provided one
        regex_match
            .chars()
            .next_back()
            .unwrap()
            .to_ascii_uppercase()
            == checksum
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_chinese_ids() {
        let valid_ids = vec![
            "513231200012121657",
            "513231200012121673",
            "51323120001212169X",
            "513231200012121710",
            "513231200012121737",
            "513231200012121753",
            "513231200012121294",
            "51323120001212177X",
            "513231200012121796",
            "513231200012121817",
            "513231200012121833",
            "51323120001212185X",
            // Same with lowercase x should work
            "51323120001212185x",
            "513231200012121876",
            "513231200012121892",
        ];
        for id in valid_ids {
            assert!(ChineseIdChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_chinese_ids() {
        let invalid_ids = vec![
            // wrong checksum
            "513231200012121293",
            // non digit characters
            "a13231200012121293",
            // wrong length
            "a1323120001212129",
            // Non utf-8 characters 18 bytes
            "513231200012Àñô",
        ];
        for id in invalid_ids {
            assert!(!ChineseIdChecksum.is_valid_match(id));
        }
    }
}
