use crate::secondary_validation::Validator;

pub struct GermanIdsChecksum;
const MULTIPLIERS: &[u32] = &[7, 3, 1];

// https://en.wikipedia.org/wiki/German_passport
// https://de.wikipedia.org/wiki/Personalausweis_(Deutschland)
impl Validator for GermanIdsChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut valid_chars = regex_match.chars().filter(|c| c.is_ascii_alphanumeric());

        let sum_digits = valid_chars.by_ref().take(9);
        let mut sum = 0;
        for (idx, value) in sum_digits.enumerate() {
            if let Some(digit) = value.to_digit(36) {
                sum += digit * MULTIPLIERS[idx % MULTIPLIERS.len()]
            } else {
                return false;
            }
        }

        let check_digit = valid_chars
            .by_ref()
            .take(1)
            .filter_map(|c| c.to_digit(10))
            .next();

        // If Missing check digit, then assume the match is valid.
        if check_digit.is_none() {
            return true;
        }
        check_digit.unwrap() == sum % 10
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_numbers() {
        let valid_ids = vec![
            "C01X00T47",   // Missing check digit - so valid
            "C01X00T47D",  // Missing check digit with optional D - so valid
            "C01X00T478",  // With check digit
            "C01X00T478D", // With check digit and optional D
            "CZ6311T472D",
            "CZ63351X73D", // https://www.consilium.europa.eu/prado/en/DEU-AO-04004/image-371462.html
            "cz63351x73d",
            // IDs
            "2406055684",
            "2406055684d",
            "2406055684D",
            "T220001293D",
            "T220001293",
            // https://de.wikipedia.org/wiki/Personalausweis_(Deutschland)
            "LZ6311T475",
            "lz6311t475",
            "👍lz6311t475", // ignored character
        ];
        for id in valid_ids {
            println!("testing for input {}", id);
            assert!(GermanIdsChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_numbers() {
        let invalid_ids = vec![
            // wrong checksum
            "C01X00T470",
        ];
        for id in invalid_ids {
            println!("testing for input {}", id);
            assert!(!GermanIdsChecksum.is_valid_match(id));
        }
    }
}
