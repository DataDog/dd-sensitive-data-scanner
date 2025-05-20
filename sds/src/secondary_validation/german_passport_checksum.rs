use crate::secondary_validation::Validator;

pub struct GermanPassportChecksum;
const MULTIPLIERS: &[u32] = &[7, 3, 1];

// https://en.wikipedia.org/wiki/German_passport
impl Validator for GermanPassportChecksum {
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
            .map(|c| c.to_digit(10))
            .flatten()
            .next();

        // If Missing check digit, then assume the match is valid.
        if check_digit.is_none() {
            return true;
        }
        println!("{}, {}", check_digit.unwrap(), sum);
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
        ];
        for id in valid_ids {
            println!("testing for input {}", id);
            assert!(GermanPassportChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_numbers() {
        let invalid_ids = vec![
            // wrong checksum
            "C01X00T470",
            // wrong length
            "000000000000000000",
            "0",
        ];
        for id in invalid_ids {
            println!("testing for input {}", id);
            assert!(!GermanPassportChecksum.is_valid_match(id));
        }
    }
}
