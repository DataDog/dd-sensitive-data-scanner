use crate::secondary_validation::{Validator, validate_mod11_weighted_checksum};

pub struct NhsCheckDigit;

const WEIGHTS: &[u32; 9] = &[10, 9, 8, 7, 6, 5, 4, 3, 2];

impl Validator for NhsCheckDigit {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // https://www.datadictionary.nhs.uk/attributes/nhs_number.html
        // The NHS number is a 10-digit number in the format 123 456 7890.
        validate_mod11_weighted_checksum(regex_match, WEIGHTS, |remainder| match remainder {
            0 => Some(0), // 11 - 0 = 11 → 0
            1 => None,    // 11 - 1 = 10 → invalid
            _ => Some(11 - remainder),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_nhs_number() {
        let valid_ids = vec![
            "1234567881",
            "907 784 4449",
            "798 428 4334",
            "111 431 1456",
            "095 558 1001",
            "649 261 8610",
            "600 562 5942",
            "110 537 9787",
            "166 584 5783",
            "714 375 8426",
            "434 539 1210",
            "064 327 9288",
        ];
        for id in valid_ids {
            assert!(NhsCheckDigit.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_nhs_number() {
        let invalid_ids = vec![
            "1234567890",  // can't compute check digit
            "1234567882",  // invalid check digit
            "12345678810", // invalid length
        ];
        for id in invalid_ids {
            assert!(!NhsCheckDigit.is_valid_match(id));
        }
    }
}
