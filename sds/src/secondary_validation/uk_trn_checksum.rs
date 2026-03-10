use crate::secondary_validation::{Validator, validate_mod11_weighted_checksum};

pub struct UkTrnChecksum;

/// From [HMRC UtrReferenceChecker](https://github.com/hmrc/reference-checker/blob/main/src/main/scala/uk/gov/hmrc/referencechecker/ReferenceChecker.scala#L103)
const WEIGHTS: &[u32; 9] = &[6, 7, 8, 9, 10, 5, 4, 3, 2];
const REMAINDER_LOOKUP: [u32; 11] = [2, 1, 9, 8, 7, 6, 5, 4, 3, 2, 1];

impl Validator for UkTrnChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Self Assessment UTR may have one leading or trailing K; more than one K is invalid.
        if regex_match
            .chars()
            .filter(|c| c.eq_ignore_ascii_case(&'K'))
            .count()
            > 1
        {
            return false;
        }

        let digits: Vec<char> = regex_match.chars().filter(|c| c.is_ascii_digit()).collect();
        let ten_digits = match digits.len() {
            10 => digits,
            13 => digits[3..13].to_vec(), // 13-digit = 3 prefix + 10-digit UTR
            _ => return false,
        };

        // UTR has check digit at index 0 and data at 1..10; validate_mod11_weighted_checksum
        // expects data first then check, so we reorder to avoid duplicating the algorithm.
        let data_then_check: String = ten_digits[1..10]
            .iter()
            .chain(ten_digits[0..1].iter())
            .collect();

        validate_mod11_weighted_checksum(&data_then_check, WEIGHTS, |remainder| {
            Some(REMAINDER_LOOKUP[remainder as usize])
        })
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_uk_trn() {
        let validator = UkTrnChecksum;

        // Valid numbers generated from https://generator.avris.it/
        // Manual addition of k
        let valid_numbers = vec![
            "1123456789",
            "112 345 678 9",
            "6898201056K",
            "0006452194352",
            "K1232611912725",
            "4491783771k",
        ];

        for number in valid_numbers {
            assert!(validator.is_valid_match(number), "expected valid: {number}");
        }
    }

    #[test]
    fn test_invalid_uk_trn() {
        let validator = UkTrnChecksum;

        let invalid_numbers = vec![
            "112345678",      // 9 digits
            "11234567890",    // 11 digits
            "112345678901",   // 12 digits
            "11234567890123", // 14 digits
            "3419210344",     // wrong checksum
            "K3366215443k",   // more than one K
        ];

        for number in invalid_numbers {
            assert!(
                !validator.is_valid_match(number),
                "expected invalid: {number}"
            );
        }
    }
}
