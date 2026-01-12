use crate::secondary_validation::{Validator, get_next_digit};

pub struct BelgiumNationalRegisterChecksum;

impl Validator for BelgiumNationalRegisterChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut chars = regex_match.chars();

        let mut first_nine_value = 0u64;
        for _ in 0..9 {
            let digit = match get_next_digit(&mut chars) {
                Some(d) => d,
                None => return false,
            };
            first_nine_value = first_nine_value * 10 + digit as u64;
        }

        // extract the check digit (last 2 digits)
        let check_digit_tens = match get_next_digit(&mut chars) {
            Some(d) => d,
            None => return false,
        };
        let check_digit_ones = match get_next_digit(&mut chars) {
            Some(d) => d,
            None => return false,
        };
        let actual_check_digit = (check_digit_tens * 10 + check_digit_ones) as u64;

        if get_next_digit(&mut chars).is_some() {
            return false; // too many digits
        }

        // YY field is ambiguous (e.g. "15" could be 1915 or 2015)
        // try both calculations
        // - pre-2000: checksum of YYMMDDXXX
        // - post-2000: checksum of 2YYMMDDXXX (with "2" prefix)
        let check_pre_2000 = {
            let remainder = first_nine_value % 97;
            if remainder == 0 { 97 } else { 97 - remainder }
        };
        if check_pre_2000 == actual_check_digit {
            return true;
        }
        let first_nine_with_prefix = 2_000_000_000 + first_nine_value;
        let remainder = first_nine_with_prefix % 97;
        let check_post_2000 = if remainder == 0 { 97 } else { 97 - remainder };
        check_post_2000 == actual_check_digit
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_belgian_national_register_pre_2000() {
        // valid Belgian National Register numbers for people born before 2000
        // for 85073003[3]: 850730033 % 97 = 69, check = 97-69 = 28
        let valid_ids = vec![
            "85.07.30-033.28",
            "85 07 30 033 28",
            "850730-033.28",
            "85073003328",
        ];
        for id in valid_ids {
            assert!(
                BelgiumNationalRegisterChecksum.is_valid_match(id),
                "Expected {} to be valid",
                id
            );
        }
    }

    #[test]
    fn test_valid_belgian_national_register_pre_2000_additional() {
        let valid_ids = vec!["93.05.05-079.13", "930505-079.13", "93050507913"];
        for id in valid_ids {
            assert!(
                BelgiumNationalRegisterChecksum.is_valid_match(id),
                "Expected {} to be valid",
                id
            );
        }
    }

    #[test]
    fn test_valid_belgian_national_register_post_2000() {
        // for people born after 1999, a "2" is prepended to the 9-digit number
        let valid_ids = vec!["15.01.01-005.25", "15010100525"];
        for id in valid_ids {
            assert!(
                BelgiumNationalRegisterChecksum.is_valid_match(id),
                "Expected {} to be valid (post-2000 birth)",
                id
            );
        }
    }

    #[test]
    fn test_invalid_belgian_national_register() {
        let invalid_ids = vec![
            // wrong checksum
            "85.07.30-033.29",
            "85 07 30 033 27",
            "850730-033.26",
            "93.05.05-079.14",
            // too few digits
            "8507300332",
            // too many digits
            "850730033288",
            // non-numeric characters
            "A5073003328",
        ];
        for id in invalid_ids {
            assert!(
                !BelgiumNationalRegisterChecksum.is_valid_match(id),
                "Expected {} to be invalid",
                id
            );
        }
    }

    #[test]
    fn test_check_digit_97_edge_case() {
        // when remainder is 0, check digit should be 97
        let test_id = "97000000097";
        assert!(
            BelgiumNationalRegisterChecksum.is_valid_match(test_id),
            "Expected {} to be valid (remainder 0 case)",
            test_id
        );
    }
}
