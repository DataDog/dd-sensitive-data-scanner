use crate::secondary_validation::{Validator, validate_mod11_weighted_checksum};

pub struct ThaiNationalIdChecksum;

const WEIGHTS: &[u32; 12] = &[13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2];

impl Validator for ThaiNationalIdChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // https://nawin.ece.engr.tu.ac.th/cn102/problem/a12/thai_id.pdf
        validate_mod11_weighted_checksum(regex_match, WEIGHTS, |remainder| {
            Some((11 - remainder) % 10)
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::SecondaryValidator;

    // https://alltool.io/id-generator/thailand/
    #[test]
    fn accepts_valid_checksums() {
        for id in ["8-2941-04903-80-2", "4375905538549", "5 3801 56807 75 9"] {
            assert!(ThaiNationalIdChecksum.is_valid_match(id), "{id}");
        }
    }

    #[test]
    fn maps_remainder_zero_to_one() {
        assert!(ThaiNationalIdChecksum.is_valid_match("1234567890121"));
        assert!(!ThaiNationalIdChecksum.is_valid_match("1234567890120"));
    }

    #[test]
    fn maps_remainder_one_to_zero() {
        assert!(ThaiNationalIdChecksum.is_valid_match("1234567890180"));
        assert!(!ThaiNationalIdChecksum.is_valid_match("1234567890181"));
    }

    #[test]
    fn rejects_incorrect_check_digits() {
        for id in [
            "3720200233770",
            "7188630836812",
            "1943835715128",
            "1-2345-67890-12-3",
        ] {
            assert!(!ThaiNationalIdChecksum.is_valid_match(id), "{id}");
        }
    }

    #[test]
    fn rejects_incorrect_digit_counts() {
        for id in [
            "",
            "---",
            "123456789012",
            "12345678901210",
            "1-2345-67890-12-10",
        ] {
            assert!(!ThaiNationalIdChecksum.is_valid_match(id), "{id}");
        }
    }

    #[test]
    fn deserializes_and_compiles_validator() {
        let validator: SecondaryValidator =
            serde_json::from_str(r#"{"type":"ThaiNationalIdChecksum"}"#).unwrap();
        let compiled = validator.compile();
        assert!(compiled.is_valid_match("1234567890121"));
        assert!(!compiled.is_valid_match("1234567890123"));
    }
}
