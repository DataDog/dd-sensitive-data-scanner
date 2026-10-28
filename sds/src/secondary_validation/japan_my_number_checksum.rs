use crate::secondary_validation::{Validator, validate_mod11_weighted_checksum};

/// Check digit defined by Article 5 of Japanese ordinance No. 85:
/// https://laws.e-gov.go.jp/law/426M60000008085#Mp-At_5
pub struct JapanMyNumberChecksum;

const WEIGHTS: &[u32; 11] = &[6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];

impl Validator for JapanMyNumberChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        validate_mod11_weighted_checksum(regex_match, WEIGHTS, |remainder| {
            Some(if remainder <= 1 { 0 } else { 11 - remainder })
        })
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::{JapanMyNumberChecksum, Validator};

    #[test]
    fn test_published_japan_my_numbers() {
        // TKC examples:
        // https://www.prft.tkc.co.jp/SystemqaCPNYFree/Main/QaItem.aspx?category_id=2044&item_id=83412&system_id=260
        assert!(JapanMyNumberChecksum.is_valid_match("123456789018"));
        assert!(!JapanMyNumberChecksum.is_valid_match("923456789018"));
    }

    #[test]
    fn test_generated_japan_my_numbers() {
        // Generated fixtures from https://box4.dev/en/japan/my-number-generator
        for number in [
            "6637 6256 7333",
            "8834 6653 3261",
            "7680 7456 4211",
            "3385 0214 0532",
            "5800 0094 7110",
        ] {
            assert!(JapanMyNumberChecksum.is_valid_match(number), "{number}");
            assert!(JapanMyNumberChecksum.is_valid_match(&number.replace(' ', "")));
        }
    }

    #[test]
    fn test_incorrect_check_digit() {
        assert!(!JapanMyNumberChecksum.is_valid_match("123456789012"));
        assert!(!JapanMyNumberChecksum.is_valid_match("1234 5678 9012"));
    }

    #[test]
    fn test_incorrect_digit_count() {
        for number in ["", "12345678901", "1234567890180"] {
            assert!(!JapanMyNumberChecksum.is_valid_match(number), "{number}");
        }
    }

    #[test]
    fn test_zero_check_digit_for_small_remainders() {
        // Synthetic arithmetic cases: sums 11 and 12 give remainders 0 and 1.
        for number in ["000000000140", "000000000060"] {
            assert!(JapanMyNumberChecksum.is_valid_match(number), "{number}");
        }
        for number in ["000000000141", "000000000061"] {
            assert!(!JapanMyNumberChecksum.is_valid_match(number), "{number}");
        }
    }
}
