use crate::secondary_validation::{Validator, get_next_digit};

pub struct JapanCorporateNumberChecksum;

impl Validator for JapanCorporateNumberChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        if regex_match.len() != 13 || !regex_match.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }

        let mut chars = regex_match.chars();
        let Some(check_digit) = get_next_digit(&mut chars) else {
            return false;
        };
        let mut sum = 0;
        for weight in [2, 1].into_iter().cycle().take(12) {
            let Some(digit) = get_next_digit(&mut chars) else {
                return false;
            };
            sum += digit * weight;
        }

        // NTA: https://www.houjin-bangou.nta.go.jp/documents/houjinbangounokousei.pdf
        check_digit == 9 - sum % 9
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn accepts_official_examples() {
        // NTA worked example: https://www.houjin-bangou.nta.go.jp/documents/checkdigit.pdf
        assert!(JapanCorporateNumberChecksum.is_valid_match("8700110005901"));
        // NTA API sample: https://www.houjin-bangou.nta.go.jp/pc/download/images/k-sample-explain-r0404.pdf
        assert!(JapanCorporateNumberChecksum.is_valid_match("8040001999013"));
    }

    #[test]
    fn handles_every_remainder() {
        // Synthetic bases: only the units digit varies, giving sums 0 through 8.
        for (units, check_digit) in (0..=8).zip((1..=9).rev()) {
            let number = format!("{check_digit}00000000000{units}");
            assert!(
                JapanCorporateNumberChecksum.is_valid_match(&number),
                "{number}"
            );
        }
        // Synthetic base with a tens digit of 1 gives sum 2.
        assert!(JapanCorporateNumberChecksum.is_valid_match("7000000000010"));
    }

    #[test]
    fn rejects_wrong_check_digits() {
        for check_digit in b'0'..=b'9' {
            let mut number = *b"8700110005901";
            number[0] = check_digit;
            let number = std::str::from_utf8(&number).unwrap();
            assert_eq!(
                JapanCorporateNumberChecksum.is_valid_match(number),
                check_digit == b'8',
                "{number}"
            );
        }
        assert!(!JapanCorporateNumberChecksum.is_valid_match("8700110005902"));
    }

    #[test]
    fn rejects_malformed_input() {
        for number in [
            "",
            "870011000590",
            "87001100059010",
            "870011000590A",
            "8 700110005901",
            "8-700110005901",
            " 8700110005901",
            "8700110005901 ",
            "８700110005901",
            "870011000590１",
            "87001100059é",
            "1234567890123",
            "9876543210987",
        ] {
            assert!(
                !JapanCorporateNumberChecksum.is_valid_match(number),
                "{number}"
            );
        }
    }
}
