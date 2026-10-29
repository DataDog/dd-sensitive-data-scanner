use crate::secondary_validation::{Validator, validate_mod11_weighted_checksum};

/// [NPA §1(4)](https://www.npa.go.jp/laws/notification/menkyo20250310_76.pdf) confirms modulus 11,
/// but omits weights and remainder handling. This implementation combines secondary sources:
/// [WDIC](https://www.wdic.org/w/GEO/運転免許証) (weights and remainder handling) and
/// [Resource Sharing](https://resource-sharing.co.jp/driver-license-number-check-digit/)
/// (matching weights and a worked example); their independence is unverified.
///
/// Sources disagree on remainder 0: a [Delphix example](https://help.delphix.com/dcs/current/content/docs/japan_drivers_license.htm)
/// implies check digit 0. We choose 1, following WDIC and
/// [Fujii's explicit rule](https://ameblo.jp/fujiikenzi-shihousyoshi/entry-12957415231.html).
pub struct JapanDrivingLicenseChecksum;

const WEIGHTS: [u32; 10] = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];

impl Validator for JapanDrivingLicenseChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let digits = regex_match.as_bytes();
        if digits.len() != 12 || !digits.iter().all(u8::is_ascii_digit) {
            return false;
        }

        // The final digit is the reissuance indicator, not part of the checksum.
        validate_mod11_weighted_checksum(&regex_match[..11], &WEIGHTS, |remainder| {
            Some((11 - remainder) % 10)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_EXAMPLES: [&str; 3] = [
        "309212345690", // Worked example: https://resource-sharing.co.jp/driver-license-number-check-digit/
        "155261998521", // Masked output: https://help.delphix.com/dcs/current/content/docs/japan_drivers_license.htm
        "897346134533", // Masked output: https://help.delphix.com/dcs/current/content/docs/japan_drivers_license.htm
    ];

    #[test]
    fn accepts_published_examples() {
        for number in VALID_EXAMPLES {
            assert!(
                JapanDrivingLicenseChecksum.is_valid_match(number),
                "expected published example to pass: {number}"
            );
        }
    }

    #[test]
    fn rejects_corrupted_check_digits() {
        for number in VALID_EXAMPLES {
            for check_digit in b'0'..=b'9' {
                if check_digit == number.as_bytes()[10] {
                    continue;
                }
                let mut corrupted = number.as_bytes().to_vec();
                corrupted[10] = check_digit;
                let corrupted = String::from_utf8(corrupted).unwrap();
                assert!(
                    !JapanDrivingLicenseChecksum.is_valid_match(&corrupted),
                    "expected corrupted check digit to fail: {corrupted}"
                );
            }
        }
    }

    #[test]
    fn rejects_corrupted_data_digits() {
        for number in VALID_EXAMPLES {
            for index in 0..10 {
                let mut corrupted = number.as_bytes().to_vec();
                corrupted[index] = b'0' + (corrupted[index] - b'0' + 1) % 10;
                let corrupted = String::from_utf8(corrupted).unwrap();
                assert!(
                    !JapanDrivingLicenseChecksum.is_valid_match(&corrupted),
                    "expected corrupted data digit to fail: {corrupted}"
                );
            }
        }
    }

    #[test]
    fn rejects_malformed_input() {
        for input in [
            "",
            "30921234569",
            "3092123456900",
            "30921234569X",
            "X09212345690",
            " 309212345690",
            "309212345690 ",
            "3092 1234 5690",
            "3092-1234-5690",
            "３０９２１２３４５６９０",
            "30921234569０",
        ] {
            assert!(
                !JapanDrivingLicenseChecksum.is_valid_match(input),
                "expected malformed input to fail: {input:?}"
            );
        }
    }
}
