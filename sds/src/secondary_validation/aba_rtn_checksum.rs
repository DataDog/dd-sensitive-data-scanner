use crate::secondary_validation::{get_next_digit, Validator};

pub struct AbaRtnChecksum;

const ABA_RTN_MULTIPLIERS: &[u32] = &[3, 7, 1];

impl Validator for AbaRtnChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // check if (3(d1 + d4 + d7) + 7(d2 + d5 + d8) + (d3 + d6 + d9)) mod 10 == 0
        if regex_match.len() != 9 {
            return false;
        }

        let mut chars = regex_match.chars();
        let mut checksum = 0;

        for i in 0..9 {
            if let Some(digit) = get_next_digit(&mut chars) {
                checksum += ABA_RTN_MULTIPLIERS[i % 3] * digit;
            } else {
                return false;
            }
        }

        checksum % 10 == 0
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_aba_rtn() {
        let valid_ids = vec![
            "000000000",
            // publicly available valid ABA RTN numbers
            "121000248",
            "314074269",
            "071004200",
            "275982005",
        ];
        for id in valid_ids {
            assert!(AbaRtnChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_aba_rtn() {
        let invalid_ids = vec![
            // wrong checksum
            "123456789",
            // Non digit characters
            "abcdefghi",
            "123abcdef",
            "12345678f",
            // wrong length
            "000000000000000000",
        ];
        for id in invalid_ids {
            assert!(!AbaRtnChecksum.is_valid_match(id));
        }
    }
}
