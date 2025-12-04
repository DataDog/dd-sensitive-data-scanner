use crate::secondary_validation::{Validator, get_next_digit};

const ROUND_1_WEIGHTS: &[u32; 10] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 1];
const ROUND_2_WEIGHTS: &[u32; 10] = &[3, 4, 5, 6, 7, 8, 9, 1, 2, 3];

pub struct EstoniaPersonalCodeChecksum;

impl Validator for EstoniaPersonalCodeChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut chars = regex_match.chars();

        let mut sum_round_1 = 0;
        let mut sum_round_2 = 0;
        for i in 0..10 {
            let digit = match get_next_digit(&mut chars) {
                Some(d) => d,
                None => return false,
            };
            sum_round_1 += digit * ROUND_1_WEIGHTS[i];
            sum_round_2 += digit * ROUND_2_WEIGHTS[i];
        }

        // extract the checksum digit
        let actual_checksum = match get_next_digit(&mut chars) {
            Some(d) => d,
            None => return false,
        };

        if get_next_digit(&mut chars).is_some() {
            return false; // too many digits
        }

        // calculate checksum using two-stage mod 11 algorithm
        let mut computed_checksum = sum_round_1 % 11;
        if computed_checksum == 10 {
            computed_checksum = sum_round_2 % 11;
            if computed_checksum == 10 {
                computed_checksum = 0;
            }
        }

        computed_checksum == actual_checksum
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_estonian_personal_code() {
        let valid_ids = vec![
            // male, born 1985-07-30, serial 033
            "38507300337",
            // female, born 1993-05-05, serial 079
            "49305050799",
            // male, born 2015-01-01, serial 005
            "51501010056",
        ];
        for id in valid_ids {
            assert!(
                EstoniaPersonalCodeChecksum.is_valid_match(id),
                "Expected {} to be valid",
                id
            );
        }
    }

    #[test]
    fn test_valid_estonian_personal_code_stage_2() {
        // stage 1 checksum would be 10, so stage 2 is used
        let valid_ids = vec!["50001010040"];
        for id in valid_ids {
            assert!(
                EstoniaPersonalCodeChecksum.is_valid_match(id),
                "Expected {} to be valid (stage 2)",
                id
            );
        }
    }

    #[test]
    fn test_invalid_estonian_personal_code() {
        let invalid_ids = vec![
            // wrong checksum
            "38507300338",
            "49305050798",
            // too few digits
            "3850730033",
            // too many digits
            "385073003377",
            // non-numeric characters
            "3850730033A",
        ];
        for id in invalid_ids {
            assert!(
                !EstoniaPersonalCodeChecksum.is_valid_match(id),
                "Expected {} to be invalid",
                id
            );
        }
    }
}
