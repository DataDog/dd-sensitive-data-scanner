use crate::secondary_validation::{get_next_digit, Validator};

pub struct LatviaNationalIdChecksum;

const LATVIA_NATIONAL_ID_LENGTH: usize = 11;
const LATVIA_NATIONAL_ID_OLD_FORMAT_MULTIPLIERS: &[u32] = &[1, 6, 3, 7, 9, 10, 5, 8, 4, 2];

impl Validator for LatviaNationalIdChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        /*
         * Latvia national identification number has 2 formats:
         * 1. Since July 1st 2017, an 11-digit number, starting with "32" with possible '-' after the 6th digit
         * 2. Before July 1st 2017, an 11 digits number, in the format DDMMYY-XNNNZ, where:
         *    - DDMMYY is the date of birth
         *    - X represents the century digit (0 for 19, 1 for 20, 2 for 21)
         *    - NNN is a birth serial number in that day
         *    - Z is the checksum digit
         */

        // Remove possible '-'
        let digits_str: String = regex_match.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits_str.len() != LATVIA_NATIONAL_ID_LENGTH {
            return false;
        }

        let mut digits = digits_str.chars();
        let first_2_digits: String = digits.clone().take(2).collect();
        // No checksum validation needed for the new format
        if first_2_digits == "32" {
            return true;
        }

        // Checksum validation for the old format ABCDEF-XGHIZ
        // Z must equal to (1101-(1*A + 6*B + 3*C + 7*D + 9*E + 10*F + 5*X + 8*G + 4*H + 2*I)) | Mod 11 | Mod 10.
        let mut sum = 0;
        for mult in LATVIA_NATIONAL_ID_OLD_FORMAT_MULTIPLIERS {
            let digit = match get_next_digit(&mut digits) {
                Some(d) => d,
                None => return false,
            };
            sum += digit * mult;
        }

        let checksum = ((1101 - sum) % 11) % 10;
        let actual_checksum = digits.last().unwrap().to_digit(10).unwrap();

        checksum == actual_checksum
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_latvia_national_ids() {
        let old_latvia_national_ids = vec![
            // old format
            "121282-11210",
            "280794-12344",
        ];
        for id in old_latvia_national_ids {
            println!("Old latvia national identification number: {}", id);
            assert!(LatviaNationalIdChecksum.is_valid_match(id));

            let checksum = id.chars().last().unwrap();
            let id_without_checksum = &id[..id.len() - 1];

            let mut invalid_checksum = id_without_checksum.to_string();
            invalid_checksum.push_str(&((checksum.to_digit(10).unwrap() + 1) % 10).to_string());
            println!(
                "latvia national identification number with invalid checksum: {}",
                invalid_checksum
            );
            assert!(!LatviaNationalIdChecksum.is_valid_match(&invalid_checksum));
        }

        let new_latvia_national_ids = vec![
            // new format
            "320010-10002",
            "32001010003",
        ];
        for id in new_latvia_national_ids {
            println!("New latvia national identification number: {}", id);
            assert!(LatviaNationalIdChecksum.is_valid_match(id));
        }
    }
}
