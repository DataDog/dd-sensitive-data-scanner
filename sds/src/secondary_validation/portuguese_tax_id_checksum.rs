use crate::secondary_validation::{get_next_digit, Validator};

/// Validates the checksum of Portuguese Tax ID numbers (NIF).
/// See: https://pt.wikipedia.org/wiki/Número_de_identificação_fiscal
pub struct PortugueseTaxIdChecksum;

impl Validator for PortugueseTaxIdChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut chars = regex_match.chars();
        let mut sum = 0;

        // multiply each digit by its weight (9 to 2)
        for i in 0..8 {
            let digit = match get_next_digit(&mut chars) {
                Some(d) => d,
                None => return false,
            };
            sum += digit * (9 - i);
        }

        let expected_check_digit = match 11 - (sum % 11) {
            n if n > 9 => 0,
            n => n,
        };

        let actual_check_digit = match get_next_digit(&mut chars) {
            Some(d) => d,
            None => return false,
        };

        if get_next_digit(&mut chars).is_some() {
            return false; // too many digits
        }

        expected_check_digit == actual_check_digit
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_nif() {
        let valid_ids = vec![
            // See: https://billing.pt/nif-validator/
            "581348915",
            "581 348 915",
            "389982482",
            "389 982 482",
            "248915967",
            "248 915 967",
        ];
        for id in valid_ids {
            assert!(PortugueseTaxIdChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_nif() {
        let invalid_ids = vec![
            // wrong checksum
            "581348910",
            "581 348 910",
            "389982489",
            "389 982 489",
            // too many digits
            "5813489150",
            // too few digits
            "58134891",
        ];
        for id in invalid_ids {
            assert!(!PortugueseTaxIdChecksum.is_valid_match(id));
        }
    }
}
