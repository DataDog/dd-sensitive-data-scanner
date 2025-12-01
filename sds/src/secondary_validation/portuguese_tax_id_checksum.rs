use crate::secondary_validation::{Validator, validate_mod11_weighted_checksum};

/// Validates the checksum of Portuguese Tax ID numbers (NIF).
/// See: https://pt.wikipedia.org/wiki/Número_de_identificação_fiscal
pub struct PortugueseTaxIdChecksum;

const WEIGHTS: &[u32; 8] = &[9, 8, 7, 6, 5, 4, 3, 2];

impl Validator for PortugueseTaxIdChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        validate_mod11_weighted_checksum(regex_match, WEIGHTS, |remainder| match remainder {
            0 | 1 => Some(0), // 11 - 0 = 11 (>9), 11 - 1 = 10 (>9), both become 0
            _ => Some(11 - remainder),
        })
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
