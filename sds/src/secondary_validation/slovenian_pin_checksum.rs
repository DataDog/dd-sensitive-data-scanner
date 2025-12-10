use crate::secondary_validation::{Validator, validate_mod11_weighted_checksum};

pub struct SlovenianPINChecksum;

const WEIGHTS: &[u32; 12] = &[7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];

impl Validator for SlovenianPINChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // https://en.wikipedia.org/wiki/Unique_Master_Citizen_Number
        validate_mod11_weighted_checksum(regex_match, WEIGHTS, |remainder| match remainder {
            0 | 1 => Some(0), // 11-0=11 and 11-1=10 both become 0
            _ => Some(11 - remainder),
        })
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_slovenian_pins() {
        let slovenian_pins = vec![
            "0101006500006",
            "01-01-006-50-000-6",
            "01.01.006.50.000.6",
            "01🙏01006500006",
            "1212995504350",
            "2001939010010",
        ];
        for pin in slovenian_pins {
            assert!(SlovenianPINChecksum.is_valid_match(pin));
        }
    }

    #[test]
    fn test_invalid_slovenian_pins() {
        let invalid_slovenian_pins = vec!["0101006500007"];
        for pin in invalid_slovenian_pins {
            assert!(!SlovenianPINChecksum.is_valid_match(pin));
        }
    }
}
