pub struct SlovenianPINChecksum;
use crate::secondary_validation::Validator;

const WEIGHT_FACTORS: [u32; 12] = [7, 6, 5, 4, 3, 2, 7, 6, 5, 4, 3, 2];

impl Validator for SlovenianPINChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // https://en.wikipedia.org/wiki/Unique_Master_Citizen_Number
        let mut digits = regex_match.chars().filter_map(|c| c.to_digit(10));

        let mut sum = 0;
        for (i, digit) in digits.by_ref().take(WEIGHT_FACTORS.len()).enumerate() {
            sum += digit * WEIGHT_FACTORS[i];
        }

        if let Some(actual_checksum) = digits.next() {
            let mut computed_checksum = 11 - (sum % 11);
            if computed_checksum == 11 || computed_checksum == 10 {
                computed_checksum = 0;
            }
            return computed_checksum == actual_checksum;
        }
        false
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
