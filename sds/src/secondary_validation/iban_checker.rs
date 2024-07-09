use crate::secondary_validation::Validator;
use iban::Iban;
pub struct IbanChecker;

impl Validator for IbanChecker {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let iban_candidate: String = regex_match
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect();
        let iban = iban_candidate.parse::<Iban>();
        if iban.is_err() {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_ibans() {
        let valid_ibans = vec![
            "DE44500105175407324931",
            "DE4450-0105-1754-0732-4931",
            "KZ86 125K ZT50 0410 0100",
        ];
        for iban in valid_ibans {
            assert!(IbanChecker.is_valid_match(iban));
        }
    }

    #[test]
    fn test_invalid_ibans() {
        let invalid_ibans_checksum =
            vec!["DE45500105175407324931", "ZZZFO6666000000000000031231ZZZ"];
        for iban in invalid_ibans_checksum {
            assert!(!IbanChecker.is_valid_match(iban));
        }
        let invalid_ibans_bban = vec!["AL84212110090000AB023569874"];
        for iban in invalid_ibans_bban {
            assert!(!IbanChecker.is_valid_match(iban));
        }
    }
}
