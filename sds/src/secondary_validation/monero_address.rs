use std::str::FromStr;

use crate::secondary_validation::Validator;
use monero::Address;

pub struct MoneroAddress;

impl Validator for MoneroAddress {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        Address::from_str(regex_match).is_ok()
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_monero_addresses() {
        let valid_addresses = vec![
            "4BKjy1uVRTPiz4pHyaXXawb82XpzLiowSDd8rEQJGqvN6AD6kWosLQ6VJXW9sghopxXgQSh1RTd54JdvvCRsXiF41xvfeW5",
            "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A",
        ];
        for address in valid_addresses {
            assert!(
                MoneroAddress.is_valid_match(address),
                "Failed for address: {}",
                address
            );
        }
    }

    #[test]
    fn test_invalid_monero_addresses() {
        let invalid_addresses = vec![
            // Wrong length
            "4BKjy1uVRTPiz4pHyaXXawb82XpzLiowSDd8rEQJGqvN6AD6kWosLQ6VJXW9sghopxXgQSh1RTd54JdvvCRsXiF41xvfeW5X",
            // Invalid characters
            "44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP30",
            // Empty string
            "",
            // Just whitespace
            "   ",
        ];
        for address in invalid_addresses {
            assert!(
                !MoneroAddress.is_valid_match(address),
                "Should be invalid: {}",
                address
            );
        }
    }
}
