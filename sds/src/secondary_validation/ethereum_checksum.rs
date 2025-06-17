use crate::secondary_validation::Validator;
use ethaddr::Address;
pub struct EthereumChecksum;

impl Validator for EthereumChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        Address::from_str_checksum(regex_match).is_ok()
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_ethereum_addresses() {
        let valid_addresses = vec![
            // These are known valid EIP-55 addresses
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
        ];
        for address in valid_addresses {
            assert!(
                EthereumChecksum.is_valid_match(address),
                "Failed for address: {}",
                address
            );
        }
    }

    #[test]
    fn test_invalid_ethereum_addresses() {
        let invalid_addresses = vec![
            // Wrong checksum
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAee",
            // Wrong length
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAe",
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed1",
            // Invalid characters
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeG",
            // Wrong case (all lowercase)
            "0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed",
            // Empty string
            "",
            // Just whitespace
            "   ",
            // Mixed case without proper checksum
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD",
        ];
        for address in invalid_addresses {
            assert!(
                !EthereumChecksum.is_valid_match(address),
                "Should be invalid: {}",
                address
            );
        }
    }
}
