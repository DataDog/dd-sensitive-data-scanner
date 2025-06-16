use crate::secondary_validation::Validator;
use bitcoin::{Address, Network};
use std::str::FromStr;

pub struct BtcChecksum;

impl Validator for BtcChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Strip any whitespace or separators
        let clean_input = regex_match
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();

        let address = Address::from_str(&clean_input);
        address.is_ok_and(|addr| addr.is_valid_for_network(Network::Bitcoin))
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_bitcoin_addresses() {
        let valid_addresses = vec![
            // P2PKH addresses (start with '1')
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
            "12cbQLTFMXRnSzktFkuoG3eHoMeFtpTu3S",
            "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
            "17NdbrSGoUotzeGCcMMCqnFkEvLymoou9j",
            "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nK9",
            // P2SH addresses (start with '3')
            "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
            "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
            // Bech32 addresses (P2WPKH and P2WSH)
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
            // Bech32m addresses (P2TR)
            "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
        ];
        for address in valid_addresses {
            assert!(
                BtcChecksum.is_valid_match(address),
                "Failed for address: {}",
                address
            );
        }
    }

    #[test]
    fn test_invalid_bitcoin_addresses() {
        let invalid_addresses = vec![
            // Invalid Base58Check checksum
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3",
            "1AGNa15ZQXAZUgFiqJ3i7Z2DPU2J6hW62i",
            "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62j",
            "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62X",
            "1ANNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
            "1A Na15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
            "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62iz",
            "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62izz",
            "1Q1pE5vPGEEMqRcVRMbtBK842Y6Pzo6nJ9",
            "1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62I",
            // Invalid Base58Check characters
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfN0", // Contains '0'
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNO", // Contains 'O'
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNI", // Contains 'I'
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNl", // Contains 'l'
            "17NdbrSGoUotzeGCcMMC?nFkEvLymoou9j", // Contains '?'
            // Invalid Bech32 checksum
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // Last character changed
            "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv4", // Last character changed
            // Invalid Bech32 characters
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tb", // Contains 'b' (not in Bech32 charset)
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tO", // Contains 'O' (not in Bech32 charset)
            // Mixed case (invalid for Bech32)
            "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7Kv8f3t4", // Mixed case
            // Too short
            "1",
            "12",
            "bc1",
        ];
        for address in invalid_addresses {
            assert!(
                !BtcChecksum.is_valid_match(address),
                "Should be invalid: {}",
                address
            );
        }
    }

    #[test]
    fn test_addresses_with_whitespace() {
        // Should handle addresses with whitespace
        assert!(BtcChecksum.is_valid_match(" 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa "));
        assert!(BtcChecksum.is_valid_match("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"));
        assert!(BtcChecksum.is_valid_match("\t1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\t"));

        // Bech32 with whitespace
        assert!(BtcChecksum.is_valid_match(" bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 "));
        assert!(BtcChecksum.is_valid_match("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\n"));
    }

    #[test]
    fn test_bech32_specific_validation() {
        // Test specific Bech32 features
        assert!(BtcChecksum.is_valid_match("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));
        assert!(BtcChecksum.is_valid_match("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4")); // uppercase should work
        assert!(BtcChecksum.is_valid_match("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")); // lowercase should work

        // Bech32m (taproot)
        assert!(BtcChecksum
            .is_valid_match("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"));

        // Invalid: Testnet addresses
        assert!(!BtcChecksum.is_valid_match("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"));

        // Invalid: mixed case
        assert!(!BtcChecksum.is_valid_match("bc1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));

        // Invalid: wrong checksum
        assert!(!BtcChecksum.is_valid_match("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"));

        // Invalid: contains invalid Bech32 character
        assert!(!BtcChecksum.is_valid_match("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tb"));
    }
}
