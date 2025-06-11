use crate::secondary_validation::Validator;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

use crate::secondary_validation::base58::decode_base58;

pub struct BtcChecksum;

const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_CONST: u32 = 1;
const BECH32M_CONST: u32 = 0x2bc830a3;
const BASE58_CHECKSUM_LENGTH: usize = 4;

use lazy_static::lazy_static;

lazy_static! {
    static ref BECH32_MAP: HashMap<char, u8> = {
        let mut m = HashMap::new();
        for (i, c) in BECH32_CHARSET.chars().enumerate() {
            m.insert(c, i as u8);
        }
        m
    };
}

impl Validator for BtcChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Strip any whitespace and convert to bytes for validation
        let clean_input = regex_match
            .chars()
            .filter(|c| c.is_alphanumeric())
            .collect::<String>();

        if clean_input
            .chars()
            .next()
            .filter(|c| c.is_ascii_digit())
            .is_some()
        {
            return decode_base58_check(&clean_input);
        }
        bech32_check(&clean_input)
    }
}

/// Decode a Base58Check encoded string
fn decode_base58_check(input: &str) -> bool {
    // https://github.com/bitcoin/bips/blob/master/bip-0013.mediawiki
    // First decode the base58 string
    let decoded = match decode_base58(input) {
        Ok(decoded) => decoded,
        Err(_) => return false,
    };

    // Check minimum length (payload + 4 byte checksum)
    if decoded.len() < BASE58_CHECKSUM_LENGTH {
        return false;
    }

    // Split payload and checksum
    let (payload, checksum) = decoded.split_at(decoded.len() - BASE58_CHECKSUM_LENGTH);

    // Calculate double SHA256 hash of payload
    let hash1 = Sha256::digest(payload);
    let hash2 = Sha256::digest(hash1);

    // Compare first 4 bytes of hash with provided checksum
    &hash2[0..4] == checksum
}

fn bech32_check(input: &str) -> bool {
    if let Some(bech32_spec) = bech32_decode(input) {
        if let Some(fourth_char) = input.chars().nth(3) {
            return bech32_spec
                .get_fourth_char()
                .eq_ignore_ascii_case(&fourth_char);
        }
    }
    false
}

#[derive(Debug, PartialEq)]
enum Bech32Spec {
    Bech32,
    Bech32m,
}

impl Bech32Spec {
    fn get_fourth_char(&self) -> char {
        match self {
            Bech32Spec::Bech32 => 'q',
            Bech32Spec::Bech32m => 'p',
        }
    }
}

/// Decode a Bech32/Bech32m string and determine HRP and data
fn bech32_decode(input: &str) -> Option<Bech32Spec> {
    // https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
    // https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki
    // Check case consistency
    let has_lower = input.chars().any(|c| c.is_lowercase());
    let has_upper = input.chars().any(|c| c.is_uppercase());
    if has_lower && has_upper {
        return None;
    }

    let bech = input.to_lowercase();

    let parts: Vec<&str> = bech.rsplitn(2, '1').collect();
    let hrp = parts[1];
    let data_part = parts[0];
    if hrp.is_empty() || data_part.len() < 6 {
        return None;
    }

    let mut data: Vec<u8> = vec![];
    for c in data_part.chars() {
        if let Some(value) = BECH32_MAP.get(&c) {
            data.push(*value);
        } else {
            return None;
        }
    }
    bech32_verify_checksum(hrp, &data)
}

/// Verify a Bech32 checksum given HRP and converted data characters
fn bech32_verify_checksum(hrp: &str, data: &[u8]) -> Option<Bech32Spec> {
    let mut values = bech32_hrp_expand(hrp);
    values.extend_from_slice(data);

    let const_value = bech32_poly_mod(&values);

    if const_value == BECH32_CONST {
        Some(Bech32Spec::Bech32)
    } else if const_value == BECH32M_CONST {
        Some(Bech32Spec::Bech32m)
    } else {
        None
    }
}

/// Expand the HRP into values for checksum computation
fn bech32_hrp_expand(hrp: &str) -> Vec<u8> {
    let mut result = Vec::new();

    // High bits
    for c in hrp.chars() {
        result.push((c as u8) >> 5);
    }

    result.push(0);

    // Low bits
    for c in hrp.chars() {
        result.push((c as u8) & 31);
    }

    result
}

/// Compute the Bech32 checksum
fn bech32_poly_mod(values: &[u8]) -> u32 {
    const GENERATOR: [u32; 5] = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3];

    let mut chk: u32 = 1;

    for &value in values {
        let top = chk >> 25;
        chk = (chk & 0x1FFFFFF) << 5 ^ (value as u32);

        for (idx, value) in GENERATOR.iter().enumerate() {
            if (top >> idx) & 1 != 0 {
                chk ^= value;
            }
        }
    }

    chk
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

        // Testnet addresses
        assert!(BtcChecksum.is_valid_match("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"));

        // Invalid: mixed case
        assert!(!BtcChecksum.is_valid_match("bc1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"));

        // Invalid: wrong checksum
        assert!(!BtcChecksum.is_valid_match("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"));

        // Invalid: contains invalid Bech32 character
        assert!(!BtcChecksum.is_valid_match("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3tb"));
    }
}
