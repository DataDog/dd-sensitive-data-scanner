use crate::secondary_validation::Validator;
use crate::secondary_validation::base58::decode_base58;
use sha3::{Digest, Keccak256};

pub struct MoneroChecksum;

const CHECKSUM_LENGTH: usize = 4;

impl Validator for MoneroChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Strip any whitespace
        let clean_input = regex_match
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .collect::<String>();

        decode_monero_address(&clean_input)
    }
}

/// Decode and validate a Monero address
fn decode_monero_address(input: &str) -> bool {
    let decoded = match decode_base58(input) {
        Ok(decoded) => decoded,
        Err(_) => return false,
    };

    if decoded.len() < CHECKSUM_LENGTH {
        return false;
    }

    let (address_bytes, checksum) = decoded.split_at(decoded.len() - CHECKSUM_LENGTH);

    let hash = Keccak256::digest(address_bytes);

    &hash[0..4] == checksum
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_valid_monero_addresses() {
        let valid_addresses = vec![
            // Standard Monero addresses
            "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge",
            "45GjcbHh1fvEyXEA6mDAKqNDMmy1Gon6CNHrdhp9hghfLXQNQj4J76TLtwYGoooKApWLM7kaZwdAxLycceHmuVcELCSFPHq ", // with space
            "42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm",
            // Sub-addresses
            "84EgZVjXKF4d1JkEhZSxm4LQQEx64AvqQEwkvWPtHEb5JMrB1Y86y1vCPSCiXsKzbfS9x8vCpx3gVgPaHCpobPYqQzANTnC",
            // Integrated addresses
            "4LL9oSLmtpccfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2bYXZKKQePHES9khPK",
            "4FKZ5LYDj98gmRH9ex4GCUi7SCpBeckyX5vi97A2YSN9a5wHYGXKfMfZXHXZGJn87X6NDHAB2jZWWRnnysWoeHTw6XGSCDXRoad4zyZZt5",
        ];

        for address in valid_addresses {
            assert!(
                MoneroChecksum.is_valid_match(address),
                "Should be valid: {}",
                address
            );
        }
    }

    #[test]
    fn test_invalid_monero_addresses() {
        let invalid_addresses = vec![
            // Wrong length
            "4short",
            "4toolongaddressthatshouldnotbevalidbecauseitexceedsthenormallength",
            // Wrong starting character
            "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2BvBMSEYstWetqTFn5Au4m4GFg7xJaN",
            "3BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2BvBMSEYstWetqTFn5Au4m4GFg7xJaN",
            // Invalid characters
            "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnKacXMiNaKKK5kEqeGGjrNhM8Crd4Y7fG0P", // Contains '0'
            "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnKacXMiNaKKK5kEqeGGjrNhM8Crd4Y7fGOP", // Contains 'O'
            // Empty or too short
            "",
            "4",
            "48"
        ];

        for address in invalid_addresses {
            assert!(
                !MoneroChecksum.is_valid_match(address),
                "Should be invalid: {}",
                address
            );
        }
    }
}
