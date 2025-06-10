use std::collections::HashMap;
const BASE58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

use lazy_static::lazy_static;

lazy_static! {
    static ref BASE58_MAP: HashMap<char, u32> = {
        let mut m = HashMap::new();
        for (i, &c) in BASE58_ALPHABET.iter().enumerate() {
            m.insert(c as char, i as u32);
        }
        m
    };
}
/// Decode a Base58 string to bytes
pub fn decode_base58(input: &str) -> Result<Vec<u8>, &'static str> {
    // Skip and count leading '1's (which represent leading zeros)
    let mut leading_zeros = 0;
    let mut chars = input.chars();
    while let Some('1') = chars.as_str().chars().next() {
        leading_zeros += 1;
        chars.next();
    }

    // Initialize the vec with a single empty byte
    // The vec will grow as more characters are processed
    let mut result = vec![0u8];
    for char in chars {
        let value = match BASE58_MAP.get(&char) {
            Some(char) => char,
            None => return Err("Invalid character in Base58 string"),
        };

        // Multiply result by 58 and add new digit
        let mut carry = *value;
        for byte in result.iter_mut().rev() {
            carry += (*byte as u32) * 58;
            *byte = (carry % 256) as u8;
            carry /= 256;
        }

        // Add any remaining carry as new bytes
        while carry > 0 {
            result.insert(0, (carry % 256) as u8);
            carry /= 256;
        }
    }

    // Add leading zeros
    let mut final_result = vec![0u8; leading_zeros];
    final_result.extend_from_slice(&result);

    Ok(final_result)
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::base58::decode_base58;

    #[test]
    fn test_decode_base58_leading_ones() {
        assert_eq!(decode_base58("1111").unwrap(), vec![0, 0, 0, 0, 0]);
        assert_eq!(decode_base58("1112").unwrap(), vec![0, 0, 0, 1]);
    }

    #[test]
    fn test_decode_base58_invalid_chars() {
        assert!(decode_base58("0").is_err()); // '0' not in alphabet
        assert!(decode_base58("O").is_err()); // 'O' not in alphabet
        assert!(decode_base58("I").is_err()); // 'I' not in alphabet
        assert!(decode_base58("l").is_err()); // 'l' not in alphabet
    }

    #[test]
    fn test_decode_base58() {
        assert_eq!(decode_base58("").unwrap(), vec![0]);
        assert_eq!(decode_base58("2").unwrap(), vec![1]);
        assert_eq!(decode_base58("3").unwrap(), vec![2]);
        assert_eq!(decode_base58("z").unwrap(), vec![57]);
        // Hello World! encoded in Base58
        assert_eq!(
            decode_base58("2NEpo7TZRRrLZSi2U").unwrap(),
            vec![72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33]
        );
        // this is a secret
        assert_eq!(
            decode_base58("FNiwznCgensZP9yjTzodbq").unwrap(),
            vec![116, 104, 105, 115, 32, 105, 115, 32, 97, 32, 115, 101, 99, 114, 101, 116]
        );
        assert_eq!(
            decode_base58("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").unwrap(),
            vec![
                0, 98, 233, 7, 177, 92, 191, 39, 213, 66, 83, 153, 235, 246, 240, 251, 80, 235,
                184, 143, 24, 194, 155, 125, 147
            ]
        );
        assert_eq!(
            decode_base58("17NdbrSGoUotzeGCcMMCqnFkEvLymoou9j").unwrap(),
            vec![
                0, 69, 232, 10, 244, 156, 10, 147, 150, 186, 37, 218, 180, 105, 110, 151, 100, 167,
                67, 57, 56, 51, 103, 201, 90
            ]
        );
    }
}
