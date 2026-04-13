use crate::secondary_validation::Validator;

pub struct AtlassianTokenChecksum;

fn decode_hex_u32(hex: &[u8]) -> Option<u32> {
    if hex.len() != 8 {
        return None;
    }
    let mut value: u32 = 0;
    for &b in hex {
        let nibble = match b {
            b'0'..=b'9' => b - b'0',
            b'A'..=b'F' => b - b'A' + 10,
            b'a'..=b'f' => b - b'a' + 10,
            _ => return None,
        };
        value = value << 4 | nibble as u32;
    }
    Some(value)
}

impl Validator for AtlassianTokenChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Trailing 8 ASCII characters are a CRC32 checksum (big-endian hex).
        // The CRC is computed over everything before them (the `=` separator is included).
        if regex_match.len() < 9 {
            return false;
        }
        let (prefix, suffix) = regex_match.split_at(regex_match.len() - 8);

        if !prefix
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'=')
        {
            return false;
        }

        let Some(embedded_checksum) = decode_hex_u32(suffix.as_bytes()) else {
            return false;
        };

        crc32fast::hash(prefix.as_bytes()) == embedded_checksum
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_atlassian_tokens() {
        let validids = vec![
            "ATATT3xFfGF0YZuf-EBmAHs1FyiNmk0cYQKtD9zx2LIv8d_zB-yk5Zp8nkug2Rp_ZnYJwq9ys-lS0PRAXLS4vL-crh5tbBbGQISteyOCpgUGgKjckD2MF9A6EZVGdTXikj52U2VDS8HeDlUq9Gmw8KYs5Kb0hS-LZo4Sb2PMpT1Zx0MmTXs_EyA=E2826606",
            "ATATT3xFfGF0Z0J8j7dew7xO2JMwbmnBZm-aJ5ORorE7qRgkDnmZYg9tpvatRzyvZNebxWeUxRZnSkEGeyAV3_Jew_YCxyCUsw_Ipefxsk0EFerD8PlRNEDtQQEmexYVpWbuTguSvV3USUg41GEdgTYa1MUK3YusfDWKzLthXBmkeUH4ZyaTp2Q=325540CC",
        ];
        for id in validids {
            assert!(AtlassianTokenChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_atlassian_tokens() {
        let invalid_ids = vec![
            // Incorrect checksum
            "ATATT3xFfGF0YZuf-EBmAHs1FyiNmk0cYQKtD9zx2LIv8d_zB-yk5Zp8nkug2Rp_ZnYJwq9ys-lS0PRAXLS4vL-crh5tbBbGQISteyOCpgUGgKjckD2MF9A6EZVGdTXikj52U2VDS8HeDlUq9Gmw8KYs5Kb0hS-LZo4Sb2PMpT1Zx0MmTXs_EyA=E2826607",
            // Short checksum
            "ATATT3xFfGF0YZuf-EBmAHs1FyiNmk0cYQKtD9zx2LIv8d_zB-yk5Zp8nkug2Rp_ZnYJwq9ys-lS0PRAXLS4vL-crh5tbBbGQISteyOCpgUGgKjckD2MF9A6EZVGdTXikj52U2VDS8HeDlUq9Gmw8KYs5Kb0hS-LZo4Sb2PMpT1Zx0MmTXs_EyA=E282607",
            // Non hex characters
            "ATATT3xFfGF0YZuf-EBmAHs1FyiNmk0cYQKtD9zx2LIv8d_zB-yk5Zp8nkug2Rp_ZnYJwq9ys-lS0PRAXLS4vL-crh5tbBbGQISteyOCpgUGgKjckD2MF9A6EZVGdTXikj52U2VDS8HeDlUq9Gmw8KYs5Kb0hS-LZo4Sb2PMpT1Zx0MmTXs_EyA=E282607G",
            // // Non base64 characters
            "ATATT3xFfGF0YZuf-EBmAHs1FyiNmk0cYQK~D9zx2LIv8d_zB-yk5Zp8nkug2Rp_ZnYJwq9ys-lS0PRAXLS4vL-crh5tbBbGQISteyOCpgUGgKjckD2MF9A6EZVGdTXikj52U2VDS8HeDlUq9Gmw8KYs5Kb0hS-LZo4Sb2PMpT1Zx0MmTXs_EyA=E2826607",
        ];
        for id in invalid_ids {
            assert!(!AtlassianTokenChecksum.is_valid_match(id));
        }
    }
}
