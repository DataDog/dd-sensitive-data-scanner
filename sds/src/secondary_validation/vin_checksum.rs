use crate::secondary_validation::Validator;

pub struct VinChecksum;

impl Validator for VinChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // NHTSA 49 CFR 565.15(c) and GB 16735-2019 Appendix A use the same checksum.
        const WEIGHTS: [u16; 17] = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
        let bytes = regex_match.as_bytes();
        if bytes.len() != WEIGHTS.len() {
            return false;
        }

        let mut sum = 0;
        for (&byte, weight) in bytes.iter().zip(WEIGHTS) {
            let value = match byte.to_ascii_uppercase() {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'A' | b'J' => 1,
                b'B' | b'K' | b'S' => 2,
                b'C' | b'L' | b'T' => 3,
                b'D' | b'M' | b'U' => 4,
                b'E' | b'N' | b'V' => 5,
                b'F' | b'W' => 6,
                b'G' | b'P' | b'X' => 7,
                b'H' | b'Y' => 8,
                b'R' | b'Z' => 9,
                _ => return false,
            };
            sum += value * weight;
        }

        let check_digit = match sum % 11 {
            10 => b'X',
            remainder => b'0' + remainder as u8,
        };
        bytes[8].to_ascii_uppercase() == check_digit
    }
}
