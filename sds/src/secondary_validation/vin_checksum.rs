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

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn vin_checksum_accepts_independent_vectors_and_ascii_case() {
        let validator = VinChecksum;
        // GB 16735-2019 Appendix A (zero) and published VIN examples (numeric/X).
        for vin in [
            "LFWADRJF011002346",
            "5YJ3E1EAXHF000316",
            "1HGBH41JXMN109186",
            "LZPTCAP2561500278",
            "LJSKA3BF3CD820005",
            "5yj3e1eaxhf000316",
            "lFwAdRjF011002346",
        ] {
            assert!(validator.is_valid_match(vin), "rejected {vin}");
        }
    }

    #[test]
    fn vin_checksum_rejects_historical_invalid_examples_and_malformed_input() {
        let validator = VinChecksum;
        for vin in [
            "L5BGA2V58NG590409",
            "3D7KA28693G723011",
            "2FMDK36C18BA04895",
            "5YJ3E1EA0HF000316",
            "5YJ3E1EAXHF000317",
            "LFWADRJFA11002346",
            "",
            "LFWADRJF01100234",
            "LFWADRJF0110023460",
            "LFWADRJF 11002346",
            "LFWADRJF-11002346",
            "LFWADRJF_11002346",
            "LFWADRJF/11002346",
            "LFWADRJF01100234é",
            "LFWADRJF0110023é",
            "ＬFWADRJF011002346",
        ] {
            assert!(!validator.is_valid_match(vin), "accepted {vin}");
        }
        for forbidden in [b'I', b'O', b'Q', b'i', b'o', b'q'] {
            for position in 0..17 {
                let mut vin = b"LFWADRJF011002346".to_vec();
                vin[position] = forbidden;
                let vin = String::from_utf8(vin).unwrap();
                assert!(!validator.is_valid_match(&vin), "accepted {vin}");
            }
        }
    }

    #[test]
    fn vin_checksum_accepts_only_the_expected_ninth_character() {
        let validator = VinChecksum;
        for vin in ["LFWADRJF011002346", "5YJ3E1EAXHF000316"] {
            for character in b"0123456789ABCDEFGHJKLMNPRSTUVWXYZ" {
                let mut candidate = vin.as_bytes().to_vec();
                candidate[8] = *character;
                let candidate = String::from_utf8(candidate).unwrap();
                assert_eq!(
                    validator.is_valid_match(&candidate),
                    candidate == vin,
                    "{candidate}"
                );
            }
        }
    }

    #[test]
    fn vin_checksum_transliterates_every_allowed_character() {
        let validator = VinChecksum;
        // With only position one nonzero, its weight of eight determines the check digit.
        for (characters, check_digit) in [
            ("0", b'0'),
            ("1AJ", b'8'),
            ("2BKS", b'5'),
            ("3CLT", b'2'),
            ("4DMU", b'X'),
            ("5ENV", b'7'),
            ("6FW", b'4'),
            ("7GPX", b'1'),
            ("8HY", b'9'),
            ("9RZ", b'6'),
        ] {
            for character in characters.bytes() {
                let mut vin = *b"00000000000000000";
                vin[0] = character;
                vin[8] = check_digit;
                let vin = std::str::from_utf8(&vin).unwrap();
                assert!(validator.is_valid_match(vin), "rejected {vin}");
            }
        }
    }

    #[test]
    fn vin_checksum_checks_integrity_not_vehicle_issuance() {
        let validator = VinChecksum;
        for vin in ["00000000000000000", "11111111111111111"] {
            assert!(validator.is_valid_match(vin));
        }
    }
}
