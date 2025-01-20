use crate::secondary_validation::Validator;

use super::get_next_digit;

pub struct BrazilianCnpjChecksum;

const BRAZILIAN_CNPJ_V1_MULTIPLIERS: &[u32] = &[5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
const BRAZILIAN_CNPJ_V2_MULTIPLIERS: &[u32] = &[6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3];

impl Validator for BrazilianCnpjChecksum {
    // https://pt.wikipedia.org/wiki/Cadastro_Nacional_da_Pessoa_Jur%C3%ADdica
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Compute the checksum
        let mut v1 = 0;
        let mut v2 = 0;
        let mut content_to_scan = regex_match.chars();
        let mut digit_idx = 0;
        let mut prev_digit = 0;
        while let Some(x) = get_next_digit(&mut content_to_scan) {
            match digit_idx {
                idx if idx < 12 => {
                    v1 += BRAZILIAN_CNPJ_V1_MULTIPLIERS[idx] * x;
                    v2 += BRAZILIAN_CNPJ_V2_MULTIPLIERS[idx] * x;
                }
                12 => {
                    v1 = 11 - v1 % 11;
                    if v1 >= 10 {
                        v1 = 0;
                    }
                    v2 += 2 * x;
                    v2 = 11 - v2 % 11;
                    if v2 >= 10 {
                        v2 = 0;
                    }
                }
                13 => {
                    // Compare the computed checksum with the provided one
                    return v1 == prev_digit && v2 == x;
                }
                _ => {
                    return false;
                }
            }
            digit_idx += 1;
            prev_digit = x;
        }
        false
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_brazilian_cnpj_ids() {
        let valid_ids = vec!["00.623.904/0001-73", "00.623.904/0001-73"];
        for id in valid_ids {
            assert!(BrazilianCnpjChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_brazilian_cnpj_ids() {
        let invalid_ids = vec![
            // valid cpf
            "012.345.678-90",
            // wrong checksum
            "00.623.904/0001-71",
            "00.623.904/0001-53",
            // Non utf-8 characters 18 bytes
            "567.456.234-90ñô",
            // wrong length
            "00.623.904/0131001-53",
        ];
        for id in invalid_ids {
            assert!(!BrazilianCnpjChecksum.is_valid_match(id));
        }
    }
}
