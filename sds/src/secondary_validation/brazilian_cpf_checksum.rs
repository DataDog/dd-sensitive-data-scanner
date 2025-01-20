use crate::secondary_validation::get_previous_digit;
use crate::secondary_validation::Validator;

pub struct BrazilianCpfChecksum;

const BRAZILIAN_CPF_LENGTH: usize = 14;
const BRAZILIAN_CPF_DIGIT_COUNT: usize = 11;

impl Validator for BrazilianCpfChecksum {
    // https://pt.wikipedia.org/wiki/Cadastro_de_Pessoas_F%C3%ADsicas#C%C3%A1lculo_do_d%C3%ADgito_verificador
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Check if the length of the ID is correct

        let mut digit_idx = 0;
        let mut v1: u32 = 0;
        let mut v2: u32 = 0;
        let mut content_to_scan = regex_match.chars();
        // v1 and v2 are in order, but since we are scanning from the end, they retrieved in reverse-order
        let actual_v2 = match get_previous_digit(&mut content_to_scan) {
            Some(x) => x,
            None => return false,
        };
        let actual_v1 = match get_previous_digit(&mut content_to_scan) {
            Some(x) => x,
            None => return false,
        };
        loop {
            if let Some(x) = get_previous_digit(&mut content_to_scan) {
                v1 += x * (9 - (digit_idx % 10));
                v2 += x * (9 - ((digit_idx + 1) % 10));
                digit_idx += 1;
            } else {
                // Non-digit char in a position that should be a digit as we expect
                // to find all 9 digits (11 - 2 check digits)
                if (digit_idx as usize) != BRAZILIAN_CPF_DIGIT_COUNT - 2 {
                    return false;
                }
                break;
            }
        }
        v1 = (v1 % 11) % 10;
        v2 += v1 * 9;
        v2 = (v2 % 11) % 10;

        if v1 != actual_v1 || v2 != actual_v2 {
            // Checksum failed
            return false;
        }
        true
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_brazilian_cpf_ids() {
        let valid_ids = vec!["012.345.678-90", "083.358.948-25"];
        for id in valid_ids {
            assert!(BrazilianCpfChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_brazilian_cpf_ids() {
        let invalid_ids = vec![
            // wrong checksum
            "345.675.677-78",
            "123.567.234-67",
            "678.534.123-98",
            "234.546.324-97",
            "567.456.234-90",
            "345.678.342-76",
            // Non utf-8 characters 18 bytes
            "567.456.234-90ñô",
            // wrong length
            "345.678.3428723-76",
        ];
        for id in invalid_ids {
            assert!(!BrazilianCpfChecksum.is_valid_match(id));
        }
    }
}
