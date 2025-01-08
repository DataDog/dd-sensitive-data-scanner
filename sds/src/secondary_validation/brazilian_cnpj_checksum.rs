use crate::secondary_validation::Validator;

pub struct BrazilianCnpjChecksum;

const BRAZILIAN_CNPJ_LENGTH: usize = 18;
// XX.XXX.XXX/YYYY-ZZ
const BRAZILIAN_CNPJ_SEPARATOR_INDICES: &[usize] = &[2, 6, 10, 15];

impl Validator for BrazilianCnpjChecksum {
    // https://pt.wikipedia.org/wiki/Cadastro_Nacional_da_Pessoa_Jur%C3%ADdica
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Check if the length of the ID is correct
        if regex_match.len() != BRAZILIAN_CNPJ_LENGTH {
            return false;
        }

        // Collect digits from match
        let mut digits: Vec<u32> = Vec::with_capacity(10);
        for (idx, c) in regex_match[..BRAZILIAN_CNPJ_LENGTH].chars().enumerate() {
            if BRAZILIAN_CNPJ_SEPARATOR_INDICES.contains(&idx) {
                // Skip the separator
                continue;
            }
            if let Some(x) = c.to_digit(10) {
                digits.push(x);
            } else {
                // Non-digit char in a position that should be a digit
                return false;
            }
        }

        // Compute the checksum
        let mut v1;
        let mut v2;
        v1 = 5 * digits[0] + 4 * digits[1] + 3 * digits[2] + 2 * digits[3];
        v1 += 9 * digits[4] + 8 * digits[5] + 7 * digits[6] + 6 * digits[7];
        v1 += 5 * digits[8] + 4 * digits[9] + 3 * digits[10] + 2 * digits[11];
        v1 = 11 - v1 % 11;
        if v1 >= 10 {
            v1 = 0;
        }
        v2 = 6 * digits[0] + 5 * digits[1] + 4 * digits[2] + 3 * digits[3];
        v2 += 2 * digits[4] + 9 * digits[5] + 8 * digits[6] + 7 * digits[7];
        v2 += 6 * digits[8] + 5 * digits[9] + 4 * digits[10] + 3 * digits[11];
        v2 += 2 * digits[12];
        v2 = 11 - v2 % 11;
        if v2 >= 10 {
            v2 = 0;
        }

        // Compare the computed checksum with the provided one
        v1 == digits[12] && v2 == digits[13]
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
