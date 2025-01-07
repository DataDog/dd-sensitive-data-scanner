use crate::secondary_validation::Validator;

pub struct BrazilianCpfChecksum;

const BRAZILIAN_CPF_LENGTH: usize = 14;

impl Validator for BrazilianCpfChecksum {
    // https://pt.wikipedia.org/wiki/Cadastro_de_Pessoas_F%C3%ADsicas#C%C3%A1lculo_do_d%C3%ADgito_verificador
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Check if the length of the ID is correct
        if regex_match.len() != BRAZILIAN_CPF_LENGTH {
            println!("wrong length: {}", regex_match.len());
            return false;
        }

        // Check if all characters are digits except the last one
        // Compute the sum to compute checksum later on
        let mut digit_idx = 0;
        let mut v1: u32 = 0;
        let mut v2: u32 = 0;
        for (idx, c) in regex_match[..BRAZILIAN_CPF_LENGTH - 2]
            .chars()
            .rev()
            .enumerate()
        {
            if idx % 4 == 0 {
                // Skip the separator
                continue;
            }
            if let Some(x) = c.to_digit(10) {
                v1 += x * (9 - (digit_idx % 10));
                println!("v1 -> {} * (9 - ({} % 10)) -> {}", x, digit_idx, v1);
                v2 += x * (9 - ((digit_idx + 1) % 10));
                // println!("char: {}, idx: {}, digit_idx: {}", c, idx, digit_idx);
                digit_idx += 1;
            } else {
                println!("non digit char: {}", c);
                return false;
            }
        }
        v1 = (v1 % 11) % 10;
        v2 += v1 * 9;
        v2 = (v2 % 11) % 10;

        for (idx, c) in regex_match.chars().enumerate() {
            println!("idx: {}, c: {}", idx, c);
        }

        let actual_v1 = regex_match.chars().nth(12).unwrap().to_digit(10).unwrap();
        let actual_v2 = regex_match.chars().nth(13).unwrap().to_digit(10).unwrap();
        if v1 != actual_v1 || v2 != actual_v2 {
            println!(
                "v1: {}, v2: {}, actual_v1: {}, actual_v2: {}",
                v1, v2, actual_v1, actual_v2
            );
            return false;
        }
        return true;
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_brazilian_ids() {
        let valid_ids = vec!["012.345.678-90", "083.358.948-25"];
        for id in valid_ids {
            assert!(BrazilianCpfChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_brazilian_ids() {
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
