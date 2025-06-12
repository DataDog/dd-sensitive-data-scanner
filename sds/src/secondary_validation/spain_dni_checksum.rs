use crate::secondary_validation::Validator;

pub struct SpanishDniChecksum;

const LETTER_TABLE: [char; 23] = [
    'T', 'R', 'W', 'A', 'G', 'M', 'Y', 'F', 'P', 'D', 'X', 'B', 'N', 'J', 'Z', 'S', 'Q', 'V', 'H',
    'L', 'C', 'K', 'E',
];

const NUMBER_LENGTH: usize = 8;
impl Validator for SpanishDniChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        /*
         * Spanish DNI format:
         * 8 digits followed by a letter
         * The letter is calculated by taking the number modulo 23 and using it as an index
         * into LETTER_TABLE
         */
        let mut input = regex_match.chars().filter(|c| c.is_ascii_alphanumeric());

        let number_part: usize = match input
            .by_ref()
            .take(NUMBER_LENGTH)
            .collect::<String>()
            .parse()
        {
            Ok(number) => number,
            Err(_) => return false,
        };

        // Calculate expected letter
        let index = number_part % LETTER_TABLE.len();
        let expected_letter = LETTER_TABLE[index];

        if let Some(letter_part) = input.next() {
            return letter_part.eq_ignore_ascii_case(&expected_letter);
        }
        false
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_spanish_dni() {
        let valid_ids = vec![
            "12345678Z", // 12345678 % 23 = 15 -> Z
            "00000000T", // 0 % 23 = 0 -> T
            "99999999R", // 99999999 % 23 = 1 -> R
        ];
        for id in valid_ids {
            assert!(SpanishDniChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_spanish_dni() {
        let invalid_ids = vec![
            // Wrong letter
            "12345678A",
            "00000000R",
            "99999999T",
            // Wrong length
            "123456789",
            "1234567",
            // Non-numeric first 8 chars
            "1234567A9",
            "ABCDEFGHR",
        ];
        for id in invalid_ids {
            assert!(!SpanishDniChecksum.is_valid_match(id));
        }
    }
}
