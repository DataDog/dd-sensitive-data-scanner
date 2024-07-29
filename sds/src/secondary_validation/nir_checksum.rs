use std::str::Chars;

use crate::secondary_validation::Validator;

pub struct NirChecksum;

impl Validator for NirChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut input_iter = regex_match.chars();

        let digit: Option<i64> = get_next_digit_chars(&mut input_iter, 13)
            .and_then(|chars| chars.into_iter().collect::<String>().parse().ok());
        if digit.is_none() {
            return false;
        }

        let checksum: Option<u8> = get_next_digit_chars(&mut input_iter, 2)
            .and_then(|chars| chars.into_iter().collect::<String>().parse().ok());
        if checksum.is_none() || get_next_digit_str(&mut input_iter).is_some() {
            return false;
        }

        (97 - digit.unwrap() % 97) as u8 == checksum.unwrap()
    }
}

fn get_next_digit_str(chars: &mut Chars<'_>) -> Option<char> {
    chars.find(|&char| char.is_ascii_digit())
}

fn get_next_digit_chars(chars: &mut Chars<'_>, size: usize) -> Option<Vec<char>> {
    let mut checksum_vec: Vec<char> = Vec::with_capacity(size);
    for _ in 0..size {
        if let Some(digit) = get_next_digit_str(chars) {
            checksum_vec.push(digit);
        } else {
            return None;
        }
    }
    Some(checksum_vec)
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_numbers() {
        let valid_numbers = vec![
            "1-51-02-46102-043-25",
            "151024610204325",
            "2 69 05 49 588 157 80",
        ];
        for numbers in valid_numbers {
            assert!(NirChecksum.is_valid_match(numbers));
        }
    }

    #[test]
    fn test_invalid_numbers() {
        let valid_numbers = vec![
            // wrong checksum
            "151024610204326",
            // missing digit
            "15102461020432",
            "",
            "123",
            // extra digit
            "151024610204325 1",
        ];
        for numbers in valid_numbers {
            assert!(!NirChecksum.is_valid_match(numbers));
        }
    }
}
