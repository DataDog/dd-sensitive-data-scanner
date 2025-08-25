use std::str::Chars;

use crate::secondary_validation::{Validator, get_next_digit};

pub struct NirChecksum;

impl Validator for NirChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut input_iter = regex_match.chars();

        let digit = get_next_digit_chars(&mut input_iter, 13);
        if digit.is_none() {
            return false;
        }

        let checksum = get_next_digit_chars(&mut input_iter, 2);
        if checksum.is_none() || get_next_digit(&mut input_iter).is_some() {
            return false;
        }

        (97 - digit.unwrap() % 97) == checksum.unwrap()
    }
}

fn get_next_digit_chars(chars: &mut Chars<'_>, size: usize) -> Option<i64> {
    let mut total: i64 = 0;
    for _ in 0..size {
        if let Some(digit) = get_next_digit(chars) {
            total = total * 10 + digit as i64;
        } else {
            return None;
        }
    }
    Some(total)
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
