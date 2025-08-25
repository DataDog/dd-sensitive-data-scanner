use crate::secondary_validation::{Validator, get_previous_digit};

pub struct VerhoeffChecksum;

const MULT_TABLE: [[usize; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const PERM_TABLE: [[usize; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

impl Validator for VerhoeffChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut input_iter = regex_match.chars();
        let mut c = 0;
        let mut i = 0;

        while let Some(digit) = get_previous_digit(&mut input_iter) {
            c = MULT_TABLE[c][PERM_TABLE[i % 8][digit as usize]];
            i += 1;
        }

        c == 0
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_verhoeff_checksum() {
        // Check digits from luxembourg_individual_nin_checksum.rs without Luhn checksum digit
        let valid_numbers = vec![
            "199009301238",
            "199310281454",
            "200112030877",
            "197912200328",
            "196605150762",
        ];
        for number in valid_numbers {
            println!("valid verhoeff number: {number}");
            assert!(VerhoeffChecksum.is_valid_match(number));

            let verhoeff_digit = number.chars().last().unwrap();
            let non_checksum_digits = &number[..number.len() - 1];
            let mut invalid_number = non_checksum_digits.to_string();
            invalid_number.push_str(&((verhoeff_digit.to_digit(10).unwrap() + 1) % 10).to_string());
            println!("invalid verhoeff number: {invalid_number}");
            assert!(!VerhoeffChecksum.is_valid_match(&invalid_number));
        }
    }
}
