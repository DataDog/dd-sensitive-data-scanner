use crate::secondary_validation::{RodneCisloNumberChecksum, Validator};
use nom::lib::std::cmp::max;
pub struct CzechTaxIdentificationNumberChecksum;

impl Validator for CzechTaxIdentificationNumberChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let digits = regex_match
            .chars()
            .filter_map(|c| c.to_digit(10))
            .collect::<Vec<u32>>();

        // legal entities
        if digits.len() == 8 {
            let mut digits = digits.iter();
            return has_valid_checksum(&mut digits, |sum| max(sum, 1) % 10);
        }

        // individuals without a RČ
        if digits.len() == 9 && digits[0] == 6 {
            let mut digits = digits.iter().skip(1);
            return has_valid_checksum(&mut digits, |sum| (8 - ((10 - sum) % 11)) % 10);
        }

        RodneCisloNumberChecksum.is_valid_match(regex_match)
    }
}

fn has_valid_checksum<'a>(
    digits: &mut impl Iterator<Item = &'a u32>,
    sum_to_checksum: fn(u32) -> u32,
) -> bool {
    let sum = digits
        .by_ref()
        .take(7)
        .enumerate()
        .fold(0, |acc, (i, digit)| acc + (8 - i) as u32 * digit)
        % 11;

    let checksum = match digits.next() {
        Some(digit) => digit,
        None => return false,
    };

    sum_to_checksum(sum) == *checksum
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::czech_tin_checksum::CzechTaxIdentificationNumberChecksum;
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_pps() {
        let valid = vec![
            // 8 digits
            "CZ 251238/91",
            // 9 digits special case
            "CZ 640903/926",
            // 10 digits
            "6809115566",
            "9811150570",
            "CZ 710319/2745",
        ];
        for example in valid {
            assert!(CzechTaxIdentificationNumberChecksum.is_valid_match(example));
        }
    }

    #[test]
    fn test_invalid_pps() {
        let invalid = vec![
            // wrong checksum
            "9909116450",
            "25123890",
            // wrong length
            "12345678",
            "12345678901",
        ];
        for example in invalid {
            assert!(!CzechTaxIdentificationNumberChecksum.is_valid_match(example));
        }
    }
}
