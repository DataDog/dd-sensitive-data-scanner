use crate::secondary_validation::{Validator, get_next_digit};

pub struct AustralianTfnChecksum;

// https://en.wikipedia.org/wiki/Tax_file_number#Check_digit
// https://github.com/sidorares/tfn/issues/1
const WEIGHTS_9: &[u32; 9] = &[1, 4, 3, 7, 5, 8, 6, 9, 10];
const WEIGHTS_8: &[u32; 8] = &[10, 7, 8, 4, 6, 3, 5, 1];

impl Validator for AustralianTfnChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let digit_count = regex_match.chars().filter(|c| c.is_ascii_digit()).count();
        let weights: &[u32] = match digit_count {
            8 => WEIGHTS_8,
            9 => WEIGHTS_9,
            _ => return false,
        };

        let mut chars = regex_match.chars();
        let mut sum: u32 = 0;

        for &weight in weights {
            match get_next_digit(&mut chars) {
                Some(digit) => sum += digit * weight,
                None => return false,
            }
        }

        sum.is_multiple_of(11)
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_9_digit_tfn() {
        let valid_ids = vec![
            "430341373",
            "346-614-101",
            "1124-740-82",
            "565.051.603",
            "907 974 668",
        ];

        for id in valid_ids {
            assert!(
                AustralianTfnChecksum.is_valid_match(id),
                "expected valid: {id}"
            );
        }
    }

    #[test]
    fn test_valid_8_digit_tfn() {
        let valid_ids = vec!["81854402", "3711 8 629", "37-118-660", "37.118.705"];
        for id in valid_ids {
            assert!(
                AustralianTfnChecksum.is_valid_match(id),
                "expected valid: {id}"
            );
        }
    }

    #[test]
    fn test_invalid_tfn() {
        let invalid_ids = vec![
            "abcdefghi",
            "1",
            "1865414088",
            "9-599-230",
            "1124-740-83",
            "37 113 655",
        ];
        for id in invalid_ids {
            assert!(
                !AustralianTfnChecksum.is_valid_match(id),
                "expected invalid: {id}"
            );
        }
    }
}
