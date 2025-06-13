use crate::secondary_validation::Validator;

const ROUND_1_WEIGHTS: &[u32; 10] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 1];
const ROUND_2_WEIGHTS: &[u32; 10] = &[3, 4, 5, 6, 7, 8, 9, 1, 2, 3];

pub struct LithuanianPersonalIdentificationNumberChecksum;

impl Validator for LithuanianPersonalIdentificationNumberChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut digits = regex_match.chars().filter_map(|c| c.to_digit(10));

        let digit_to_compute_checksum = digits
            .by_ref()
            .take(ROUND_1_WEIGHTS.len())
            .collect::<Vec<_>>();
        let digit_to_compute_checksum = digit_to_compute_checksum.as_slice();
        let actual_checksum = match digits.next() {
            Some(checksum) => checksum,
            None => return false,
        };

        // At this stage, digit_to_compute_checksum is necessarily ROUND_1_WEIGHTS.len() digits long as actual_checksum is not None
        let mut computed_checksum = run_round(digit_to_compute_checksum, ROUND_1_WEIGHTS) % 11;
        if computed_checksum == 10 {
            computed_checksum = run_round(digit_to_compute_checksum, ROUND_2_WEIGHTS) % 11;
            if computed_checksum == 10 {
                computed_checksum = 0;
            }
        }
        computed_checksum == actual_checksum
    }
}

fn run_round(value: &[u32], weights: &[u32; 10]) -> u32 {
    let mut checksum = 0;
    for (digit, weight) in value.iter().zip(weights) {
        checksum += digit * weight;
    }
    checksum
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::lithuanian_personal_identification_number_checksum::LithuanianPersonalIdentificationNumberChecksum;
    use crate::secondary_validation::*;

    #[test]
    fn test_valid() {
        let valid = vec!["333-092-400-64", "39001010000", "36709010186"];
        for x in valid {
            assert!(LithuanianPersonalIdentificationNumberChecksum.is_valid_match(x));
        }
    }

    #[test]
    fn test_invalid() {
        let invalid = vec![
            // invalid checksum
            "33309240063",
            // too long
            "3330924006",
            // too long
            "333092400638",
            // non-digits
            "ABC09240063",
        ];
        for x in invalid {
            assert!(!LithuanianPersonalIdentificationNumberChecksum.is_valid_match(x));
        }
    }
}
