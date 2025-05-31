use crate::secondary_validation::Validator;

const ROUND_1_WEIGHTS: &[u32] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 1];
const ROUND_2_WEIGHTS: &[u32] = &[3, 4, 5, 6, 7, 8, 9, 1, 2, 3];

pub struct LithuanianPersonalIdentificationNumberChecksum;

impl Validator for LithuanianPersonalIdentificationNumberChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        if regex_match.chars().any(|c| !c.is_ascii_digit()) {
            return false;
        }

        // 10 chars + 1 checksum
        if regex_match.len() != 11 {
            return false;
        }

        let mut checksum = run_round(regex_match, ROUND_1_WEIGHTS) % 11;
        if checksum == 10 {
            checksum = run_round(regex_match, ROUND_2_WEIGHTS) % 11;
            if checksum == 10 {
                checksum = 0;
            }
        }

        let actual_checksum = regex_match.chars().last().unwrap().to_digit(10).unwrap();

        checksum == actual_checksum
    }
}

fn run_round(value: &str, weights: &[u32]) -> u32 {
    let mut checksum = 0;

    for (i, c) in value.chars().take(10).enumerate() {
        checksum += weights[i] * c.to_digit(10).unwrap();
    }

    checksum
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::lithuanian_personal_identification_number_checksum::LithuanianPersonalIdentificationNumberChecksum;
    use crate::secondary_validation::*;

    #[test]
    fn test_valid() {
        let valid = vec!["33309240064", "39001010000", "36709010186"];
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
