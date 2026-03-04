use crate::secondary_validation::Validator;

pub struct SingaporeNricChecksum;

// The Singapore NRIC checksum has been updated to include the letter 'M' in the checksum calculation.
// The checksum calculation is now as follows:
// 1. The first character is the prefix (S, T, F, G, M)
// 2. The next 7 characters are the digits
// 3. The last character is the checksum
// 4. The checksum is calculated using the weights and the offset
// 5. The offset is 0 for S and T, 4 for F and G, and 3 for M
// 6. The checksum is calculated using the weights and the offset
// 7. If the prefix is M, we should subtract the remainder from 10 to get the checksum character

// /!!\ IMPORTANT /!!\
// The rule 7 is difficult to find on the internet, so it might be wrong.
// Following top generators of NRIC numbers, the rule seems correct.
// https://nricgenerator.com/
// https://samliew.com/nric-generator

const WEIGHTS: &[u32; 7] = &[2, 7, 6, 5, 4, 3, 2];

fn get_checksum_character(c: char, remainder: usize) -> char {
    let remainder_vector = match c {
        'S' | 'T' => vec!['J', 'Z', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A'],
        'F' | 'G' => vec!['X', 'W', 'U', 'T', 'R', 'Q', 'P', 'N', 'M', 'L', 'K'],
        'M' => vec!['K', 'L', 'J', 'N', 'P', 'Q', 'R', 'T', 'U', 'W', 'X'],
        _ => vec![],
    };

    *remainder_vector.get(remainder).unwrap()
}

impl Validator for SingaporeNricChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        if regex_match.chars().count() != 9 {
            return false;
        }

        let mut chars = regex_match.chars();
        let prefix = match chars.next() {
            Some(c) => c.to_uppercase().next().unwrap_or(c),
            None => return false,
        };
        let offset = match prefix {
            'S' | 'F' => 0,
            'T' | 'G' => 4,
            'M' => 3,
            _ => return false,
        };

        let mut sum: u32 = 0;
        for &weight in WEIGHTS {
            let digit = match chars.next().and_then(|c| c.to_digit(10)) {
                Some(d) => d,
                None => return false,
            };
            sum += digit * weight;
        }
        let mut remainder = ((sum + offset) % 11) as usize;
        if prefix == 'M' {
            remainder = 10 - remainder;
        }

        let expected_checksum = get_checksum_character(prefix, remainder);
        let actual_checksum = chars.next().map(|c| c.to_uppercase().next().unwrap_or(c));

        actual_checksum == Some(expected_checksum)
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_numbers() {
        let validator = SingaporeNricChecksum;
        let valid_numbers = vec![
            "S6859080I",
            "T1680536F",
            "M9612050P",
            "F5221211K",
            "G8169811U",
            "g3970684p",
            "M2200054X",
        ];

        for number in valid_numbers {
            assert!(validator.is_valid_match(number));
        }
    }

    #[test]
    fn test_invalid_numbers() {
        let validator = SingaporeNricChecksum;
        let invalid_numbers = vec![
            "A",
            "111111111",
            "XXXXXXXXX",
            "I6859080I",
            "M9612050Q",
            "A1234567A",
            "g3970683p",
        ];
        for number in invalid_numbers {
            assert!(!validator.is_valid_match(number));
        }
    }
}
