use crate::secondary_validation::Validator;

pub struct GermanSvnrChecksum;
const MULTIPLIERS: &[u32] = &[2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1];
const MODULO: u32 = 10;

fn sum_all_digits(value: u32) -> u32 {
    let mut local_value = value;
    let mut sum = 0;

    while local_value > 0 {
        sum += local_value % 10;
        local_value /= 10;
    }
    sum
}

// https://de.wikipedia.org/wiki/Versicherungsnummer
impl Validator for GermanSvnrChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut valid_chars = regex_match.chars().filter(|c| c.is_ascii_alphanumeric());

        // char length expected to be equals to multipliers as one character will take two multipliers.
        if valid_chars.clone().count() != MULTIPLIERS.len() {
            return false;
        }

        let mut sum = 0;
        let mut idx = 0;

        let mut add_digit_and_increment = |char_digit: u32| -> bool {
            if let Some(weight) = MULTIPLIERS.get(idx) {
                // sum = sum + char_digit * weight;

                sum = (sum + sum_all_digits(char_digit * weight)) % MODULO;
                idx += 1;
                return true;
            }
            false
        };

        // See above, one character will use two multipliers
        for value in valid_chars.by_ref().take(MULTIPLIERS.len() - 1) {
            if let Some(char_digit) = value.to_digit(36) {
                if char_digit < 10 {
                    if !add_digit_and_increment(char_digit) {
                        return false;
                    }
                } else {
                    let char_digit = char_digit - 9;
                    let first_digit = char_digit / 10;
                    if !add_digit_and_increment(first_digit) {
                        return false;
                    }
                    let second_digit = char_digit % 10;
                    if !add_digit_and_increment(second_digit) {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }

        if let Some(check_digit) = valid_chars
            .by_ref()
            .take(1)
            .filter_map(|c| c.to_digit(10))
            .next()
        {
            return sum == check_digit;
        }

        false
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_numbers() {
        let valid_ids = vec![
            "15 070649 C103", // https://de.wikipedia.org/wiki/Sozialversicherungsnummer#Deutschland
            "50 150256 W493", // https://www.settle-in-berlin.com/health-insurance-germany/social-security-number-germany/#payslips
            "212 40284 M 032", // https://www.settle-in-berlin.com/health-insurance-germany/social-security-number-germany/#your-yearly-summary-sent-by-your-krankenkasse
        ];
        for id in valid_ids {
            println!("testing for input {}", id);
            assert!(GermanSvnrChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_numbers() {
        let invalid_ids = vec![
            // wrong checksum
            "15 070649 C102",
            // to many letters
            "15 070649 CD02",
            // Not enough letters
            "15 070649 0002",
            // wrong length
            "000000000000000000",
            "0",
        ];
        for id in invalid_ids {
            println!("testing for input {}", id);
            assert!(!GermanSvnrChecksum.is_valid_match(id));
        }
    }
}
