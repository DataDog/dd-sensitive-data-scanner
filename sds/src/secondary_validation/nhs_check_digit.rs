use crate::secondary_validation::{Validator, get_previous_digit};

pub struct NhsCheckDigit;

fn nhs_multiplier_from_number_idx(index: usize) -> u32 {
    11 - ((index + 1) as u32)
}

impl Validator for NhsCheckDigit {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // https://www.datadictionary.nhs.uk/attributes/nhs_number.html
        // The NHS number is a 10-digit number in the format 123 456 7890.

        let mut input_iter = regex_match.chars();
        let mut total_sum = 0;
        let mut nb_digit = 0;
        let mut check_digit = 0;

        while let Some(digit) = get_previous_digit(&mut input_iter) {
            if nb_digit > 10 {
                return false;
            }
            if nb_digit < 9 {
                let multiplier = nhs_multiplier_from_number_idx(nb_digit);
                total_sum += digit * multiplier;
            } else {
                check_digit = digit;
            }
            nb_digit += 1;
        }

        // Divide the total_sum by 11 and get the remainder
        let remainder = total_sum % 11;

        // Subtract the remainder from 11 to give us the total
        let mut identifier = 11 - remainder;

        // The identifier is used to compare against the check digit we extracted earlier
        // If the total is 11, we set the identifier to 0
        if identifier == 11 {
            identifier = 0;
        }

        // Finally, we check the identifier against the check digit to see if the NHS number is valid
        if identifier == 10 {
            // If the identifier is 10, we know the NHS number is INVALID
            return false;
        } else if identifier == check_digit {
            // If the identifier is equal to the check digit, we know the NHS number is VALID
            return true;
        }
        false
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_nhs_number() {
        let valid_ids = vec![
            "1234567881",
            "907 784 4449",
            "798 428 4334",
            "111 431 1456",
            "095 558 1001",
            "649 261 8610",
            "600 562 5942",
            "110 537 9787",
            "166 584 5783",
            "714 375 8426",
            "434 539 1210",
            "064 327 9288",
        ];
        for id in valid_ids {
            assert!(NhsCheckDigit.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_nhs_number() {
        let invalid_ids = vec![
            "1234567890",  // can't compute check digit
            "1234567882",  // invalid check digit
            "12345678810", // invalid length
        ];
        for id in invalid_ids {
            assert!(!NhsCheckDigit.is_valid_match(id));
        }
    }
}
