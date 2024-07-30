use crate::secondary_validation::{get_previous_digit, Validator};

pub struct LuhnChecksum;

impl Validator for LuhnChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut input_iter = regex_match.chars();

        if let Some(checksum) = get_previous_digit(&mut input_iter) {
            let mut sum: u32 = 0;
            let mut is_odd = false;
            while let Some(digit) = get_previous_digit(&mut input_iter) {
                if is_odd {
                    sum += digit
                } else if digit > 4 {
                    sum += digit * 2 - 9;
                } else {
                    sum += digit * 2
                }
                is_odd = !is_odd;
            }
            return (10 - (sum % 10)) % 10 == checksum;
        }
        false
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_various_credit_cards() {
        let credit_cards = vec![
            // source https://www.paypalobjects.com/en_AU/vhelp/paypalmanager_help/credit_card_numbers.htm
            // American Express
            "3782 822463 10005",
            "3714 4963 5398 431",
            // American Express Corporate
            "378734493671000",
            // Australian BankCard
            "5610591081018250",
            // Diners Club
            "3056 930902 5904",
            "3852 0000 0232 37",
            // Discover
            "6011111111111117",
            "6011 0009 9013 9424",
            // JCB
            "3530111333300000",
            "35660020 20360505",
            // MasterCard
            "5555555555554444",
            "5105 1051 0510 5100",
            // Visa
            "4111 1111 1111 1111",
            "40128888 88881881",
            "4222222222222",
            // Dankort (PBS)
            "5019717010103742",
            // Switch/Solo (Paymentech)
            "6331101999990016",
        ];
        for credit_card in credit_cards {
            println!("credit card input: {}", credit_card);
            assert!(LuhnChecksum.is_valid_match(credit_card));

            let (split_credit_card, last_digit) = credit_card.split_at(credit_card.len() - 1);
            let mut wrong_credit_card = split_credit_card.to_string();
            wrong_credit_card
                .push_str(&((last_digit.parse::<u32>().unwrap() + 1) * 2 % 10).to_string());

            println!("wrong credit card input: {}", wrong_credit_card);

            assert!(!LuhnChecksum.is_valid_match(&wrong_credit_card));
        }
    }

    #[test]
    fn skip_non_digit_characters() {
        assert!(LuhnChecksum.is_valid_match("378282246310005"));
        // Same credit card with space and non-digit characters
        assert!(LuhnChecksum.is_valid_match("3 7 8 2 8 2 2 4ABC, 6 3 1 🎅0 0 0 5"));
    }
}
