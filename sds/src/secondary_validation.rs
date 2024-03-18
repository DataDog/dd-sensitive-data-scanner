use crate::rule::SecondaryValidator;
use std::str::Chars;

pub trait Validator: Send + Sync {
    fn is_valid_match(&self, regex_match: &str) -> bool;
}

/// Apply the Luhn checksum on digit values in the match
pub struct LuhnChecksum;
pub struct ChineseIdChecksum;
pub struct GithubTokenChecksum;

impl Validator for SecondaryValidator {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        match self {
            SecondaryValidator::LuhnChecksum => LuhnChecksum.is_valid_match(regex_match),
            SecondaryValidator::ChineseIdChecksum => ChineseIdChecksum.is_valid_match(regex_match),
            SecondaryValidator::GithubTokenChecksum => {
                GithubTokenChecksum.is_valid_match(regex_match)
            }
        }
    }
}

impl Validator for LuhnChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut input_iter = regex_match.chars();

        fn get_next_digit(chars: &mut Chars<'_>) -> Option<u32> {
            while let Some(char) = chars.next_back() {
                if let Some(digit) = char.to_digit(10) {
                    return Some(digit);
                }
            }
            None
        }

        if let Some(checksum) = get_next_digit(&mut input_iter) {
            let mut sum: u32 = 0;
            let mut is_odd = false;
            while let Some(digit) = get_next_digit(&mut input_iter) {
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

const CHINESE_ID_LENGTH: usize = 18;
const CHINESE_ID_COEFFICIENTS: &[i32] = &[7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];

impl Validator for ChineseIdChecksum {
    // https://en.wikipedia.org/wiki/Resident_Identity_Card
    //  Last digit checksum cf ISO 7064:1983, MOD 11-2.
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Check if the length of the ID is correct
        if regex_match.len() != CHINESE_ID_LENGTH {
            return false;
        }

        // Check if all characters are digits except the last one
        // Compute the sum to compute checksum later on
        let mut sum = 0;
        for (idx, c) in regex_match.chars().take(CHINESE_ID_LENGTH - 1).enumerate() {
            if let Some(x) = c.to_digit(10) {
                sum += CHINESE_ID_COEFFICIENTS[idx] * x as i32;
            } else {
                return false;
            }
        }

        // Compute the checksum
        let checksum = match sum % 11 {
            0 => '1',
            1 => '0',
            2 => 'X',
            // Convert the remainder to ascii value then to char
            _ => (12 - sum % 11 + '0' as i32) as u8 as char,
        };

        // Compare the computed checksum with the provided one
        regex_match
            .chars()
            .next_back()
            .unwrap()
            .to_ascii_uppercase()
            == checksum
    }
}

impl Validator for GithubTokenChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        // Implementation of https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
        let parts: Vec<&str> = regex_match.split('_').collect();
        if parts.len() < 2 {
            return false;
        }
        let last_part = parts.last().unwrap();
        // check that last part is only made with base62 chars
        if !last_part.chars().all(|c| c.is_ascii_alphanumeric()) {
            return false;
        }

        // check that last part has more than 6 chars
        if last_part.len() <= 6 {
            return false;
        }

        // extract the payload (everything except the last 6 chars)
        let computed_checksum = crc32fast::hash(last_part[..last_part.len() - 6].as_bytes());
        let computed_checksum_b62 = base62::encode(computed_checksum);
        // check that the crc is the last 6 chars
        computed_checksum_b62 == last_part[last_part.len() - 6..]
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

    #[test]
    fn test_valid_chinese_ids() {
        let valid_ids = vec![
            "513231200012121657",
            "513231200012121673",
            "51323120001212169X",
            "513231200012121710",
            "513231200012121737",
            "513231200012121753",
            "513231200012121294",
            "51323120001212177X",
            "513231200012121796",
            "513231200012121817",
            "513231200012121833",
            "51323120001212185X",
            // Same with lowercase x should work
            "51323120001212185x",
            "513231200012121876",
            "513231200012121892",
        ];
        for id in valid_ids {
            assert!(ChineseIdChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_chinese_ids() {
        let invalid_ids = vec![
            // wrong checksum
            "513231200012121293",
            // non digit characters
            "a13231200012121293",
            // wrong length
            "a1323120001212129",
            // Non utf-8 characters 18 bytes
            "513231200012Àñô",
        ];
        for id in invalid_ids {
            assert!(!ChineseIdChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_valid_github_tokens() {
        let validids = vec![
            "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",
            "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",
            "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",
            "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",
            "nawak_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",
        ];
        for id in validids {
            assert!(GithubTokenChecksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_github_tokens() {
        let invalid_ids = vec![
            "ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V3",
            // Non utf-8 characters 18 bytes
            "ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4Vñ",
            // Non base62 characters
            "ghp_M7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V/",
            // No sep
            "ghpM7H4jxUDDWHP4kZ6A4dxlQYsQIWJuq11T4V4",
        ];
        for id in invalid_ids {
            assert!(!GithubTokenChecksum.is_valid_match(id));
        }
    }
}
