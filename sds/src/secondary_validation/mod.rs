mod chinese_id_checksum;
mod github_token_checksum;
mod iban_checker;
mod luhn_checksum;
mod nhs_check_digit;

pub use crate::secondary_validation::chinese_id_checksum::ChineseIdChecksum;
pub use crate::secondary_validation::github_token_checksum::GithubTokenChecksum;
pub use crate::secondary_validation::iban_checker::IbanChecker;
pub use crate::secondary_validation::luhn_checksum::LuhnChecksum;
pub use crate::secondary_validation::nhs_check_digit::NhsCheckDigit;

use crate::scanner::regex_rule::config::SecondaryValidator;
use std::str::Chars;

pub trait Validator: Send + Sync {
    fn is_valid_match(&self, regex_match: &str) -> bool;
}

fn get_next_digit(chars: &mut Chars<'_>) -> Option<u32> {
    while let Some(char) = chars.next_back() {
        if let Some(digit) = char.to_digit(10) {
            return Some(digit);
        }
    }
    None
}

impl Validator for SecondaryValidator {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        match self {
            SecondaryValidator::LuhnChecksum => LuhnChecksum.is_valid_match(regex_match),
            SecondaryValidator::ChineseIdChecksum => ChineseIdChecksum.is_valid_match(regex_match),
            SecondaryValidator::GithubTokenChecksum => {
                GithubTokenChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::NhsCheckDigit => NhsCheckDigit.is_valid_match(regex_match),
            SecondaryValidator::IbanChecker => IbanChecker.is_valid_match(regex_match),
        }
    }
}
