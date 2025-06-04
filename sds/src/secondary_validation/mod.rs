mod aba_rtn_checksum;
mod brazilian_cnpj_checksum;
mod brazilian_cpf_checksum;
mod chinese_id_checksum;
mod france_ssn_checksum;
mod github_token_checksum;
mod iban_checker;
mod jwt_expiration_checker;
mod luhn_checksum;
mod luxembourg_individual_nin_checksum;
mod nhs_check_digit;
mod nir_checksum;
mod polish_national_id_checksum;
mod sweden_pin_checksum;
mod verhoeff_checksum;

#[cfg(test)]
pub use jwt_expiration_checker::generate_jwt;

use crate::scanner::regex_rule::config::SecondaryValidator;
pub use crate::secondary_validation::aba_rtn_checksum::AbaRtnChecksum;
pub use crate::secondary_validation::brazilian_cnpj_checksum::BrazilianCnpjChecksum;
pub use crate::secondary_validation::brazilian_cpf_checksum::BrazilianCpfChecksum;
pub use crate::secondary_validation::chinese_id_checksum::ChineseIdChecksum;
pub use crate::secondary_validation::france_ssn_checksum::FranceSsnChecksum;
pub use crate::secondary_validation::github_token_checksum::GithubTokenChecksum;
pub use crate::secondary_validation::iban_checker::IbanChecker;
pub use crate::secondary_validation::jwt_expiration_checker::JwtExpirationChecker;
pub use crate::secondary_validation::luhn_checksum::LuhnChecksum;
pub use crate::secondary_validation::luxembourg_individual_nin_checksum::LuxembourgIndividualNINChecksum;
pub use crate::secondary_validation::nhs_check_digit::NhsCheckDigit;
pub use crate::secondary_validation::nir_checksum::NirChecksum;
pub use crate::secondary_validation::polish_national_id_checksum::PolishNationalIdChecksum;
pub use crate::secondary_validation::sweden_pin_checksum::SwedenPINChecksum;
pub use crate::secondary_validation::verhoeff_checksum::VerhoeffChecksum;
use std::str::Chars;

pub trait Validator: Send + Sync {
    fn is_valid_match(&self, regex_match: &str) -> bool;
}

fn get_previous_digit(chars: &mut Chars<'_>) -> Option<u32> {
    while let Some(char) = chars.next_back() {
        if let Some(digit) = char.to_digit(10) {
            return Some(digit);
        }
    }
    None
}
fn get_next_digit(chars: &mut Chars<'_>) -> Option<u32> {
    for char in chars.by_ref() {
        if let Some(digit) = char.to_digit(10) {
            return Some(digit);
        }
    }
    None
}

/// Sum all the digits from a number
#[inline]
fn sum_all_digits(digits: u32) -> u32 {
    let mut sum = 0;
    let mut num = digits;
    while num > 0 {
        sum += num % 10;
        num /= 10;
    }
    sum
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
            SecondaryValidator::NirChecksum => NirChecksum.is_valid_match(regex_match),
            SecondaryValidator::JwtExpirationChecker => {
                JwtExpirationChecker.is_valid_match(regex_match)
            }
            SecondaryValidator::BrazilianCpfChecksum => {
                BrazilianCpfChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::BrazilianCnpjChecksum => {
                BrazilianCnpjChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::AbaRtnChecksum => AbaRtnChecksum.is_valid_match(regex_match),
            SecondaryValidator::PolishNationalIdChecksum => {
                PolishNationalIdChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::LuxembourgIndividualNINChecksum => {
                LuxembourgIndividualNINChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::FranceSsnChecksum => FranceSsnChecksum.is_valid_match(regex_match),
            SecondaryValidator::SwedenPINChecksum => SwedenPINChecksum.is_valid_match(regex_match),
        }
    }
}
