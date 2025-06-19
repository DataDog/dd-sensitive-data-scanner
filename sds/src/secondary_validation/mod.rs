mod aba_rtn_checksum;
mod brazilian_cnpj_checksum;
mod brazilian_cpf_checksum;
mod btc_checksum;
mod chinese_id_checksum;
mod coordination_number_checksum;
mod czech_tin_checksum;
mod dutch_bsn_checksum;
mod dutch_passport_checksum;
mod ethereum_checksum;
mod finnish_hetu_checksum;
mod france_nif_checksum;
mod france_ssn_checksum;
mod german_ids_checksum;
mod german_svnr_checksum;
mod github_token_checksum;
mod greece_tin_checksum;
mod hungarian_tin_checksum;
mod iban_checker;
mod irish_pps_checksum;
mod iso_7064_checksum;
mod italian_national_id_checksum;
mod jwt_expiration_checker;
mod latvia_national_id_checksum;
mod lithuanian_personal_identification_number_checksum;
mod luhn_checksum;
mod luxembourg_individual_nin_checksum;
mod monero_address;
mod nhs_check_digit;
mod nir_checksum;
mod polish_national_id_checksum;
mod polish_nip_checksum;
mod portuguese_tax_id_checksum;
mod rodne_cislo_checksum;
mod romanian_personal_numeric_code;
mod slovenian_pin_checksum;
mod spain_dni_checksum;
mod spanish_nuss_checksum;
mod sweden_pin_checksum;
mod verhoeff_checksum;
#[cfg(test)]
pub use jwt_expiration_checker::generate_jwt;

use crate::scanner::regex_rule::config::SecondaryValidator;
pub use crate::secondary_validation::aba_rtn_checksum::AbaRtnChecksum;
pub use crate::secondary_validation::brazilian_cnpj_checksum::BrazilianCnpjChecksum;
pub use crate::secondary_validation::brazilian_cpf_checksum::BrazilianCpfChecksum;
pub use crate::secondary_validation::btc_checksum::BtcChecksum;
pub use crate::secondary_validation::chinese_id_checksum::ChineseIdChecksum;
pub use crate::secondary_validation::coordination_number_checksum::CoordinationNumberChecksum;
pub use crate::secondary_validation::czech_tin_checksum::CzechTaxIdentificationNumberChecksum;
pub use crate::secondary_validation::dutch_bsn_checksum::DutchDsnChecksum;
pub use crate::secondary_validation::dutch_passport_checksum::DutchPassportChecksum;
pub use crate::secondary_validation::ethereum_checksum::EthereumChecksum;
pub use crate::secondary_validation::finnish_hetu_checksum::FinnishHetuChecksum;
use crate::secondary_validation::france_nif_checksum::FranceNifChecksum;
pub use crate::secondary_validation::france_ssn_checksum::FranceSsnChecksum;
pub use crate::secondary_validation::german_ids_checksum::GermanIdsChecksum;
pub use crate::secondary_validation::german_svnr_checksum::GermanSvnrChecksum;
pub use crate::secondary_validation::github_token_checksum::GithubTokenChecksum;
pub use crate::secondary_validation::greece_tin_checksum::GreekTinChecksum;
pub use crate::secondary_validation::hungarian_tin_checksum::HungarianTinChecksum;
pub use crate::secondary_validation::iban_checker::IbanChecker;
pub use crate::secondary_validation::irish_pps_checksum::IrishPpsChecksum;
pub use crate::secondary_validation::iso_7064_checksum::{
    Mod11_10checksum, Mod11_2checksum, Mod1271_36Checksum, Mod27_26checksum, Mod37_2checksum,
    Mod37_36checksum, Mod661_26checksum, Mod97_10checksum,
};
pub use crate::secondary_validation::italian_national_id_checksum::ItalianNationalIdChecksum;
pub use crate::secondary_validation::jwt_expiration_checker::JwtExpirationChecker;
pub use crate::secondary_validation::latvia_national_id_checksum::LatviaNationalIdChecksum;
use crate::secondary_validation::lithuanian_personal_identification_number_checksum::LithuanianPersonalIdentificationNumberChecksum;
pub use crate::secondary_validation::luhn_checksum::LuhnChecksum;
pub use crate::secondary_validation::luxembourg_individual_nin_checksum::LuxembourgIndividualNINChecksum;
pub use crate::secondary_validation::monero_address::MoneroAddress;
pub use crate::secondary_validation::nhs_check_digit::NhsCheckDigit;
pub use crate::secondary_validation::nir_checksum::NirChecksum;
pub use crate::secondary_validation::polish_national_id_checksum::PolishNationalIdChecksum;
pub use crate::secondary_validation::polish_nip_checksum::PolishNipChecksum;
pub use crate::secondary_validation::portuguese_tax_id_checksum::PortugueseTaxIdChecksum;
pub use crate::secondary_validation::rodne_cislo_checksum::RodneCisloNumberChecksum;
pub use crate::secondary_validation::romanian_personal_numeric_code::RomanianPersonalNumericCode;
pub use crate::secondary_validation::slovenian_pin_checksum::SlovenianPINChecksum;
pub use crate::secondary_validation::spain_dni_checksum::SpanishDniChecksum;
pub use crate::secondary_validation::spanish_nuss_checksum::SpanishNussChecksum;
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
            SecondaryValidator::FranceSsnChecksum => FranceSsnChecksum.is_valid_match(regex_match),
            SecondaryValidator::Mod11_2checksum => Mod11_2checksum.is_valid_match(regex_match),
            SecondaryValidator::Mod37_2checksum => Mod37_2checksum.is_valid_match(regex_match),
            SecondaryValidator::Mod1271_36Checksum => {
                Mod1271_36Checksum.is_valid_match(regex_match)
            }
            SecondaryValidator::Mod661_26checksum => Mod661_26checksum.is_valid_match(regex_match),
            SecondaryValidator::Mod97_10checksum => Mod97_10checksum.is_valid_match(regex_match),
            SecondaryValidator::Mod11_10checksum => Mod11_10checksum.is_valid_match(regex_match),
            SecondaryValidator::Mod27_26checksum => Mod27_26checksum.is_valid_match(regex_match),
            SecondaryValidator::Mod37_36checksum => Mod37_36checksum.is_valid_match(regex_match),
            SecondaryValidator::NirChecksum => NirChecksum.is_valid_match(regex_match),
            SecondaryValidator::GreekTinChecksum => GreekTinChecksum.is_valid_match(regex_match),
            SecondaryValidator::ItalianNationalIdChecksum => {
                ItalianNationalIdChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::JwtExpirationChecker => {
                JwtExpirationChecker.is_valid_match(regex_match)
            }
            SecondaryValidator::BrazilianCpfChecksum => {
                BrazilianCpfChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::BrazilianCnpjChecksum => {
                BrazilianCnpjChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::BtcChecksum => BtcChecksum.is_valid_match(regex_match),
            SecondaryValidator::AbaRtnChecksum => AbaRtnChecksum.is_valid_match(regex_match),
            SecondaryValidator::PolishNationalIdChecksum => {
                PolishNationalIdChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::PolishNipChecksum => PolishNipChecksum.is_valid_match(regex_match),
            SecondaryValidator::LuxembourgIndividualNINChecksum => {
                LuxembourgIndividualNINChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::CzechTaxIdentificationNumberChecksum => {
                CzechTaxIdentificationNumberChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::HungarianTinChecksum => {
                HungarianTinChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::CzechPersonalIdentificationNumberChecksum => {
                RodneCisloNumberChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::SpanishNussChecksum => {
                SpanishNussChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::DutchPassportChecksum => {
                DutchPassportChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::DutchDsnChecksum => DutchDsnChecksum.is_valid_match(regex_match),
            SecondaryValidator::FranceNifChecksum => FranceNifChecksum.is_valid_match(regex_match),
            SecondaryValidator::GermanSvnrChecksum => {
                GermanSvnrChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::SwedenPINChecksum => SwedenPINChecksum.is_valid_match(regex_match),
            SecondaryValidator::LatviaNationalIdChecksum => {
                LatviaNationalIdChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::CoordinationNumberChecksum => {
                CoordinationNumberChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::LithuanianPersonalIdentificationNumberChecksum => {
                LithuanianPersonalIdentificationNumberChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::GermanIdsChecksum => GermanIdsChecksum.is_valid_match(regex_match),
            SecondaryValidator::SpanishDniChecksum => {
                SpanishDniChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::SlovenianPINChecksum => {
                SlovenianPINChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::FinnishHetuChecksum => {
                FinnishHetuChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::IrishPpsChecksum => IrishPpsChecksum.is_valid_match(regex_match),
            SecondaryValidator::PortugueseTaxIdChecksum => {
                PortugueseTaxIdChecksum.is_valid_match(regex_match)
            }
            SecondaryValidator::RomanianPersonalNumericCode => {
                RomanianPersonalNumericCode.is_valid_match(regex_match)
            }
            SecondaryValidator::EthereumChecksum => EthereumChecksum.is_valid_match(regex_match),
            SecondaryValidator::MoneroAddress => MoneroAddress.is_valid_match(regex_match),
        }
    }
}
