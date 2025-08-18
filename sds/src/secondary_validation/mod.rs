mod aba_rtn_checksum;
mod brazilian_cnpj_checksum;
mod brazilian_cpf_checksum;
mod btc_checksum;
mod bulgarian_egn_checksum;
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
pub mod jwt_claims_checker;
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
pub use crate::secondary_validation::bulgarian_egn_checksum::BulgarianEGNChecksum;
pub use crate::secondary_validation::chinese_id_checksum::ChineseIdChecksum;
pub use crate::secondary_validation::coordination_number_checksum::CoordinationNumberChecksum;
pub use crate::secondary_validation::czech_tin_checksum::CzechTaxIdentificationNumberChecksum;
pub use crate::secondary_validation::dutch_bsn_checksum::DutchBsnChecksum;
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
    Mod11_2checksum, Mod11_10checksum, Mod27_26checksum, Mod37_2checksum, Mod37_36checksum,
    Mod97_10checksum, Mod661_26checksum, Mod1271_36Checksum,
};
pub use crate::secondary_validation::italian_national_id_checksum::ItalianNationalIdChecksum;
pub use crate::secondary_validation::jwt_claims_checker::JwtClaimsChecker;
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
use std::sync::Arc;

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

impl SecondaryValidator {
    pub fn compile(&self) -> Arc<dyn Validator> {
        match self {
            SecondaryValidator::AbaRtnChecksum => Arc::new(AbaRtnChecksum),
            SecondaryValidator::BrazilianCnpjChecksum => Arc::new(BrazilianCnpjChecksum),
            SecondaryValidator::BrazilianCpfChecksum => Arc::new(BrazilianCpfChecksum),
            SecondaryValidator::BtcChecksum => Arc::new(BtcChecksum),
            SecondaryValidator::BulgarianEGNChecksum => Arc::new(BulgarianEGNChecksum),
            SecondaryValidator::ChineseIdChecksum => Arc::new(ChineseIdChecksum),
            SecondaryValidator::CoordinationNumberChecksum => Arc::new(CoordinationNumberChecksum),
            SecondaryValidator::CzechPersonalIdentificationNumberChecksum => {
                Arc::new(RodneCisloNumberChecksum)
            }
            SecondaryValidator::CzechTaxIdentificationNumberChecksum => {
                Arc::new(CzechTaxIdentificationNumberChecksum)
            }
            SecondaryValidator::DutchBsnChecksum => Arc::new(DutchBsnChecksum),
            SecondaryValidator::DutchPassportChecksum => Arc::new(DutchPassportChecksum),
            SecondaryValidator::EthereumChecksum => Arc::new(EthereumChecksum),
            SecondaryValidator::FinnishHetuChecksum => Arc::new(FinnishHetuChecksum),
            SecondaryValidator::FranceNifChecksum => Arc::new(FranceNifChecksum),
            SecondaryValidator::FranceSsnChecksum => Arc::new(FranceSsnChecksum),
            SecondaryValidator::GermanIdsChecksum => Arc::new(GermanIdsChecksum),
            SecondaryValidator::GermanSvnrChecksum => Arc::new(GermanSvnrChecksum),
            SecondaryValidator::GithubTokenChecksum => Arc::new(GithubTokenChecksum),
            SecondaryValidator::GreekTinChecksum => Arc::new(GreekTinChecksum),
            SecondaryValidator::HungarianTinChecksum => Arc::new(HungarianTinChecksum),
            SecondaryValidator::IbanChecker => Arc::new(IbanChecker),
            SecondaryValidator::IrishPpsChecksum => Arc::new(IrishPpsChecksum),
            SecondaryValidator::ItalianNationalIdChecksum => Arc::new(ItalianNationalIdChecksum),
            SecondaryValidator::JwtClaimsChecker { config } => {
                Arc::new(JwtClaimsChecker::new(config.clone()))
            }
            SecondaryValidator::JwtExpirationChecker => Arc::new(JwtExpirationChecker),
            SecondaryValidator::LatviaNationalIdChecksum => Arc::new(LatviaNationalIdChecksum),
            SecondaryValidator::LithuanianPersonalIdentificationNumberChecksum => {
                Arc::new(LithuanianPersonalIdentificationNumberChecksum)
            }
            SecondaryValidator::LuhnChecksum => Arc::new(LuhnChecksum),
            SecondaryValidator::LuxembourgIndividualNINChecksum => {
                Arc::new(LuxembourgIndividualNINChecksum)
            }
            SecondaryValidator::Mod11_10checksum => Arc::new(Mod11_10checksum),
            SecondaryValidator::Mod11_2checksum => Arc::new(Mod11_2checksum),
            SecondaryValidator::Mod1271_36Checksum => Arc::new(Mod1271_36Checksum),
            SecondaryValidator::Mod27_26checksum => Arc::new(Mod27_26checksum),
            SecondaryValidator::Mod37_2checksum => Arc::new(Mod37_2checksum),
            SecondaryValidator::Mod37_36checksum => Arc::new(Mod37_36checksum),
            SecondaryValidator::Mod661_26checksum => Arc::new(Mod661_26checksum),
            SecondaryValidator::Mod97_10checksum => Arc::new(Mod97_10checksum),
            SecondaryValidator::MoneroAddress => Arc::new(MoneroAddress),
            SecondaryValidator::NhsCheckDigit => Arc::new(NhsCheckDigit),
            SecondaryValidator::NirChecksum => Arc::new(NirChecksum),
            SecondaryValidator::PolishNationalIdChecksum => Arc::new(PolishNationalIdChecksum),
            SecondaryValidator::PolishNipChecksum => Arc::new(PolishNipChecksum),
            SecondaryValidator::PortugueseTaxIdChecksum => Arc::new(PortugueseTaxIdChecksum),
            SecondaryValidator::RodneCisloNumberChecksum => Arc::new(RodneCisloNumberChecksum),
            SecondaryValidator::RomanianPersonalNumericCode => {
                Arc::new(RomanianPersonalNumericCode)
            }
            SecondaryValidator::SlovenianPINChecksum => Arc::new(SlovenianPINChecksum),
            SecondaryValidator::SpanishDniChecksum => Arc::new(SpanishDniChecksum),
            SecondaryValidator::SpanishNussChecksum => Arc::new(SpanishNussChecksum),
            SecondaryValidator::SwedenPINChecksum => Arc::new(SwedenPINChecksum),
        }
    }
}
