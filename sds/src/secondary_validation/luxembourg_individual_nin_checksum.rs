use crate::secondary_validation::{LuhnChecksum, Validator, VerhoeffChecksum};

pub struct LuxembourgIndividualNINChecksum;

const LUXEMBOURG_INDIVIDUALS_NIN_LENGTH: usize = 13;

impl Validator for LuxembourgIndividualNINChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        /*
         * Luxembourg uses a 13-digit identification code,
         * consisting of the birth date formatted as YYYYMMDD followed by a number XXX
         * ensuring persons born on the same date have a unique national ID,
         * then a first check on YYYYMMDDXXX using the Luhn10 algorithm,
         * and finally a check on YYYYMMDDXXX using the Verhoeff algorithm.
         */
        if regex_match.len() != LUXEMBOURG_INDIVIDUALS_NIN_LENGTH {
            return false;
        }

        if !regex_match.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }

        let verhoeff_digit = regex_match.chars().last().unwrap();
        let luhn_digit = regex_match.chars().nth_back(1).unwrap();
        let nin_without_checksum = &regex_match[..regex_match.len() - 2];

        let mut with_luhn_checksum = nin_without_checksum.to_string();
        with_luhn_checksum.push_str(&luhn_digit.to_string());
        if !LuhnChecksum.is_valid_match(&with_luhn_checksum) {
            return false;
        }

        let mut with_verhoeff_checksum = nin_without_checksum.to_string();
        with_verhoeff_checksum.push_str(&verhoeff_digit.to_string());
        if !VerhoeffChecksum.is_valid_match(&with_verhoeff_checksum) {
            return false;
        }

        true
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_luxembourg_individual_nins() {
        /*
         * Check digits generated with random birth dates and a random number of 3 digits
         * Luhn checksum digit computed through https://simplycalc.com/luhn-calculate.php
         * Verhoeff checksum digit computed through https://kik.amc.nl/home/rcornet/verhoeff.html
         */
        let luxembourg_nins = vec![
            "1990093012358",
            "1993102814564",
            "2001120308757",
            "1979122003208",
            "1966051507682",
        ];
        for nin in luxembourg_nins {
            println!("luxembourg national identification number: {}", nin);
            assert!(LuxembourgIndividualNINChecksum.is_valid_match(nin));

            let verhoeff_digit = nin.chars().last().unwrap();
            let luhn_digit = nin.chars().nth(nin.len() - 2).unwrap();
            let nin_without_checksum = &nin[..nin.len() - 2];

            let mut invalid_verhoeff_nin = nin_without_checksum.to_string();
            invalid_verhoeff_nin.push_str(&luhn_digit.to_string());
            invalid_verhoeff_nin
                .push_str(&((verhoeff_digit.to_digit(10).unwrap() + 1) % 10).to_string());
            println!(
                "luxembourg national identification number with invalid verhoeff checksum: {}",
                invalid_verhoeff_nin
            );
            assert!(!LuxembourgIndividualNINChecksum.is_valid_match(&invalid_verhoeff_nin));

            let mut invalid_luhn_nin = nin_without_checksum.to_string();
            invalid_luhn_nin.push_str(&((luhn_digit.to_digit(10).unwrap() + 1) % 10).to_string());
            invalid_luhn_nin.push_str(&verhoeff_digit.to_string());
            println!(
                "luxembourg national identification number with invalid luhn checksum: {}",
                invalid_luhn_nin
            );
            assert!(!LuxembourgIndividualNINChecksum.is_valid_match(&invalid_luhn_nin));
        }
    }
}
