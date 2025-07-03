use crate::secondary_validation::Validator;

pub struct LatviaNationalIdChecksum;

const LATVIA_NATIONAL_ID_OLD_FORMAT_MULTIPLIERS: &[u32; 10] = &[1, 6, 3, 7, 9, 10, 5, 8, 4, 2];

impl Validator for LatviaNationalIdChecksum {
    // https://en.wikipedia.org/wiki/National_identification_number
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let mut digits = regex_match.chars().filter_map(|c| c.to_digit(10));
        let first_2_digits: Vec<u32> = digits.clone().take(2).collect();
        // No checksum validation needed for the new format
        if first_2_digits == vec![3, 2] {
            return true;
        }

        let mut sum = 0;
        for (index, digit) in digits
            .by_ref()
            .take(LATVIA_NATIONAL_ID_OLD_FORMAT_MULTIPLIERS.len())
            .enumerate()
        {
            let multiplier = LATVIA_NATIONAL_ID_OLD_FORMAT_MULTIPLIERS[index];
            sum += digit * multiplier;
        }

        if let Some(actual_checksum) = digits.next() {
            let computed_checksum = ((1101 - sum) % 11) % 10;
            return actual_checksum == computed_checksum;
        }
        false
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn validate_latvia_national_ids() {
        let old_latvia_national_ids = vec![
            // old format
            "121282-11210",
            "280794-12344",
        ];
        for id in old_latvia_national_ids {
            println!("Old latvia national identification number: {id}");
            assert!(LatviaNationalIdChecksum.is_valid_match(id));

            let checksum = id.chars().last().unwrap();
            let id_without_checksum = &id[..id.len() - 1];

            let mut invalid_checksum = id_without_checksum.to_string();
            invalid_checksum.push_str(&((checksum.to_digit(10).unwrap() + 1) % 10).to_string());
            println!(
                "latvia national identification number with invalid checksum: {invalid_checksum}"
            );
            assert!(!LatviaNationalIdChecksum.is_valid_match(&invalid_checksum));
        }

        let new_latvia_national_ids = vec![
            // new format
            "320010-10002",
            "32001010003",
        ];
        for id in new_latvia_national_ids {
            println!("New latvia national identification number: {id}");
            assert!(LatviaNationalIdChecksum.is_valid_match(id));
        }
    }
}
