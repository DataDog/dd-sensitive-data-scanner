use iso_iec_7064::{
    System, MOD_11_10, MOD_11_2, MOD_1271_36, MOD_27_26, MOD_37_2, MOD_37_36, MOD_661_26, MOD_97_10,
};

use crate::secondary_validation::Validator;

/// Filter some characters. The str input forwarded to iso_iec_7064 should only contain valid characters.
/// Filtering some characters allows to be more flexible on the regex pattern.
fn filter_chars(input: &str) -> String {
    input
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_' | '/'))
        .collect()
}

// Pure ISO 7064

pub struct Mod11_2checksum;
impl Validator for Mod11_2checksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        MOD_11_2.validate_string(&filter_chars(regex_match).to_uppercase())
    }
}

pub struct Mod37_2checksum;
impl Validator for Mod37_2checksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        MOD_37_2.validate_string(&filter_chars(regex_match).to_uppercase())
    }
}

pub struct Mod1271_36Checksum;
impl Validator for Mod1271_36Checksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        MOD_1271_36.validate_string(&filter_chars(regex_match).to_uppercase())
    }
}

pub struct Mod661_26checksum;
impl Validator for Mod661_26checksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        MOD_661_26.validate_string(&filter_chars(regex_match).to_uppercase())
    }
}

pub struct Mod97_10checksum;
impl Validator for Mod97_10checksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        MOD_97_10.validate_string(&filter_chars(regex_match))
    }
}

// Hybrid ISO 7064

pub struct Mod11_10checksum;
impl Validator for Mod11_10checksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        MOD_11_10.validate_string(&filter_chars(regex_match))
    }
}

pub struct Mod27_26checksum;
impl Validator for Mod27_26checksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        MOD_27_26.validate_string(&filter_chars(regex_match).to_uppercase())
    }
}

pub struct Mod37_36checksum;
impl Validator for Mod37_36checksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        MOD_37_36.validate_string(&filter_chars(regex_match).to_uppercase())
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;

    #[test]
    fn test_valid_11_10() {
        let valid_numbers = vec![
            "15203607809",
            "15 203 607 809",
            "15-203_607/809",
            "26954371827",
        ];
        for numbers in valid_numbers {
            println!("testing for input {}", numbers);
            assert!(Mod11_10checksum.is_valid_match(numbers));
        }
    }

    #[test]
    fn test_invalid_11_10() {
        let valid_numbers = vec!["00 000 000 000.", "30405607809"];
        for numbers in valid_numbers {
            println!("testing for input {}", numbers);
            assert!(!Mod11_10checksum.is_valid_match(numbers));
        }
    }

    #[test]
    fn test_valid_11_2() {
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
            println!("testing for input {}", id);
            assert!(Mod11_2checksum.is_valid_match(id));
        }
    }

    #[test]
    fn test_invalid_11_2() {
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
            println!("testing for input {}", id);
            assert!(!Mod11_2checksum.is_valid_match(id));
        }
    }
}
