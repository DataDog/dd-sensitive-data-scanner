use crate::secondary_validation::{Mod11_2checksum, Validator};

pub struct ChineseIdChecksum;

impl Validator for ChineseIdChecksum {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        Mod11_2checksum.is_valid_match(regex_match)
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
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
            println!("testing for input {id}");
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
            println!("testing for input {id}");
            assert!(!ChineseIdChecksum.is_valid_match(id));
        }
    }
}
