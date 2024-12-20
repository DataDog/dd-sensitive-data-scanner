use crate::secondary_validation::Validator;

pub struct GithubTokenChecksum;

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

        let computed_checksum = crc32fast::hash(last_part[..last_part.len() - 6].as_bytes());
        let checksum = base62::decode(last_part[last_part.len() - 6..].as_bytes());

        if checksum.is_err() {
            return false;
        }

        computed_checksum as u64 == checksum.unwrap() as u64
    }
}

#[cfg(test)]
mod test {
    use crate::secondary_validation::*;
    #[test]
    fn test_valid_github_tokens() {
        let validids = vec![
            "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",
            "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",
            "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",
            "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",
            // long prefix
            "nawak_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",
            // Example with zero padding
            "b62_QdwULL38u41vs1OcAjhKqcaSZ9W63r0Zu4ln",
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
            // too short second part
            "ghp_T4V4",
        ];
        for id in invalid_ids {
            assert!(!GithubTokenChecksum.is_valid_match(id));
        }
    }
}
