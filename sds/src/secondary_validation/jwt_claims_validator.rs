use crate::secondary_validation::Validator;
use ahash::AHashMap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", content = "config")]
pub enum ClaimRequirement {
    /// Just check that the claim exists
    Present,
    /// Check that the claim exists and has an exact value
    ExactValue(String),
    /// Check that the claim exists and matches a regex pattern
    RegexMatch(String),
}

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
pub struct JwtClaimsValidatorConfig {
    #[serde(default)]
    pub required_claims: std::collections::BTreeMap<String, ClaimRequirement>,
}

pub struct JwtClaimsValidator {
    pub required_claims: Vec<(String, ClaimRequirement)>,
    patterns: AHashMap<String, Regex>,
}

impl JwtClaimsValidator {
    pub fn new(config: JwtClaimsValidatorConfig) -> Self {
        let mut patterns = AHashMap::new();
        for (claim_name, requirement) in &config.required_claims {
            if let ClaimRequirement::RegexMatch(pattern) = requirement {
                patterns.insert(claim_name.clone(), Regex::new(pattern).unwrap());
            }
        }
        Self {
            required_claims: config.required_claims.into_iter().collect(),
            patterns,
        }
    }
}

impl Validator for JwtClaimsValidator {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        if let Some((_, payload)) = decode_segments(regex_match) {
            validate_required_claims(&payload, &self.required_claims, &self.patterns)
        } else {
            // If JWT segments cannot be decoded, the JWT is not well formatted
            false
        }
    }
}

// This function is an extraction of the decoding part from jwt_expiration_checker
// Reusing the JWT decoding logic to avoid duplication
fn decode_segments(encoded_token: &str) -> Option<(JsonValue, JsonValue)> {
    let mut raw_segments: std::str::Split<&str> = encoded_token.split(".");

    let header_segment = raw_segments.next()?;
    let payload_segment = raw_segments.next()?;

    raw_segments.next()?;

    let header_json = decode_segment(header_segment)?;
    let payload_json = decode_segment(payload_segment)?;
    Some((header_json, payload_json))
}

fn decode_segment(segment: &str) -> Option<JsonValue> {
    let decoded = URL_SAFE_NO_PAD.decode(segment).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn validate_required_claims(
    payload: &JsonValue,
    required_claims: &[(String, ClaimRequirement)],
    patterns: &AHashMap<String, Regex>,
) -> bool {
    if let Some(payload_obj) = payload.as_object() {
        // Check each required claim
        required_claims.iter().all(|(claim_name, requirement)| {
            if let Some(claim_value) = payload_obj.get(claim_name) {
                validate_claim_requirement(claim_value, requirement, patterns.get(claim_name))
            } else {
                false
            }
        })
    } else {
        false
    }
}

fn validate_claim_requirement(
    claim_value: &JsonValue,
    requirement: &ClaimRequirement,
    cached_pattern: Option<&Regex>,
) -> bool {
    match requirement {
        ClaimRequirement::Present => {
            // Just check that the claim exists (we already know it does if we're here)
            claim_value != &JsonValue::Null
        }
        ClaimRequirement::ExactValue(expected) => {
            // Check for exact string match
            if let Some(actual) = claim_value.as_str() {
                actual == expected
            } else {
                false // We only match string values
            }
        }
        ClaimRequirement::RegexMatch(_) => {
            // Check if the claim value matches the regex pattern
            if let Some(actual) = claim_value.as_str() {
                cached_pattern
                    .map(|pattern| pattern.is_match(actual))
                    .unwrap_or(false)
            } else {
                false // Can only regex match string values
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secondary_validation::jwt_claims_validator::ClaimRequirement::{
        Present, RegexMatch,
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::collections::BTreeMap;

    fn generate_jwt_with_claims(claims: &str) -> String {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}
        let payload_encoded = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        let signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        format!("{header}.{payload_encoded}.{signature}")
    }

    #[test]
    fn test_decode_segments() {
        let jwt =
            generate_jwt_with_claims(r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#);
        let result = decode_segments(&jwt);
        assert!(result.is_some());

        let (header, payload) = result.unwrap();
        assert_eq!(
            header.get("alg"),
            Some(&JsonValue::String("HS256".to_string()))
        );
        assert_eq!(
            payload.get("sub"),
            Some(&JsonValue::String("1234567890".to_string()))
        );
    }

    #[test]
    fn test_valid_jwt_with_claims_no_requirements() {
        let jwt =
            generate_jwt_with_claims(r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#);
        let config = JwtClaimsValidatorConfig::default();
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_valid_jwt_with_required_claims_present() {
        let jwt =
            generate_jwt_with_claims(r#"{"sub":"1234567890","name":"John Doe","iat":1516239022}"#);
        let mut required_claims = BTreeMap::new();
        required_claims.insert("sub".to_string(), ClaimRequirement::Present);
        required_claims.insert("name".to_string(), ClaimRequirement::Present);

        let config = JwtClaimsValidatorConfig { required_claims };
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_valid_jwt_with_exact_value_match() {
        let jwt = generate_jwt_with_claims(
            r#"{"sub":"1234567890","issuer":"my-service","role":"admin"}"#,
        );
        let mut required_claims = BTreeMap::new();
        required_claims.insert(
            "sub".to_string(),
            ClaimRequirement::ExactValue("1234567890".to_string()),
        );
        required_claims.insert(
            "issuer".to_string(),
            ClaimRequirement::ExactValue("my-service".to_string()),
        );

        let config = JwtClaimsValidatorConfig { required_claims };
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_valid_jwt_with_regex_match() {
        let jwt =
            generate_jwt_with_claims(r#"{"sub":"user-1234567890","email":"john.doe@example.com"}"#);
        let mut required_claims = BTreeMap::new();
        required_claims.insert(
            "sub".to_string(),
            ClaimRequirement::RegexMatch(r"^user-\d+$".to_string()),
        );
        required_claims.insert(
            "email".to_string(),
            ClaimRequirement::RegexMatch(r"^[^@]+@[^@]+\.[^@]+$".to_string()),
        );

        let config = JwtClaimsValidatorConfig { required_claims };
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_invalid_jwt_missing_required_claims() {
        let jwt = generate_jwt_with_claims(r#"{"sub":"1234567890","name":"John Doe"}"#);
        let mut required_claims = BTreeMap::new();
        required_claims.insert("sub".to_string(), ClaimRequirement::Present);
        required_claims.insert("aud".to_string(), ClaimRequirement::Present); // aud is missing

        let config = JwtClaimsValidatorConfig { required_claims };
        let checker = JwtClaimsValidator::new(config);
        assert!(!checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_invalid_jwt_wrong_exact_value() {
        let jwt = generate_jwt_with_claims(r#"{"sub":"1234567890","issuer":"wrong-service"}"#);
        let mut required_claims = BTreeMap::new();
        required_claims.insert(
            "issuer".to_string(),
            ClaimRequirement::ExactValue("my-service".to_string()),
        );

        let config = JwtClaimsValidatorConfig { required_claims };
        let checker = JwtClaimsValidator::new(config);
        assert!(!checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_invalid_jwt_regex_no_match() {
        let jwt = generate_jwt_with_claims(r#"{"sub":"invalid-user","email":"invalid-email"}"#);
        let mut required_claims = BTreeMap::new();
        required_claims.insert(
            "sub".to_string(),
            ClaimRequirement::RegexMatch(r"^user-\d+$".to_string()),
        );
        required_claims.insert(
            "email".to_string(),
            ClaimRequirement::RegexMatch(r"^[^@]+@[^@]+\.[^@]+$".to_string()),
        );

        let config = JwtClaimsValidatorConfig { required_claims };
        let checker = JwtClaimsValidator::new(config);
        assert!(!checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_mixed_claim_requirements() {
        let jwt = generate_jwt_with_claims(
            r#"{"sub":"user-123","issuer":"my-service","role":"admin","email":"user@example.com"}"#,
        );
        let mut required_claims = BTreeMap::new();
        required_claims.insert(
            "sub".to_string(),
            ClaimRequirement::RegexMatch(r"^user-\d+$".to_string()),
        );
        required_claims.insert(
            "issuer".to_string(),
            ClaimRequirement::ExactValue("my-service".to_string()),
        );
        required_claims.insert("role".to_string(), ClaimRequirement::Present);
        required_claims.insert(
            "email".to_string(),
            ClaimRequirement::RegexMatch(r"^[^@]+@[^@]+\.[^@]+$".to_string()),
        );

        let config = JwtClaimsValidatorConfig { required_claims };
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_invalid_jwt_malformed() {
        let config = JwtClaimsValidatorConfig::default();
        let checker = JwtClaimsValidator::new(config);
        assert!(!checker.is_valid_match("invalid_jwt"));
    }

    #[test]
    fn test_invalid_jwt_wrong_segments() {
        let config = JwtClaimsValidatorConfig::default();
        let checker = JwtClaimsValidator::new(config);
        assert!(!checker.is_valid_match("header.payload")); // Missing signature
    }

    #[test]
    fn test_deserialize_config_present() {
        assert_eq!(
            serde_json::from_str::<JwtClaimsValidatorConfig>(
                r#"{"required_claims": {"a": {"type": "Present"}}}"#
            )
            .unwrap(),
            JwtClaimsValidatorConfig {
                required_claims: [("a".to_owned(), Present)].into()
            }
        );
    }

    #[test]
    fn test_deserialize_config_regex() {
        assert_eq!(
            serde_json::from_str::<JwtClaimsValidatorConfig>(
                r#"{"required_claims": {"a": {"type": "RegexMatch", "config": "myregex"}}}"#
            )
            .unwrap(),
            JwtClaimsValidatorConfig {
                required_claims: [("a".to_owned(), RegexMatch("myregex".to_owned()))].into()
            }
        );
    }
}
