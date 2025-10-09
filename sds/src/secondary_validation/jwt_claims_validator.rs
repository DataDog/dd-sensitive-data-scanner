use crate::scanner::regex_rule::config::{ClaimRequirement, JwtClaimsValidatorConfig};
use crate::secondary_validation::Validator;
use ahash::AHashMap;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use regex::Regex;
use serde_json::Value as JsonValue;

pub struct JwtClaimsValidator {
    pub header_required_claims: Vec<(String, ClaimRequirement)>,
    pub payload_required_claims: Vec<(String, ClaimRequirement)>,
    header_patterns: AHashMap<String, Regex>,
    payload_patterns: AHashMap<String, Regex>,
}

impl JwtClaimsValidator {
    pub fn new(config: JwtClaimsValidatorConfig) -> Self {
        let mut payload_patterns = AHashMap::new();
        let mut header_patterns = AHashMap::new();

        for (claim_name, requirement) in &config.required_claims {
            if let ClaimRequirement::RegexMatch(pattern) = requirement {
                payload_patterns.insert(claim_name.clone(), Regex::new(pattern).unwrap());
            }
        }

        for (claim_name, requirement) in &config.required_headers {
            if let ClaimRequirement::RegexMatch(pattern) = requirement {
                header_patterns.insert(claim_name.clone(), Regex::new(pattern).unwrap());
            }
        }

        Self {
            header_required_claims: config.required_headers.into_iter().collect(),
            payload_required_claims: config.required_claims.into_iter().collect(),
            header_patterns,
            payload_patterns,
        }
    }
}

impl Validator for JwtClaimsValidator {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        if let Some((header, payload)) = decode_segments(regex_match) {
            validate_required_claims(
                &payload,
                &self.payload_required_claims,
                &self.payload_patterns,
            ) && validate_required_claims(
                &header,
                &self.header_required_claims,
                &self.header_patterns,
            )
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
    if required_claims.is_empty() {
        true
    } else if let Some(payload_obj) = payload.as_object() {
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
        ClaimRequirement::NotExpired => {
            // Check that the claim exists and is not expired
            if let Some(claim_value) = claim_value.as_i64() {
                let now = Utc::now().timestamp();
                claim_value > now
            } else {
                // if the expiration claim is not an integer, we consider it as an invalid match
                // exp is a reserved claim for NumericDate (https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)
                // The NumericDate is the UNIX timestamp (https://www.rfc-editor.org/rfc/rfc7519#section-2)
                false
            }
        }
        ClaimRequirement::ExactValue(expected) => {
            // Check for exact string match
            if let Some(actual) = claim_value.as_str() {
                actual == expected
            } else if let Some(actual) = claim_value.as_number() {
                actual.to_string() == *expected
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
            } else if let Some(actual) = claim_value.as_number() {
                cached_pattern
                    .map(|pattern| pattern.is_match(&actual.to_string()))
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
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use std::collections::BTreeMap;

    fn generate_jwt_with_claims(claims: &str) -> String {
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}
        let payload_encoded = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        format!("{header}.{payload_encoded}.sign")
    }

    fn generate_jwt_with_header_and_claims(header_json: &str, claims: &str) -> String {
        let header_encoded = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        let payload_encoded = URL_SAFE_NO_PAD.encode(claims.as_bytes());
        format!("{header_encoded}.{payload_encoded}.sign")
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

        let config = JwtClaimsValidatorConfig {
            required_claims,
            required_headers: BTreeMap::new(),
        };
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

        let config = JwtClaimsValidatorConfig {
            required_claims,
            required_headers: BTreeMap::new(),
        };
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

        let config = JwtClaimsValidatorConfig {
            required_claims,
            required_headers: BTreeMap::new(),
        };
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_invalid_jwt_missing_required_claims() {
        let jwt = generate_jwt_with_claims(r#"{"sub":"1234567890","name":"John Doe"}"#);
        let mut required_claims = BTreeMap::new();
        required_claims.insert("sub".to_string(), ClaimRequirement::Present);
        required_claims.insert("aud".to_string(), ClaimRequirement::Present); // aud is missing

        let config = JwtClaimsValidatorConfig {
            required_claims,
            required_headers: BTreeMap::new(),
        };
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

        let config = JwtClaimsValidatorConfig {
            required_claims,
            required_headers: BTreeMap::new(),
        };
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

        let config = JwtClaimsValidatorConfig {
            required_claims,
            required_headers: BTreeMap::new(),
        };
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

        let config = JwtClaimsValidatorConfig {
            required_claims,
            required_headers: BTreeMap::new(),
        };
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
                required_claims: [("a".to_owned(), ClaimRequirement::Present)].into(),
                required_headers: BTreeMap::new()
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
                required_claims: [(
                    "a".to_owned(),
                    ClaimRequirement::RegexMatch("myregex".to_owned())
                )]
                .into(),
                required_headers: BTreeMap::new()
            }
        );
    }

    #[test]
    fn test_deserialize_config_with_headers() {
        assert_eq!(
            serde_json::from_str::<JwtClaimsValidatorConfig>(
                r#"{"required_claims": {"sub": {"type": "Present"}}, "required_headers": {"kid": {"type": "ExactValue", "config": "key-123"}}}"#
            )
            .unwrap(),
            JwtClaimsValidatorConfig {
                required_claims: [("sub".to_owned(), ClaimRequirement::Present)].into(),
                required_headers: [("kid".to_owned(), ClaimRequirement::ExactValue("key-123".to_owned()))].into()
            }
        );
    }

    #[test]
    fn test_header_claim_validation() {
        // Create a JWT with custom header containing a "kid" claim
        let header_json = r#"{"alg":"HS256","typ":"JWT","kid":"key-123"}"#;
        let payload_json = r#"{"sub":"1234567890","name":"John Doe"}"#;
        let jwt = generate_jwt_with_header_and_claims(header_json, payload_json);

        // Configure validator to require "kid" claim in header
        let mut required_headers = BTreeMap::new();
        required_headers.insert("kid".to_string(), ClaimRequirement::Present);

        let config = JwtClaimsValidatorConfig {
            required_claims: BTreeMap::new(),
            required_headers,
        };
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_header_claim_validation_with_exact_value() {
        // Create a JWT with custom header containing a "kid" claim
        let header_json = r#"{"alg":"HS256","typ":"JWT","kid":"key-123","env":"production"}"#;
        let payload_json = r#"{"sub":"1234567890","name":"John Doe"}"#;
        let jwt = generate_jwt_with_header_and_claims(header_json, payload_json);

        // Configure validator to require specific values in header
        let mut required_headers = BTreeMap::new();
        required_headers.insert(
            "kid".to_string(),
            ClaimRequirement::ExactValue("key-123".to_string()),
        );
        required_headers.insert(
            "env".to_string(),
            ClaimRequirement::ExactValue("production".to_string()),
        );

        let config = JwtClaimsValidatorConfig {
            required_claims: BTreeMap::new(),
            required_headers,
        };
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_header_vs_payload_claim_separation() {
        // Create a JWT where the same claim name exists in both header and payload with different values
        let header_json = r#"{"alg":"HS256","typ":"JWT","env":"header-env","version":"1.0"}"#;
        let payload_json = r#"{"sub":"1234567890","env":"payload-env","version":"2.0"}"#;
        let jwt = generate_jwt_with_header_and_claims(header_json, payload_json);

        // Configure validator to require specific values from header and payload separately
        let mut required_claims = BTreeMap::new();
        required_claims.insert(
            "env".to_string(),
            ClaimRequirement::ExactValue("payload-env".to_string()),
        );
        required_claims.insert(
            "version".to_string(),
            ClaimRequirement::ExactValue("2.0".to_string()),
        );

        let mut required_headers = BTreeMap::new();
        required_headers.insert(
            "env".to_string(),
            ClaimRequirement::ExactValue("header-env".to_string()),
        );
        required_headers.insert(
            "version".to_string(),
            ClaimRequirement::ExactValue("1.0".to_string()),
        );

        let config = JwtClaimsValidatorConfig {
            required_claims,
            required_headers,
        };
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_header_claim_validation_fails_when_missing() {
        // Create a JWT with default header (no custom claims)
        let header_json = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload_json = r#"{"sub":"1234567890","name":"John Doe"}"#;
        let jwt = generate_jwt_with_header_and_claims(header_json, payload_json);

        // Configure validator to require "kid" claim in header (which doesn't exist)
        let mut required_headers = BTreeMap::new();
        required_headers.insert("kid".to_string(), ClaimRequirement::Present);

        let config = JwtClaimsValidatorConfig {
            required_claims: BTreeMap::new(),
            required_headers,
        };
        let checker = JwtClaimsValidator::new(config);
        assert!(!checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_header_claim_validation_fails_wrong_value() {
        // Create a JWT with custom header containing a "kid" claim
        let header_json = r#"{"alg":"HS256","typ":"JWT","kid":"wrong-key"}"#;
        let payload_json = r#"{"sub":"1234567890","name":"John Doe"}"#;
        let jwt = generate_jwt_with_header_and_claims(header_json, payload_json);

        // Configure validator to require specific "kid" value in header
        let mut required_headers = BTreeMap::new();
        required_headers.insert(
            "kid".to_string(),
            ClaimRequirement::ExactValue("key-123".to_string()),
        );

        let config = JwtClaimsValidatorConfig {
            required_claims: BTreeMap::new(),
            required_headers,
        };
        let checker = JwtClaimsValidator::new(config);
        assert!(!checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_confusion_prevention_payload_claim_in_header_requirement() {
        // Create a JWT where "kid" exists in payload but we require it in header
        let header_json = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload_json = r#"{"sub":"1234567890","kid":"key-from-payload"}"#;
        let jwt = generate_jwt_with_header_and_claims(header_json, payload_json);

        // Configure validator to require "kid" in header (but it's only in payload)
        let mut required_headers = BTreeMap::new();
        required_headers.insert("kid".to_string(), ClaimRequirement::Present);

        let config = JwtClaimsValidatorConfig {
            required_claims: BTreeMap::new(),
            required_headers,
        };
        let checker = JwtClaimsValidator::new(config);
        // Should fail because "kid" is in payload, not header
        assert!(!checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_header_claim_regex_validation() {
        // Create a JWT with custom header containing versioned key ID
        let header_json =
            r#"{"alg":"HS256","typ":"JWT","kid":"key-v123","service":"auth-service"}"#;
        let payload_json = r#"{"sub":"1234567890","name":"John Doe"}"#;
        let jwt = generate_jwt_with_header_and_claims(header_json, payload_json);

        // Configure validator to use regex for header claims
        let mut required_headers = BTreeMap::new();
        required_headers.insert(
            "kid".to_string(),
            ClaimRequirement::RegexMatch(r"^key-v\d+$".to_string()),
        );
        required_headers.insert(
            "service".to_string(),
            ClaimRequirement::RegexMatch(r"^auth-.*".to_string()),
        );

        let config = JwtClaimsValidatorConfig {
            required_claims: BTreeMap::new(),
            required_headers,
        };
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }

    #[test]
    fn test_numeric_claim_regex_validation() {
        // Create a JWT with custom header containing versioned key ID
        let header_json = r#"{"alg":"HS256","typ":"JWT"}"#;
        let payload_json = r#"{"iat": 1756904571,"scope": 123,"sub": 1211208433496121,"version": 2,"app": 1211208544034048,"exp": 1756908171}"#;
        let jwt = generate_jwt_with_header_and_claims(header_json, payload_json);

        // Configure validator to use regex for header claims
        let mut required_claims = BTreeMap::new();
        required_claims.insert("scope".to_string(), ClaimRequirement::Present);
        required_claims.insert(
            "app".to_string(),
            ClaimRequirement::RegexMatch(r"^\d{16}$".to_string()),
        );
        required_claims.insert(
            "version".to_string(),
            ClaimRequirement::ExactValue("2".to_string()),
        );

        let config = JwtClaimsValidatorConfig {
            required_claims,
            required_headers: BTreeMap::new(),
        };
        let checker = JwtClaimsValidator::new(config);
        assert!(checker.is_valid_match(&jwt));
    }
}
