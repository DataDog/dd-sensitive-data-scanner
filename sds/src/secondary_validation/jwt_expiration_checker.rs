use crate::secondary_validation::Validator;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use serde_json::Value as JsonValue;

pub struct JwtExpirationChecker;

const SEGMENTS_COUNT: usize = 3;

impl Validator for JwtExpirationChecker {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        if let Some((_, payload)) = decode_segments(regex_match) {
            if let Some(exp) = payload.get("exp") {
                if let Some(exp) = exp.as_i64() {
                    let now = Utc::now().timestamp();
                    exp > now
                } else {
                    // if the expiration claim is not an integer, we consider it as an invalid match
                    // exp is a reserved claim for NumericDate (https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)
                    // The NumericDate is the UNIX timestamp (https://www.rfc-editor.org/rfc/rfc7519#section-2)
                    false
                }
            } else {
                // if there is no expiration claim, we consider it as a valid match
                true
            }
        } else {
            // if JWT segments cannot be decoded, the JWT is not well formatted, we consider it as an invalid match
            false
        }
    }
}

// This function is an extraction of the decoding part https://github.com/GildedHonour/frank_jwt
// We don't want to depend on the whole frank_jwt crate for this simple function
// Our goal is to be able to decode a JWT without checking the signature
fn decode_segments(encoded_token: &str) -> Option<(JsonValue, JsonValue)> {
    let raw_segments: Vec<&str> = encoded_token.split(".").collect();
    if raw_segments.len() != SEGMENTS_COUNT {
        // Invalid JWT header + payload + signature
        return None;
    }

    let header_segment = raw_segments[0];
    let payload_segment = raw_segments[1];
    let header_json = decode_segment(header_segment)?;
    let payload_json = decode_segment(payload_segment)?;
    Some((header_json, payload_json))
}

fn decode_segment(segment: &str) -> Option<JsonValue> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .ok()
        .and_then(|decoded| serde_json::from_slice(&decoded).ok())
}

#[cfg(test)]
pub fn generate_jwt(exp: String) -> String {
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let payload = format!("{{\"exp\":{exp}}}");
    let payload_encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    format!("{header}.{payload_encoded}.{signature}")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_decode_segments() {
        // {"alg":"HS256","typ":"JWT"}"."{"exp":1728872000}".signature
        let result = decode_segments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mjg4NzIwMDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
        assert!(result.is_some());
        let (header, payload) = result.unwrap();
        assert_eq!(
            header.get("alg"),
            Some(&JsonValue::String("HS256".to_string()))
        );
        assert_eq!(payload.get("exp"), Some(&json!(1728872000)));
    }

    #[test]
    fn test_is_valid_match_valid_jwt() {
        let future_time_as_string = (Utc::now().timestamp() + 1000000).to_string();
        let json = generate_jwt(future_time_as_string);
        let checker = JwtExpirationChecker;
        assert!(checker.is_valid_match(&json));
    }
    #[test]
    fn test_is_invalid_match_for_expired_jwt() {
        let past_time_as_string = (Utc::now().timestamp() - 1000000).to_string();
        let json = generate_jwt(past_time_as_string);
        let checker = JwtExpirationChecker;
        assert!(!checker.is_valid_match(&json));
    }

    #[test]
    fn test_is_valid_match_jwt_without_expiration() {
        let future_time_as_string = (Utc::now().timestamp() + 1000000).to_string();
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let payload = format!("{{\"no_exp\":{future_time_as_string}}}");
        let payload_encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let json = format!("{header}.{payload_encoded}.{signature}");
        let checker = JwtExpirationChecker;
        assert!(checker.is_valid_match(&json));
    }

    #[test]
    fn test_is_invalid_match_for_invalid_exp() {
        let past_time_as_string = "\"hello\"".to_string();
        let json = generate_jwt(past_time_as_string);
        let checker = JwtExpirationChecker;
        assert!(!checker.is_valid_match(&json));
    }

    #[test]
    fn test_is_invalid_match_for_invalid_jwt() {
        let json = "invalid_jwt";
        let checker = JwtExpirationChecker;
        assert!(!checker.is_valid_match(json));
    }
}
