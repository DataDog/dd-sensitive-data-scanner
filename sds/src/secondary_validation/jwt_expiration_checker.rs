use crate::secondary_validation::Validator;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use serde_json::Value as JsonValue;

pub struct JwtExpirationChecker;

const SEGMENTS_COUNT: usize = 3;

impl Validator for JwtExpirationChecker {
    fn is_valid_match(&self, regex_match: &str) -> bool {
        let result = decode_segments(regex_match);
        if let Ok((_, payload)) = result {
            let expiration = payload.get("exp");
            if let Some(exp) = expiration {
                let exp_int: i64 = exp.as_i64().unwrap();
                let now = Utc::now().timestamp();
                exp_int > now
            } else {
                // if there is no expiration claim, we consider it as a valid match
                true
            }
        } else {
            // if JWT segments cannot be decoded, the JWT is not well formated, we consider it as an invalid match
            false
        }
    }
}

// This function is an extraction of the decoding part https://github.com/GildedHonour/frank_jwt
// We don't want to depend on the whole frank_jwt crate for this simple function
// Our goal is to be able to decode a JWT without checking the signature
fn decode_segments(encoded_token: &str) -> Result<(JsonValue, JsonValue), ()> {
    let raw_segments: Vec<&str> = encoded_token.split(".").collect();
    if raw_segments.len() != SEGMENTS_COUNT {
        // Invalid JWT header + payload + signature
        return Err(());
    }

    let header_segment = raw_segments[0];
    let payload_segment = raw_segments[1];
    let result = decode_header_and_payload(header_segment, payload_segment);
    if let Ok((header, payload)) = result {
        Ok((header, payload))
    } else {
        Err(())
    }
}

fn decode_header_and_payload(
    header_segment: &str,
    payload_segment: &str,
) -> Result<(JsonValue, JsonValue), ()> {
    let b64_to_json = |seg| -> Result<JsonValue, ()> {
        let res = URL_SAFE_NO_PAD.decode(seg);
        if let Ok(decoded) = res {
            serde_json::from_slice(&decoded).map_err(|_| ())
        } else {
            Err(())
        }
    };

    let header_json = b64_to_json(header_segment)?;
    let payload_json = b64_to_json(payload_segment)?;
    Ok((header_json, payload_json))
}

#[cfg(test)]
pub fn generate_jwt(exp: String) -> String {
    let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let payload = format!("{{\"exp\":{}}}", exp);
    let payload_encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    format!("{}.{}.{}", header, payload_encoded, signature)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_decode_segments() {
        // {"alg":"HS256","typ":"JWT"}"."{"exp":1728872000}".signature
        let result = decode_segments("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3Mjg4NzIwMDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
        assert_eq!(result.is_ok(), true);
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
    fn test_is_valid_match_expired_jwt() {
        let past_time_as_string = (Utc::now().timestamp() - 1000000).to_string();
        let json = generate_jwt(past_time_as_string);
        let checker = JwtExpirationChecker;
        assert!(!checker.is_valid_match(&json));
    }

    #[test]
    fn test_is_valid_match_jwt_without_expiration() {
        let future_time_as_string = (Utc::now().timestamp() + 1000000).to_string();
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let payload = format!("{{\"no_exp\":{}}}", future_time_as_string);
        let payload_encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let json = format!("{}.{}.{}", header, payload_encoded, signature);
        let checker = JwtExpirationChecker;
        assert!(checker.is_valid_match(&json));
    }

    #[test]
    fn test_is_valid_match_invalid_jwt() {
        let json = "invalid_jwt";
        let checker = JwtExpirationChecker;
        assert!(!checker.is_valid_match(&json));
    }
}
